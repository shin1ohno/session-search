"""~/.config/session-search/config.json (§7.5).

{"endpoint": "https://…/memory/sessions/v1", "host_label": "pro-dev",
 "auth": {"type": "client_credentials", "token_url": "…", "client_id": "…",
          "secret_file": "~/.config/session-search/client.secret"}
         | {"type": "tailnet"},
 "hmac_key_file": "~/.config/session-search/hmac.key"}

The endpoint lives only here (§8 row 3): nothing in the package hardcodes it.
"""

from __future__ import annotations

import json
import os
import urllib.parse

from . import util


class ConfigError(Exception):
    pass


class NotConfigured(ConfigError):
    pass


def _check_url(value, field: str, tailnet: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError("config: `%s` is missing" % field)
    parts = urllib.parse.urlsplit(value)
    if parts.scheme == "https" and parts.hostname:
        return value.rstrip("/")
    # Plain http only to loopback (tests, an on-box client).
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"):
        return value.rstrip("/")
    # Plain http to a tailnet MagicDNS name, only for tailnet auth: the work
    # proxy listens on its tailscale0 address without TLS, and the hop is
    # already WireGuard-encrypted. Identity comes from the tailnet, so no
    # bearer token ever travels over this URL.
    host = parts.hostname or ""
    if tailnet and parts.scheme == "http" and host.endswith(".ts.net") and len(host) > len(".ts.net"):
        return value.rstrip("/")
    raise ConfigError("config: `%s` must be an https URL (http only to 127.0.0.1, "
                      "or to a *.ts.net host with tailnet auth)" % field)


class Config:
    def __init__(self, data: dict, path: str):
        self.path = path
        if not isinstance(data, dict):
            raise ConfigError("config: top level must be an object")
        auth_raw = data.get("auth")
        is_tailnet = isinstance(auth_raw, dict) and auth_raw.get("type") == "tailnet"
        self.endpoint = _check_url(data.get("endpoint"), "endpoint", tailnet=is_tailnet)
        host = data.get("host_label")
        if not isinstance(host, str) or not util.HOST_LABEL_RE.match(host):
            raise ConfigError("config: `host_label` must match ^[a-z0-9-]{1,63}$")
        self.host_label = host
        auth = data.get("auth")
        if not isinstance(auth, dict):
            raise ConfigError("config: `auth` must be an object")
        atype = auth.get("type")
        if atype == "tailnet":
            self.auth_type = "tailnet"
            self.token_url = None
            self.client_id = None
            self.secret_file = None
            self.audience = None
        elif atype == "client_credentials":
            self.auth_type = atype
            self.token_url = _check_url(auth.get("token_url"), "auth.token_url")
            cid = auth.get("client_id")
            if not isinstance(cid, str) or not cid:
                raise ConfigError("config: `auth.client_id` is missing")
            self.client_id = cid
            sf = auth.get("secret_file")
            if not isinstance(sf, str) or not sf:
                raise ConfigError("config: `auth.secret_file` is missing")
            self.secret_file = os.path.expanduser(sf)
            # Not part of the §7.5 shape; the personal proxy's Hydra audience is
            # `memory` (same as memory-mirror), so that is the default.
            self.audience = auth.get("audience", "memory")
        else:
            raise ConfigError("config: `auth.type` must be \"tailnet\" or \"client_credentials\"")
        kf = data.get("hmac_key_file")
        if not isinstance(kf, str) or not kf:
            raise ConfigError("config: `hmac_key_file` is missing")
        self.hmac_key_file = os.path.expanduser(kf)

    def read_secret(self) -> str:
        try:
            with open(self.secret_file, encoding="utf-8") as fh:
                secret = fh.read().strip()
        except OSError as e:
            raise ConfigError("client secret unreadable at %s (%s)" % (self.secret_file, e.__class__.__name__))
        if not secret:
            raise ConfigError("client secret file %s is empty" % self.secret_file)
        return secret


def load(path: str | None = None) -> Config:
    path = path or util.config_path()
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        raise NotConfigured("not configured: %s does not exist" % path)
    except OSError as e:
        raise ConfigError("config %s unreadable (%s)" % (path, e.__class__.__name__))
    try:
        data = json.loads(raw)
    except ValueError:
        raise ConfigError("config %s is not valid JSON" % path)
    return Config(data, path)
