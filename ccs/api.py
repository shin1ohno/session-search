"""HTTP + auth layer for /memory/sessions/v1 (§7.2), and the search circuit breaker (§6.8).

Auth:
  client_credentials — personal hosts. POST token_url with HTTP Basic
    (client_secret_basic) + grant_type=client_credentials + audience, the same
    shape as hooks/mirror-file-memory.rb. The token is cached in memory for the
    life of the process only and refreshed once on a 401.
  tailnet — work hosts. No Authorization header; the box's proxy derives the
    identity from the tailnet connection.
"""

from __future__ import annotations

import base64
import gzip
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from . import VERSION, util

USER_AGENT = "ccs/%s" % VERSION


class Unreachable(Exception):
    """Network error, timeout, or the token endpoint could not be reached."""


class AuthError(Exception):
    pass


class Response:
    def __init__(self, status: int, headers, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        try:
            return json.loads(self.body.decode("utf-8") or "null")
        except (UnicodeDecodeError, ValueError):
            return None

    def header(self, name: str):
        if self.headers is None:
            return None
        return self.headers.get(name)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect would replay the bearer token to wherever Location points.
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def _send(req: urllib.request.Request, timeout: float) -> Response:
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return Response(resp.status, resp.headers, resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        return Response(e.code, e.headers, body)
    except (urllib.error.URLError, OSError, ValueError) as e:
        # socket.timeout is an OSError subclass on every supported Python.
        raise Unreachable("%s: %s" % (e.__class__.__name__, getattr(e, "reason", e)))


class Api:
    def __init__(self, config, timeout: float = 30.0):
        self.config = config
        self.timeout = timeout
        self._token = None

    # --- auth -------------------------------------------------------------
    def _fetch_token(self) -> str:
        cfg = self.config
        secret = cfg.read_secret()
        basic = base64.b64encode(
            ("%s:%s" % (urllib.parse.quote(cfg.client_id, safe=""), urllib.parse.quote(secret, safe=""))).encode()
        ).decode()
        form = {"grant_type": "client_credentials"}
        if cfg.audience:
            form["audience"] = cfg.audience
        req = urllib.request.Request(
            cfg.token_url,
            data=urllib.parse.urlencode(form).encode(),
            method="POST",
            headers={
                "Authorization": "Basic " + basic,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": USER_AGENT,
            },
        )
        resp = _send(req, self.timeout)
        if resp.status != 200:
            raise AuthError("token endpoint answered HTTP %d" % resp.status)
        data = resp.json() or {}
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise AuthError("token endpoint answered 200 without an access_token")
        return token

    def _auth_headers(self, refresh: bool = False) -> dict:
        if self.config.auth_type == "tailnet":
            return {}
        if refresh or self._token is None:
            self._token = self._fetch_token()
        return {"Authorization": "Bearer " + self._token}

    # --- requests ---------------------------------------------------------
    def request(self, method: str, path: str, body=None, params=None, gzip_body: bool = False,
                timeout: float | None = None) -> Response:
        url = self.config.endpoint + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = None
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
            if gzip_body:
                # No Content-Encoding header on purpose: the aiohttp proxies in
                # front of the server auto-decompress an encoded request body
                # while keeping the compressed Content-Length, and the request
                # stalls. The server recognises gzip by its magic bytes instead
                # (sessions_app._json_body), so the body travels opaque.
                data = gzip.compress(data, compresslevel=6)
        t = self.timeout if timeout is None else timeout
        for attempt in (0, 1):
            h = dict(headers)
            h.update(self._auth_headers(refresh=attempt == 1))
            req = urllib.request.Request(url, data=data, method=method, headers=h)
            resp = _send(req, t)
            if resp.status == 401 and self.config.auth_type == "client_credentials" and attempt == 0:
                continue
            return resp
        return resp  # pragma: no cover

    def post(self, path, body, gzip_body=False, timeout=None):
        return self.request("POST", path, body=body, gzip_body=gzip_body, timeout=timeout)

    def get(self, path, params=None, timeout=None):
        return self.request("GET", path, params=params, timeout=timeout)


class Breaker:
    """2 consecutive failures (errors or >800 ms timeouts) open it for 60 s (§6.8).

    State is cached in ~/.claude/session-search/breaker.json so that every fzf
    reload (a fresh process) sees it.
    """

    THRESHOLD = 2
    OPEN_SECONDS = 60.0
    TIMEOUT = 0.8

    def __init__(self, path: str | None = None, clock=time.time):
        self.path = path or util.breaker_path()
        self.clock = clock

    def _load(self) -> dict:
        d = util.read_json(self.path, {})
        return d if isinstance(d, dict) else {}

    def is_open(self) -> bool:
        d = self._load()
        until = d.get("open_until") or 0
        return isinstance(until, (int, float)) and self.clock() < until

    def state(self) -> dict:
        d = self._load()
        return {"failures": int(d.get("failures") or 0), "open_until": d.get("open_until") or 0,
                "open": self.is_open()}

    def record_failure(self) -> None:
        d = self._load()
        failures = int(d.get("failures") or 0) + 1
        out = {"failures": failures, "open_until": d.get("open_until") or 0}
        if failures >= self.THRESHOLD:
            out["open_until"] = self.clock() + self.OPEN_SECONDS
        util.atomic_write(self.path, json.dumps(out))

    def record_success(self) -> None:
        d = self._load()
        if d.get("failures") or d.get("open_until"):
            util.atomic_write(self.path, json.dumps({"failures": 0, "open_until": 0}))
