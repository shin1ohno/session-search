import unittest

import support  # noqa: F401 — puts the package on sys.path

from ccs import config


def cfg(endpoint, auth):
    return {"endpoint": endpoint, "host_label": "air", "auth": auth,
            "hmac_key_file": "~/.config/session-search/hmac.key"}


TAILNET = {"type": "tailnet"}
CC = {"type": "client_credentials", "token_url": "https://mcp.example/oauth2/token",
      "client_id": "session-search-pro-dev", "secret_file": "~/.config/session-search/client.secret"}


class EndpointScheme(unittest.TestCase):
    def test_https_accepted_for_both_auth_types(self):
        for auth in (TAILNET, CC):
            c = config.Config(cfg("https://mcp.example/memory/sessions/v1/", auth), "x")
            self.assertEqual(c.endpoint, "https://mcp.example/memory/sessions/v1")

    def test_http_loopback_accepted(self):
        c = config.Config(cfg("http://127.0.0.1:8011/memory/sessions/v1", TAILNET), "x")
        self.assertEqual(c.endpoint, "http://127.0.0.1:8011/memory/sessions/v1")

    def test_http_tailnet_name_accepted_only_with_tailnet_auth(self):
        url = "http://sh1-cloud.tailff05.ts.net:8011/memory/sessions/v1"
        self.assertEqual(config.Config(cfg(url, TAILNET), "x").endpoint, url)
        with self.assertRaises(config.ConfigError):
            config.Config(cfg(url, CC), "x")

    def test_http_elsewhere_rejected(self):
        for url in ("http://mcp.example/memory/sessions/v1",
                    "http://ts.net/memory/sessions/v1",
                    "http://evil.ts.net.example.com/memory/sessions/v1",
                    "http://sh1-cloud.ts.netx/memory/sessions/v1"):
            with self.subTest(url=url), self.assertRaises(config.ConfigError):
                config.Config(cfg(url, TAILNET), "x")

    def test_token_url_stays_https_only(self):
        auth = dict(CC, token_url="http://hydra.tailff05.ts.net/oauth2/token")
        with self.assertRaises(config.ConfigError):
            config.Config(cfg("https://mcp.example/memory/sessions/v1", auth), "x")


if __name__ == "__main__":
    unittest.main()
