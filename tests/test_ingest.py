import fcntl
import hashlib
import json
import os
import unittest

import support
from support import FAKE_TOKEN, SID, FakeRedactor, FakeServer, HomeCase, assistant, user

from ccs import api as api_mod, config as config_mod, ingest, util


def ok_handler(req):
    if req["path"].endswith("/ingest"):
        seg = req["body"]["segment"]
        return 200, {"session_key": "sk_test", "indexed": len(seg["lines"]), "next_offset": seg["end_offset"],
                     "archive": "written"}, {}
    return 200, {"stored": True}, {}


class IngestCase(HomeCase):
    def setUp(self):
        super().setUp()
        self.srv = FakeServer(ok_handler)
        self.write_config(self.srv.base + "/memory/sessions/v1")

    def tearDown(self):
        self.srv.close()
        super().tearDown()

    def shipper(self, **kw):
        cfg = config_mod.load()
        red = FakeRedactor()
        return ingest.Shipper(cfg, api_mod.Api(cfg, timeout=5), red, red.load_key(cfg.hmac_key_file),
                              ingest.State(), **kw)

    def ingests(self):
        return self.srv.of("/ingest")


class AdapterShape(IngestCase):


    def test_tombstone_format(self):
        t = ingest.tombstone("unmasked_secret", ["aws-key"], 123)
        self.assertEqual(t, {"type": "session-search-tombstone", "reason": "unmasked_secret",
                             "kinds": ["aws-key"], "line_offset": 123})


if __name__ == "__main__":
    unittest.main()
