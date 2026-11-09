"""The server-owned corpus must identify the exact vendored oracle bytes."""
import hashlib
import json
from pathlib import Path
import unittest

VENDOR = Path(__file__).resolve().parents[2] / "vendor/memory-mcp"


class CorpusProvenance(unittest.TestCase):
    def test_corpus_hash_count_source_and_recorded_blob(self):
        source = (VENDOR / "SOURCE").read_text()
        for name, corpus, minimum in (("redact", "session_redact_r1.jsonl", 8000),
                                       ("codex", "session_codex_v1.jsonl", 100)):
            with self.subTest(name=name):
                data = (VENDOR / "conformance" / corpus).read_bytes()
                header, body = data.split(b"\n", 1)
                header = json.loads(header)
                module = (VENDOR / ("session_" + name + ".py")).read_bytes()
                oracle_oid = hashlib.sha1(b"blob " + str(len(module)).encode() + b"\0" + module).hexdigest()
                self.assertEqual(header["source_blob"], oracle_oid)
                if name == "redact":
                    client = (VENDOR.parents[1] / "ccs/ingest.py").read_bytes()
                    client_oid = hashlib.sha1(b"blob " + str(len(client)).encode() + b"\0" + client).hexdigest()
                    self.assertEqual(header["client_source_blob"], client_oid)
                    self.assertEqual(header["client_source"].encode(), client)
                self.assertEqual(header["format"], "ccs-%s-conformance/1" % name)
                self.assertGreaterEqual(header["min_vectors"], minimum)
                self.assertGreaterEqual(header["vectors"], header["min_vectors"])
                self.assertEqual(header["vectors"], body.count(b"\n"))
                self.assertEqual(header["sha256_of_vectors"], hashlib.sha256(body).hexdigest())
                corpus_oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                self.assertIn("blob: " + corpus_oid, source)
                self.assertIn("vendored-as: vendor/memory-mcp/conformance/" + corpus, source)
