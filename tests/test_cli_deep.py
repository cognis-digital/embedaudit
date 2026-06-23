"""CLI integration tests: formats, exit codes, subcommands. Stdlib only."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from embedaudit.cli import build_parser, main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demos", "01-basic", "store_snapshot.jsonl")


def _write(records):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return path


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestParser(unittest.TestCase):
    def test_audit_subcommand_parses(self):
        ns = build_parser().parse_args(["audit", "x.jsonl"])
        self.assertEqual(ns.command, "audit")
        self.assertEqual(ns.dup_threshold, 0.999)

    def test_drift_subcommand_parses(self):
        ns = build_parser().parse_args(["drift", "a.jsonl", "b.jsonl"])
        self.assertEqual(ns.command, "drift")

    def test_format_choices(self):
        for fmt in ("table", "json", "sarif", "csv"):
            ns = build_parser().parse_args(["--format", fmt, "audit", "x.jsonl"])
            self.assertEqual(ns.format, fmt)

    def test_enrich_feeds_flag(self):
        ns = build_parser().parse_args(["audit", "x.jsonl", "--enrich-feeds"])
        self.assertTrue(ns.enrich_feeds)


class TestExitCodes(unittest.TestCase):
    def test_clean_audit_exit_zero(self):
        path = _write([{"id": "a", "vector": [0.9, 0.1]},
                       {"id": "b", "vector": [0.1, 0.9]},
                       {"id": "c", "vector": [0.4, 0.6]}])
        try:
            rc, _, _ = _run(["audit", path])
            self.assertEqual(rc, 0)
        finally:
            os.remove(path)

    def test_poison_audit_exit_one(self):
        if not os.path.exists(DEMO):
            self.skipTest("demo missing")
        rc, _, _ = _run(["--format", "json", "audit", DEMO])
        self.assertEqual(rc, 1)

    def test_missing_file_exit_two(self):
        rc, _, err = _run(["audit", "/nonexistent/x.jsonl"])
        self.assertEqual(rc, 2)
        self.assertIn("error", err)

    def test_bad_json_exit_two(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("{not json}\n")
        try:
            rc, _, _ = _run(["audit", path])
            self.assertEqual(rc, 2)
        finally:
            os.remove(path)


class TestFormats(unittest.TestCase):
    def setUp(self):
        self.path = _write([{"id": "z", "vector": [0.0, 0.0]},
                            {"id": "a", "vector": [1.0, 0.0]},
                            {"id": "b", "vector": [0.0, 1.0]}])

    def tearDown(self):
        os.remove(self.path)

    def test_json_output_parses(self):
        rc, out, _ = _run(["--format", "json", "audit", self.path])
        doc = json.loads(out)
        self.assertIn("findings", doc)
        self.assertFalse(doc["ok"])
        self.assertEqual(rc, 1)

    def test_sarif_output_parses(self):
        _, out, _ = _run(["--format", "sarif", "audit", self.path])
        doc = json.loads(out)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_csv_output_has_header(self):
        _, out, _ = _run(["--format", "csv", "audit", self.path])
        self.assertTrue(out.startswith("severity,rank,code,message,detail"))

    def test_table_output_human(self):
        _, out, _ = _run(["audit", self.path])
        self.assertIn("findings", out)
        self.assertIn("ZERO_VECTOR", out)
        self.assertIn("risk score", out)


class TestDriftCli(unittest.TestCase):
    def test_drift_json(self):
        base = _write([{"id": str(i), "vector": [1.0, 0.0]} for i in range(5)])
        cur = _write([{"id": str(i), "vector": [0.0, 1.0]} for i in range(5)])
        try:
            rc, out, _ = _run(["--format", "json", "drift", base, cur])
            doc = json.loads(out)
            self.assertTrue(any(f["code"] == "DRIFT" for f in doc["findings"]))
            self.assertEqual(rc, 1)
        finally:
            os.remove(base)
            os.remove(cur)

    def test_drift_clean_exit_zero(self):
        base = _write([{"id": str(i), "vector": [1.0, 0.0]} for i in range(5)])
        cur = _write([{"id": str(i), "vector": [1.0, 0.0]} for i in range(5)])
        try:
            rc, _, _ = _run(["drift", base, cur])
            self.assertEqual(rc, 0)
        finally:
            os.remove(base)
            os.remove(cur)


class TestFeedsCli(unittest.TestCase):
    def test_feeds_list_table(self):
        rc, out, _ = _run(["feeds"])
        self.assertEqual(rc, 0)
        self.assertIn("feed catalog", out)

    def test_feeds_list_json(self):
        rc, out, _ = _run(["--format", "json", "feeds"])
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertIn("feeds", doc)
        self.assertIn("available", doc)

    def test_feeds_domain_filter(self):
        rc, out, _ = _run(["--format", "json", "feeds", "--domain", "vuln"])
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        for f in doc["feeds"]:
            self.assertEqual(f.get("domain"), "vuln")


if __name__ == "__main__":
    unittest.main()
