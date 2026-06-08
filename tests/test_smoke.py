"""Smoke tests for EMBEDAUDIT. Standard library only, no network."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from embedaudit import TOOL_NAME, TOOL_VERSION, audit_store, drift_report  # noqa: E402
from embedaudit.core import Record, AuditError, load_jsonl  # noqa: E402
from embedaudit.cli import main  # noqa: E402


def _write(records):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return path


class TestMeta(unittest.TestCase):
    def test_tool_identity(self):
        self.assertEqual(TOOL_NAME, "embedaudit")
        self.assertTrue(TOOL_VERSION)


class TestLoad(unittest.TestCase):
    def test_roundtrip(self):
        path = _write([{"id": "a", "vector": [1.0, 0.0]},
                       {"id": "b", "vector": [0.0, 1.0]}])
        try:
            recs = load_jsonl(path)
            self.assertEqual(len(recs), 2)
            self.assertIsInstance(recs[0], Record)
        finally:
            os.remove(path)

    def test_bad_vector_rejected(self):
        path = _write([{"id": "a", "vector": "not-a-list"}])
        try:
            with self.assertRaises(AuditError):
                load_jsonl(path)
        finally:
            os.remove(path)

    def test_empty_file_rejected(self):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        try:
            with self.assertRaises(AuditError):
                load_jsonl(path)
        finally:
            os.remove(path)


class TestAudit(unittest.TestCase):
    def test_clean_store_ok(self):
        recs = [
            Record("a", [0.9, 0.1, 0.0]),
            Record("b", [0.1, 0.9, 0.0]),
            Record("c", [0.0, 0.1, 0.9]),
            Record("d", [0.2, 0.2, 0.8]),
        ]
        res = audit_store(recs)
        self.assertTrue(res.ok)
        self.assertEqual(res.dimension, 3)

    def test_zero_vector_critical(self):
        recs = [Record("a", [1.0, 0.0]), Record("z", [0.0, 0.0]),
                Record("b", [0.0, 1.0])]
        res = audit_store(recs)
        self.assertFalse(res.ok)
        self.assertTrue(any(f.code == "ZERO_VECTOR" for f in res.findings))

    def test_dimension_mismatch_critical(self):
        recs = [Record("a", [1.0, 0.0]), Record("b", [0.0, 1.0, 0.0])]
        res = audit_store(recs)
        self.assertTrue(any(f.code == "DIM_MISMATCH" for f in res.findings))

    def test_duplicate_detected(self):
        recs = [Record("a", [0.5, 0.5]), Record("b", [0.5, 0.5]),
                Record("c", [0.1, 0.9])]
        res = audit_store(recs)
        self.assertTrue(any(f.code == "DUPLICATE_VECTOR" for f in res.findings))

    def test_retrieval_domination_critical(self):
        recs = [Record(f"p{i}", [0.5 + i * 1e-4, 0.5, 0.5]) for i in range(6)]
        recs += [Record("x", [0.9, 0.1, 0.0]), Record("y", [0.0, 0.1, 0.9])]
        res = audit_store(recs)
        self.assertTrue(
            any(f.code == "RETRIEVAL_DOMINATION" for f in res.findings))
        self.assertFalse(res.ok)


class TestDrift(unittest.TestCase):
    def test_no_drift(self):
        base = [Record(str(i), [1.0, 0.0]) for i in range(5)]
        cur = [Record(str(i), [1.0, 0.0]) for i in range(5)]
        res = drift_report(base, cur)
        self.assertTrue(res.ok)

    def test_drift_flagged(self):
        base = [Record(str(i), [1.0, 0.0]) for i in range(5)]
        cur = [Record(str(i), [0.0, 1.0]) for i in range(5)]
        res = drift_report(base, cur)
        self.assertFalse(res.ok)
        self.assertTrue(any(f.code == "DRIFT" for f in res.findings))

    def test_dim_change_critical(self):
        base = [Record("a", [1.0, 0.0])]
        cur = [Record("a", [1.0, 0.0, 0.0])]
        res = drift_report(base, cur)
        self.assertTrue(any(f.code == "DIM_MISMATCH" for f in res.findings))


class TestCLI(unittest.TestCase):
    def test_audit_json_exit_nonzero_on_poison(self):
        demo = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "demos", "01-basic", "store_snapshot.jsonl")
        if os.path.exists(demo):
            rc = main(["--format", "json", "audit", demo])
            self.assertEqual(rc, 1)

    def test_clean_audit_exit_zero(self):
        path = _write([{"id": "a", "vector": [0.9, 0.1]},
                       {"id": "b", "vector": [0.1, 0.9]},
                       {"id": "c", "vector": [0.4, 0.6]}])
        try:
            rc = main(["audit", path])
            self.assertEqual(rc, 0)
        finally:
            os.remove(path)

    def test_missing_file_exit_two(self):
        rc = main(["audit", "/nonexistent/path/x.jsonl"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
