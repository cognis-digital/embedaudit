"""Tests for the SARIF / CSV / risk-score output formats. Stdlib only."""

import csv
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from embedaudit.core import Record, audit_store, drift_report  # noqa: E402
from embedaudit.formats import (  # noqa: E402
    RULE_HELP, risk_score, to_csv, to_sarif,
)


def _poisoned():
    recs = [Record(f"p{i}", [0.5 + i * 1e-4, 0.5, 0.5]) for i in range(6)]
    recs += [Record("x", [0.9, 0.1, 0.0]), Record("z", [0.0, 0.0, 0.0])]
    return audit_store(recs)


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.res = _poisoned()
        self.doc = to_sarif(self.res, tool_name="embedaudit", tool_version="9.9.9")

    def test_top_level_shape(self):
        self.assertEqual(self.doc["version"], "2.1.0")
        self.assertIn("$schema", self.doc)
        self.assertEqual(len(self.doc["runs"]), 1)

    def test_driver_identity(self):
        drv = self.doc["runs"][0]["tool"]["driver"]
        self.assertEqual(drv["name"], "embedaudit")
        self.assertEqual(drv["version"], "9.9.9")
        self.assertTrue(drv["informationUri"].startswith("https://"))

    def test_results_present(self):
        results = self.doc["runs"][0]["results"]
        self.assertEqual(len(results), len(self.res.findings))
        for r in results:
            self.assertIn(r["level"], ("error", "warning", "note"))
            self.assertIn("ruleId", r)
            self.assertIn("text", r["message"])

    def test_rules_deduped(self):
        rules = self.doc["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_rule_has_help_text(self):
        rules = self.doc["runs"][0]["tool"]["driver"]["rules"]
        for r in rules:
            self.assertTrue(r["fullDescription"]["text"])

    def test_critical_maps_to_error(self):
        levels = {r["ruleId"]: r["level"] for r in self.doc["runs"][0]["results"]}
        self.assertEqual(levels.get("ZERO_VECTOR"), "error")

    def test_properties_carry_meta(self):
        props = self.doc["runs"][0]["properties"]
        self.assertEqual(props["ok"], self.res.ok)
        self.assertEqual(props["recordCount"], self.res.record_count)

    def test_sarif_is_json_serialisable(self):
        s = json.dumps(self.doc)
        self.assertIn("ZERO_VECTOR", s)

    def test_empty_result_sarif(self):
        clean = audit_store([Record("a", [0.9, 0.1]), Record("b", [0.1, 0.9]),
                             Record("c", [0.4, 0.6])])
        doc = to_sarif(clean)
        self.assertEqual(doc["runs"][0]["results"], [])
        self.assertTrue(doc["runs"][0]["properties"]["ok"])

    def test_rule_help_covers_codes(self):
        for code in ("DIM_MISMATCH", "ZERO_VECTOR", "DRIFT",
                     "RETRIEVAL_DOMINATION", "DUPLICATE_VECTOR"):
            self.assertIn(code, RULE_HELP)


class TestCsv(unittest.TestCase):
    def setUp(self):
        self.res = _poisoned()
        self.text = to_csv(self.res)

    def test_header(self):
        first = self.text.splitlines()[0]
        self.assertEqual(first, "severity,rank,code,message,detail")

    def test_row_count(self):
        rows = list(csv.reader(io.StringIO(self.text)))
        self.assertEqual(len(rows) - 1, len(self.res.findings))

    def test_detail_is_json(self):
        rows = list(csv.DictReader(io.StringIO(self.text)))
        for row in rows:
            json.loads(row["detail"])  # must parse

    def test_sorted_by_rank_desc(self):
        rows = list(csv.DictReader(io.StringIO(self.text)))
        ranks = [int(r["rank"]) for r in rows]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_clean_store_only_header(self):
        clean = audit_store([Record("a", [0.9, 0.1]), Record("b", [0.1, 0.9]),
                             Record("c", [0.4, 0.6])])
        self.assertEqual(len(to_csv(clean).strip().splitlines()), 1)


class TestRiskScore(unittest.TestCase):
    def test_clean_is_zero(self):
        clean = audit_store([Record("a", [0.9, 0.1]), Record("b", [0.1, 0.9]),
                             Record("c", [0.4, 0.6])])
        self.assertEqual(risk_score(clean), 0)

    def test_poison_is_positive(self):
        self.assertGreater(risk_score(_poisoned()), 0)

    def test_monotonic_with_severity(self):
        clean = audit_store([Record("a", [0.9, 0.1]), Record("b", [0.1, 0.9]),
                             Record("c", [0.4, 0.6])])
        self.assertLess(risk_score(clean), risk_score(_poisoned()))


if __name__ == "__main__":
    unittest.main()
