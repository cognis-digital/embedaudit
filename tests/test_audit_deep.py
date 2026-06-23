"""Deep audit + drift edge-case tests. Stdlib only, no network."""

import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from embedaudit.core import (  # noqa: E402
    Record, audit_store, drift_report,
    _cosine, _dot, _mean_vector, _norm, _quantize_key, _greedy_clusters,
)


class TestVectorMath(unittest.TestCase):
    def test_norm_pythagorean(self):
        self.assertAlmostEqual(_norm([3.0, 4.0]), 5.0)

    def test_norm_zero(self):
        self.assertEqual(_norm([0.0, 0.0]), 0.0)

    def test_dot(self):
        self.assertEqual(_dot([1.0, 2.0, 3.0], [4.0, 5.0, 6.0]), 32.0)

    def test_cosine_identical(self):
        v = [1.0, 1.0]
        n = _norm(v)
        self.assertAlmostEqual(_cosine(v, v, n, n), 1.0)

    def test_cosine_orthogonal(self):
        a, b = [1.0, 0.0], [0.0, 1.0]
        self.assertAlmostEqual(_cosine(a, b, _norm(a), _norm(b)), 0.0)

    def test_cosine_opposite(self):
        a, b = [1.0, 0.0], [-1.0, 0.0]
        self.assertAlmostEqual(_cosine(a, b, _norm(a), _norm(b)), -1.0)

    def test_cosine_zero_norm_safe(self):
        self.assertEqual(_cosine([0.0, 0.0], [1.0, 1.0], 0.0, _norm([1.0, 1.0])), 0.0)

    def test_mean_vector(self):
        m = _mean_vector([[0.0, 2.0], [2.0, 0.0]], 2)
        self.assertEqual(m, [1.0, 1.0])

    def test_quantize_key_identical(self):
        self.assertEqual(_quantize_key([0.5, 0.5]), _quantize_key([0.5004, 0.4996]))

    def test_quantize_key_distinct(self):
        self.assertNotEqual(_quantize_key([0.5, 0.5]), _quantize_key([0.9, 0.1]))

    def test_greedy_clusters_merges_near(self):
        vs = [[1.0, 0.0], [1.0, 0.0001], [0.0, 1.0]]
        ns = [_norm(v) for v in vs]
        clusters = _greedy_clusters(vs, ns, 0.999)
        sizes = sorted(len(c) for c in clusters)
        self.assertEqual(sizes, [1, 2])


class TestAuditFindings(unittest.TestCase):
    def test_clean_store_no_findings(self):
        recs = [Record("a", [0.9, 0.1, 0.0]), Record("b", [0.1, 0.9, 0.0]),
                Record("c", [0.0, 0.1, 0.9]), Record("d", [0.2, 0.2, 0.8])]
        res = audit_store(recs)
        self.assertTrue(res.ok)
        self.assertEqual(res.findings, [])

    def test_record_count_and_dimension(self):
        recs = [Record("a", [1.0, 0.0, 0.0]), Record("b", [0.0, 1.0, 0.0])]
        res = audit_store(recs)
        self.assertEqual(res.record_count, 2)
        self.assertEqual(res.dimension, 3)

    def test_nan_is_invalid_value(self):
        recs = [Record("a", [float("nan"), 0.0]), Record("b", [0.0, 1.0]),
                Record("c", [0.3, 0.7])]
        res = audit_store(recs)
        self.assertTrue(any(f.code == "INVALID_VALUE" for f in res.findings))
        self.assertFalse(res.ok)

    def test_inf_is_invalid_value(self):
        recs = [Record("a", [float("inf"), 0.0]), Record("b", [0.0, 1.0]),
                Record("c", [0.3, 0.7])]
        res = audit_store(recs)
        self.assertTrue(any(f.code == "INVALID_VALUE" for f in res.findings))

    def test_zero_vector_lists_ids(self):
        recs = [Record("z1", [0.0, 0.0]), Record("a", [1.0, 0.0]),
                Record("b", [0.0, 1.0])]
        res = audit_store(recs)
        zv = [f for f in res.findings if f.code == "ZERO_VECTOR"][0]
        self.assertIn("z1", zv.detail["ids"])

    def test_dim_mismatch_uses_majority(self):
        recs = [Record("a", [1.0, 0.0]), Record("b", [0.0, 1.0]),
                Record("c", [0.5, 0.5]), Record("odd", [1.0, 0.0, 0.0])]
        res = audit_store(recs)
        self.assertEqual(res.dimension, 2)
        self.assertTrue(any(f.code == "DIM_MISMATCH" for f in res.findings))

    def test_duplicate_pairs_counted(self):
        recs = [Record("a", [0.5, 0.5]), Record("b", [0.5, 0.5]),
                Record("c", [0.5, 0.5]), Record("d", [0.1, 0.9])]
        res = audit_store(recs)
        self.assertEqual(res.stats["duplicate_pairs"], 2)

    def test_norm_outlier_flagged(self):
        # spread directions so no domination cluster forms; one giant norm
        recs = [Record(str(i), [math.cos(i), math.sin(i), i * 0.01])
                for i in range(30)]
        recs.append(Record("big", [500.0, 500.0, 500.0]))
        res = audit_store(recs)
        self.assertTrue(any(f.code == "NORM_OUTLIER" for f in res.findings))

    def test_domination_share_threshold(self):
        recs = [Record(f"p{i}", [0.5 + i * 1e-5, 0.5, 0.5]) for i in range(8)]
        recs += [Record("x", [0.9, 0.1, 0.0]), Record("y", [0.0, 0.1, 0.9])]
        res = audit_store(recs, domination_share=0.30)
        self.assertTrue(any(f.code == "RETRIEVAL_DOMINATION" for f in res.findings))
        self.assertFalse(res.ok)

    def test_domination_not_flagged_when_below_threshold(self):
        recs = [Record(f"p{i}", [0.5 + i * 1e-5, 0.5, 0.5]) for i in range(2)]
        recs += [Record(f"q{i}", [0.1 * i, 1.0, 0.2 * i]) for i in range(8)]
        res = audit_store(recs, domination_share=0.30)
        self.assertFalse(any(f.code == "RETRIEVAL_DOMINATION" for f in res.findings))

    def test_stats_keys_present(self):
        recs = [Record("a", [0.9, 0.1]), Record("b", [0.1, 0.9]),
                Record("c", [0.4, 0.6])]
        res = audit_store(recs)
        for k in ("mean_norm", "std_norm", "min_norm", "max_norm",
                  "mean_centroid_sim", "duplicate_pairs", "largest_cluster",
                  "largest_cluster_share", "num_clusters"):
            self.assertIn(k, res.stats)

    def test_to_dict_roundtrip(self):
        recs = [Record("z", [0.0, 0.0]), Record("a", [1.0, 0.0]),
                Record("b", [0.0, 1.0])]
        d = audit_store(recs).to_dict()
        self.assertIn("findings", d)
        self.assertIn("ok", d)
        self.assertFalse(d["ok"])

    def test_ok_property_only_critical(self):
        recs = [Record(str(i), [math.cos(i), math.sin(i), i * 0.01])
                for i in range(30)]
        recs.append(Record("big", [500.0, 500.0, 500.0]))  # warning only
        res = audit_store(recs)
        # only NORM_OUTLIER (a warning) should fire -> still ok
        self.assertTrue(all(f.severity != "critical" for f in res.findings))
        self.assertTrue(res.ok)


class TestDriftDeep(unittest.TestCase):
    def test_identical_no_drift(self):
        base = [Record(str(i), [1.0, 0.0]) for i in range(5)]
        cur = [Record(str(i), [1.0, 0.0]) for i in range(5)]
        res = drift_report(base, cur)
        self.assertTrue(res.ok)
        self.assertAlmostEqual(res.stats["drift_score"], 0.0, places=6)

    def test_orthogonal_drift_critical(self):
        base = [Record(str(i), [1.0, 0.0]) for i in range(5)]
        cur = [Record(str(i), [0.0, 1.0]) for i in range(5)]
        res = drift_report(base, cur)
        self.assertFalse(res.ok)
        d = [f for f in res.findings if f.code == "DRIFT"][0]
        self.assertEqual(d.severity, "critical")

    def test_dim_change_short_circuits(self):
        base = [Record("a", [1.0, 0.0])]
        cur = [Record("a", [1.0, 0.0, 0.0])]
        res = drift_report(base, cur)
        self.assertTrue(any(f.code == "DIM_MISMATCH" for f in res.findings))
        self.assertFalse(res.ok)

    def test_internal_inconsistency_short_circuits(self):
        base = [Record("a", [1.0, 0.0]), Record("b", [1.0, 0.0, 0.0])]
        cur = [Record("a", [1.0, 0.0])]
        res = drift_report(base, cur)
        self.assertTrue(any(f.code == "DIM_MISMATCH" for f in res.findings))

    def test_record_loss_warns(self):
        base = [Record(str(i), [1.0, 0.0]) for i in range(10)]
        cur = [Record(str(i), [1.0, 0.0]) for i in range(4)]
        res = drift_report(base, cur)
        self.assertTrue(any(f.code == "RECORD_LOSS" for f in res.findings))

    def test_no_record_loss_when_growing(self):
        base = [Record(str(i), [1.0, 0.0]) for i in range(4)]
        cur = [Record(str(i), [1.0, 0.0]) for i in range(10)]
        res = drift_report(base, cur)
        self.assertFalse(any(f.code == "RECORD_LOSS" for f in res.findings))

    def test_drift_score_bounded(self):
        base = [Record(str(i), [1.0, 0.0]) for i in range(5)]
        cur = [Record(str(i), [0.0, 1.0]) for i in range(5)]
        res = drift_report(base, cur)
        self.assertGreaterEqual(res.stats["drift_score"], 0.0)
        self.assertLessEqual(res.stats["drift_score"], 2.0)

    def test_drift_stats_keys(self):
        base = [Record(str(i), [1.0, 0.0]) for i in range(5)]
        cur = [Record(str(i), [0.9, 0.1]) for i in range(5)]
        res = drift_report(base, cur)
        for k in ("drift_score", "centroid_distance", "fraction_dims_drifted",
                  "baseline_records", "current_records"):
            self.assertIn(k, res.stats)


if __name__ == "__main__":
    unittest.main()
