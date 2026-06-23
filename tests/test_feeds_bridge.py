"""Tests for the offline edge/air-gap feed bridge. Stdlib only, no network.

These exercise the *offline* paths exclusively: the bundled catalog JSON and
in-memory indicator extraction. Nothing here touches the network — feed fetches
are gated behind an explicit cache that these tests never populate.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from embedaudit import feeds_bridge as fb  # noqa: E402
from embedaudit.core import Record, audit_store  # noqa: E402


class TestCatalog(unittest.TestCase):
    def test_available_offline(self):
        # The catalog JSON ships in the package, so this is True offline.
        self.assertTrue(fb.available())

    def test_list_catalog_nonempty(self):
        feeds = fb.list_catalog()
        self.assertTrue(feeds)

    def test_relevant_domains_only_by_default(self):
        for f in fb.list_catalog():
            self.assertIn(f.get("domain"), fb.RELEVANT_DOMAINS)

    def test_osv_and_vuln_excluded_by_default(self):
        ids = {f.get("id") for f in fb.list_catalog()}
        # vuln/CVE feeds are deliberately irrelevant to embeddings
        self.assertNotIn("osv", ids)
        self.assertFalse(any(f.get("domain") == "vuln" for f in fb.list_catalog()))

    def test_domain_filter_passthrough(self):
        vuln = fb.list_catalog(domain="vuln")
        # explicit domain filter bypasses the relevance gate
        for f in vuln:
            self.assertEqual(f.get("domain"), "vuln")

    def test_catalog_entries_have_ids(self):
        for f in fb.list_catalog():
            self.assertTrue(f.get("id"))


class TestIndicators(unittest.TestCase):
    def test_extract_url(self):
        ind = fb.extract_indicators("see http://evil.example/payload for more")
        self.assertIn("http://evil.example/payload", ind["urls"])

    def test_extract_https_url(self):
        ind = fb.extract_indicators("visit https://bad.test/x?y=1 now")
        self.assertTrue(any(u.startswith("https://bad.test") for u in ind["urls"]))

    def test_extract_bare_domain(self):
        ind = fb.extract_indicators("contact mail at phish.example today")
        self.assertIn("phish.example", ind["domains"])

    def test_url_host_not_double_counted(self):
        ind = fb.extract_indicators("go to http://evil.example/p")
        self.assertNotIn("evil.example", ind["domains"])

    def test_empty_text(self):
        ind = fb.extract_indicators("")
        self.assertEqual(ind["urls"], [])
        self.assertEqual(ind["domains"], [])

    def test_none_safe(self):
        ind = fb.extract_indicators(None)  # type: ignore[arg-type]
        self.assertEqual(ind["urls"], [])

    def test_plain_text_no_indicators(self):
        ind = fb.extract_indicators("How do I reset my password?")
        self.assertEqual(ind["urls"], [])
        self.assertEqual(ind["domains"], [])


class TestScanNoCache(unittest.TestCase):
    def test_no_cache_yields_no_hits(self):
        # With no feed cache present, scan returns [] (pure offline default).
        recs = [Record("a", [1.0, 0.0], text="http://evil.example/x")]
        hits = fb.scan_records_for_known_bad(recs, offline=True)
        self.assertEqual(hits, [])

    def test_audit_enrich_is_noop_without_cache(self):
        recs = [Record("a", [0.9, 0.1], text="http://evil.example/x"),
                Record("b", [0.1, 0.9], text="clean"),
                Record("c", [0.4, 0.6], text="clean")]
        plain = audit_store(recs)
        enriched = audit_store(recs, enrich_feeds=True)
        # No cache -> no KNOWN_BAD_CONTENT, identical finding set
        codes_plain = {f.code for f in plain.findings}
        codes_enriched = {f.code for f in enriched.findings}
        self.assertEqual(codes_plain, codes_enriched)
        self.assertNotIn("KNOWN_BAD_CONTENT", codes_enriched)


class TestScanWithFakeCache(unittest.TestCase):
    """Inject a fake blocklist to exercise the matching path (still offline)."""

    def test_known_bad_url_flagged(self):
        orig = fb._load_blocklist
        fb._load_blocklist = lambda offline=True: {"http://evil.example/x"}
        try:
            recs = [Record("a", [1.0, 0.0], text="http://evil.example/x"),
                    Record("b", [0.0, 1.0], text="totally clean")]
            hits = fb.scan_records_for_known_bad(recs)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["id"], "a")
            self.assertEqual(hits[0]["kind"], "url")
        finally:
            fb._load_blocklist = orig

    def test_known_bad_domain_flagged(self):
        orig = fb._load_blocklist
        fb._load_blocklist = lambda offline=True: {"phish.example"}
        try:
            recs = [Record("a", [1.0, 0.0], text="reach me at phish.example")]
            hits = fb.scan_records_for_known_bad(recs)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["kind"], "domain")
        finally:
            fb._load_blocklist = orig

    def test_audit_enrich_adds_critical_with_cache(self):
        orig = fb._load_blocklist
        fb._load_blocklist = lambda offline=True: {"http://evil.example/x"}
        try:
            recs = [Record("a", [0.9, 0.1], text="http://evil.example/x"),
                    Record("b", [0.1, 0.9], text="clean"),
                    Record("c", [0.4, 0.6], text="clean")]
            res = audit_store(recs, enrich_feeds=True)
            self.assertTrue(any(f.code == "KNOWN_BAD_CONTENT" for f in res.findings))
            self.assertFalse(res.ok)
        finally:
            fb._load_blocklist = orig


if __name__ == "__main__":
    unittest.main()
