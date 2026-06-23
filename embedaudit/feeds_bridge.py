"""Edge / air-gap feed bridge for EMBEDAUDIT.

EMBEDAUDIT's core audit is pure-math and fully offline. This optional bridge
lets an operator enrich an audit with **real, keyless threat-intel context**
from the bundled Cognis data-feed catalog (``embedaudit/feeds/``):

* ``threat-intel`` / ``osint`` feeds (abuse.ch URLhaus, OpenPhish, …) provide
  known-bad URLs / domains. If a poisoned RAG document smuggles one of these
  into its ``text``, the bridge flags it — no network calls at query time.
* The vulnerability feeds (CISA KEV / EPSS / OSV / NVD) are **not** used here:
  CVEs are irrelevant to embedding integrity, so we deliberately ignore them.

Everything works **offline / air-gapped**:

* The catalog JSON ships in the package, so ``list_catalog()`` works with no
  network at all.
* ``datafeeds`` caches each fetched feed to disk and can serve ``offline=True``.
* ``datafeeds snapshot-export`` tars the cache for sneakernet into an enclave.

This module degrades gracefully: if the ``feeds`` package is unavailable it
returns empty results rather than raising, so the core tool never depends on it.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# Only these catalog domains are relevant to embedding-content poisoning.
RELEVANT_DOMAINS = ("threat-intel", "osint")

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)


def _datafeeds():
    """Import the bundled datafeeds module, or return None if unavailable."""
    try:
        from embedaudit.feeds import datafeeds as df  # type: ignore
        return df
    except Exception:  # pragma: no cover - defensive
        return None


def available() -> bool:
    """True if the bundled feed catalog can be loaded offline."""
    df = _datafeeds()
    if df is None:
        return False
    try:
        return bool(df.load_catalog().get("feeds"))
    except Exception:  # pragma: no cover
        return False


def list_catalog(domain: str | None = None) -> list[dict]:
    """List catalog feeds (offline; reads the bundled JSON). Filter by domain."""
    df = _datafeeds()
    if df is None:
        return []
    feeds = df.list_feeds(domain=domain)
    if domain is None:
        feeds = [f for f in feeds if f.get("domain") in RELEVANT_DOMAINS]
    return feeds


def extract_indicators(text: str) -> dict[str, list[str]]:
    """Pull candidate URLs / domains out of a record's text (offline, regex)."""
    urls = _URL_RE.findall(text or "")
    domains = {m.group(0).lower() for m in _DOMAIN_RE.finditer(text or "")}
    # don't double-count the host part of a captured URL as a bare domain
    for u in urls:
        for d in list(domains):
            if d in u:
                domains.discard(d)
    return {"urls": sorted(set(urls)), "domains": sorted(domains)}


def _load_blocklist(offline: bool = True) -> set[str]:
    """Load known-bad URLs/domains from cached threat-intel feeds (offline).

    Returns an empty set if nothing is cached — the caller treats that as
    "no enrichment available" rather than an error.
    """
    df = _datafeeds()
    if df is None:
        return set()
    bad: set[str] = set()
    for feed in list_catalog():
        fid = feed.get("id")
        if not fid:
            continue
        try:
            raw = df.get(fid, offline=offline)
        except Exception:
            continue  # not cached / offline with no snapshot
        if isinstance(raw, (dict, list)):
            raw = str(raw)
        for line in str(raw).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tok = line.split(",")[0].split()[0].strip().lower()
            if tok:
                bad.add(tok)
    return bad


def scan_records_for_known_bad(records: Iterable[Any], *, offline: bool = True
                               ) -> list[dict]:
    """Flag records whose text contains a known-bad indicator from cached feeds.

    Args:
        records: objects with ``.id`` and ``.text`` (embedaudit ``Record``).
        offline: serve only cached feeds; never touch the network.

    Returns a list of ``{"id", "indicator", "kind"}`` hits. Empty if no feed
    cache is present (so the audit still runs fully offline by default).
    """
    blocklist = _load_blocklist(offline=offline)
    if not blocklist:
        return []
    hits: list[dict] = []
    for r in records:
        ind = extract_indicators(getattr(r, "text", "") or "")
        for url in ind["urls"]:
            low = url.lower()
            if any(b in low for b in blocklist):
                hits.append({"id": getattr(r, "id", "?"), "indicator": url,
                             "kind": "url"})
        for dom in ind["domains"]:
            if dom in blocklist:
                hits.append({"id": getattr(r, "id", "?"), "indicator": dom,
                             "kind": "domain"})
    return hits
