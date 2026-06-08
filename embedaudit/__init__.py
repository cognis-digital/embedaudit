"""EMBEDAUDIT - Embedding / vector-store drift and poisoning audit.

A zero-install, standard-library-only auditor for embedding stores used in
RAG pipelines. It detects:

  * Dimension / norm anomalies (corrupted or mis-scaled vectors).
  * Duplicate / near-duplicate vectors (index bloat, retrieval flooding).
  * Distributional DRIFT between a trusted baseline snapshot and a current
    snapshot (per-dimension mean shift -> data poisoning / model swap).
  * Poisoning indicators: outlier vectors, suspiciously dense clusters that
    can dominate retrieval (a small set of texts that are near-identical to
    everything -> classic RAG injection / "universal" poison docs).

Input format: JSONL where each line is a record:
    {"id": "doc-1", "vector": [0.1, 0.2, ...], "text": "optional"}

Stdlib only. Python 3.10+.
"""

from .core import (
    Record,
    load_jsonl,
    audit_store,
    drift_report,
    AuditResult,
)

TOOL_NAME = "embedaudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Record",
    "load_jsonl",
    "audit_store",
    "drift_report",
    "AuditResult",
    "TOOL_NAME",
    "TOOL_VERSION",
]
