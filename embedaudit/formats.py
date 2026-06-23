"""Output formats for EMBEDAUDIT findings.

Pure standard library. Renders an :class:`AuditResult` into the formats a
security/data pipeline already speaks:

* ``table``  — human-readable (rendered in ``cli``)
* ``json``   — the canonical machine report (``AuditResult.to_dict``)
* ``sarif``  — SARIF 2.1.0 for GitHub code-scanning / any SARIF viewer
* ``csv``    — one row per finding for spreadsheets / SIEM ingest

Severity maps to a stable, documented vocabulary so downstream gates are
deterministic. Nothing here touches the network.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

# embedaudit severity -> SARIF level
_SARIF_LEVEL = {"critical": "error", "warning": "warning", "info": "note"}
# embedaudit severity -> generic numeric rank (higher = worse)
_RANK = {"critical": 3, "warning": 2, "info": 1}

# Stable rule metadata for the documented finding codes.
RULE_HELP: dict[str, str] = {
    "DIM_MISMATCH": "Vectors in the store do not all share one dimension; a "
    "silent embedding-model swap or a corrupt write.",
    "INVALID_VALUE": "A vector contains NaN/Inf — un-indexable and a sign of a "
    "broken embedding pipeline.",
    "ZERO_VECTOR": "A zero-norm vector cannot be embedded meaningfully; usually "
    "a failed embed call written to the store.",
    "NORM_OUTLIER": "A vector's L2 norm is a statistical outlier — possible "
    "mis-scaled vector or a different model's output.",
    "DUPLICATE_VECTOR": "Near-identical duplicate vectors inflate the index and "
    "can flood top-k retrieval.",
    "OUTLIER_VECTOR": "A vector sits far from the store centroid — an injected "
    "off-topic / poison document.",
    "RETRIEVAL_DOMINATION": "A tight cluster of near-identical vectors makes up a "
    "large share of the store and can hijack retrieval (universal poison docs).",
    "DRIFT": "The current snapshot's distribution moved away from the trusted "
    "baseline — poisoning or a silent model swap on an append-only store.",
    "RECORD_LOSS": "The current snapshot has fewer records than the baseline — "
    "possible deletion / truncation / rollback.",
}


def to_sarif(result: Any, *, tool_name: str = "embedaudit",
             tool_version: str = "0.0.0") -> dict:
    """Render an AuditResult as a SARIF 2.1.0 log (a plain dict)."""
    seen: dict[str, dict] = {}
    results: list[dict] = []
    for f in result.findings:
        if f.code not in seen:
            seen[f.code] = {
                "id": f.code,
                "name": f.code.title().replace("_", ""),
                "shortDescription": {"text": f.code.replace("_", " ").title()},
                "fullDescription": {"text": RULE_HELP.get(f.code, f.code)},
                "helpUri": "https://github.com/cognis-digital/embedaudit#findings",
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "note")},
            }
        results.append({
            "ruleId": f.code,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f.message},
            "properties": dict(f.detail),
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": "https://github.com/cognis-digital/embedaudit",
                "rules": list(seen.values()),
            }},
            "results": results,
            "properties": {
                "recordCount": result.record_count,
                "dimension": result.dimension,
                "ok": result.ok,
            },
        }],
    }


def to_csv(result: Any) -> str:
    """Render findings as CSV text (one row per finding)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["severity", "rank", "code", "message", "detail"])
    order = sorted(result.findings, key=lambda x: -_RANK.get(x.severity, 0))
    for f in order:
        w.writerow([
            f.severity,
            _RANK.get(f.severity, 0),
            f.code,
            f.message,
            json.dumps(f.detail, separators=(",", ":")),
        ])
    return buf.getvalue()


def risk_score(result: Any) -> int:
    """A single deterministic integer summarising a result's severity."""
    return sum(_RANK.get(f.severity, 0) for f in result.findings)
