"""EMBEDAUDIT MCP server — exposes the audit/drift API as MCP tools.

For Claude Desktop, Cursor, Cognis.Studio, and the uncensored-fleet. Requires
the optional 'mcp' extra:  pip install "cognis-embedaudit[mcp]"
"""
from __future__ import annotations

import json

from embedaudit.core import audit_store, drift_report, load_jsonl


def serve() -> int:
    """Start an MCP stdio server exposing embedaudit_audit / embedaudit_drift."""
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-embedaudit[mcp]'")
        return 1
    app = FastMCP("embedaudit")

    @app.tool()
    def embedaudit_audit(snapshot_path: str, dup_threshold: float = 0.999,
                         domination_share: float = 0.30) -> str:
        """Audit a JSONL embedding snapshot for drift/poisoning. Returns JSON."""
        recs = load_jsonl(snapshot_path)
        res = audit_store(recs, dup_threshold=dup_threshold,
                          domination_share=domination_share)
        return json.dumps(res.to_dict(), indent=2)

    @app.tool()
    def embedaudit_drift(baseline_path: str, current_path: str,
                         drift_threshold: float = 0.15) -> str:
        """Compare a baseline JSONL snapshot to a current one. Returns JSON."""
        res = drift_report(load_jsonl(baseline_path), load_jsonl(current_path),
                           drift_threshold=drift_threshold)
        return json.dumps(res.to_dict(), indent=2)

    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(serve())
