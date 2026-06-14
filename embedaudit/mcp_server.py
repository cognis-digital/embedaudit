"""EMBEDAUDIT MCP server — exposes audit() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from embedaudit.core import AuditError, audit_store, load_jsonl


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-embedaudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-embedaudit[mcp]'")
        return 1
    app = FastMCP("embedaudit")

    @app.tool()
    def embedaudit_scan(target: str) -> str:
        """Embedding / vector-store drift and poisoning audit. Returns JSON findings."""
        try:
            records = load_jsonl(target)
            result = audit_store(records)
        except (AuditError, FileNotFoundError, OSError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(result.to_dict())

    app.run()
    return 0
