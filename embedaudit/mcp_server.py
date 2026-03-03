"""EMBEDAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from embedaudit.core import scan, to_json

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
        return to_json(scan(target))

    app.run()
    return 0
