"""MAGICID MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from magicid.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-magicid[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-magicid[mcp]'")
        return 1
    app = FastMCP("magicid")

    @app.tool()
    def magicid_scan(target: str) -> str:
        """Identify true file types by magic bytes (beats extensions). Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
