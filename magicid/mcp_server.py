"""MAGICID MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import os

from magicid.core import scan_paths


def _scan_to_json(target: str) -> str:
    """Scan *target* (file or directory) and return findings as a JSON string."""
    if not target or not target.strip():
        return json.dumps({"error": "target path must not be empty"})
    target = target.strip()
    if not os.path.exists(target):
        return json.dumps({"error": f"path does not exist: {target}"})
    results = scan_paths([target], recursive=os.path.isdir(target))
    payload = {
        "count": len(results),
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2)


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
        return _scan_to_json(target)

    app.run()
    return 0
