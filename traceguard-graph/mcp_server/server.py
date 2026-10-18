"""TraceGuard MCP server.

Exposes TraceGuard's graph tools to any MCP client (Claude Desktop, Claude Code, the MCP Inspector).
It is a thin wrapper over the running TraceGuard API, so every call uses the same graph, the same
provenance and the same audit trail as the web app. The CLIENT chooses which tool to call.

Run (stdio):  python server.py
Env:          TRACEGUARD_API  (default http://localhost:8000)
"""
import os
from typing import Optional

import httpx
from mcp.server.fastmcp import FastMCP

API = os.getenv("TRACEGUARD_API", "http://localhost:8000").rstrip("/")
mcp = FastMCP("traceguard")


def _call(method: str, path: str, **kwargs):
    try:
        r = httpx.request(method, f"{API}{path}", timeout=30, **kwargs)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Cannot reach the TraceGuard API at {API}. Is 'docker compose up' running? ({e})")
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        raise RuntimeError(f"TraceGuard API returned {r.status_code}: {detail}")
    return r.json()


@mcp.tool()
def list_identities() -> dict:
    """List every identity in the graph with its role, status and alert counts."""
    return _call("GET", "/identities")


@mcp.tool()
def triage_identities() -> dict:
    """Read-only scan of every identity, ranked by risk, each with its proposed containment.
    Saves nothing and changes nothing. Use this first to decide whom to investigate."""
    return _call("POST", "/agent/triage")


@mcp.tool()
def investigate_identity(identity: str) -> dict:
    """Investigate one identity: multi-hop attack paths to high-sensitivity assets (each hop names the
    source system that asserted it), blast radius, scoped evidence, a containment recommendation, and
    the change since the previous saved run. Saves the run to graph memory and returns its investigation_id,
    which apply_containment needs. Fails with 404 if the identity does not exist."""
    j = _call("POST", "/agent/investigate", json={"identity": identity, "use_llm": False})
    return {"investigation_id": j["investigation_id"], "answer": j["answer"],
            "findings": j["findings"], "comparison": j["comparison"]}


@mcp.tool()
def simulate_impact(asset: str, depth: int = 3) -> dict:
    """What an asset can reach (compromise spread) and what depends on it (outage spread), up to `depth` hops."""
    return _call("POST", "/graph/simulate", json={"node": asset, "depth": depth})["data"]


@mcp.tool()
def who_found_paths_to(asset: str) -> dict:
    """Graph-memory recall: which saved investigations found an attack path to this asset?"""
    return _call("GET", f"/memory/asset/{asset}")


@mcp.tool()
def apply_containment(edges: list[dict[str, str]], confirm: bool = False,
                      investigation_id: Optional[str] = None) -> dict:
    """CHANGES THE GRAPH. Cut relationships to contain an identity. Each edge is
    {"source": ..., "target": ..., "type": "CONNECTS_TO" | "DEPENDS_ON" | "HAS_ACCESS_TO"}.
    Use the edges from an investigation's containment recommendation, and pass its investigation_id
    so the audit trail links the action to the run that proposed it.
    Call it only after the human has approved; without confirm=true it only returns a preview."""
    if not confirm:
        return {"applied": False,
                "preview": edges,
                "message": "Nothing was changed. Ask the user to approve, then call again with confirm=true."}
    return _call("POST", "/graph/contain", json={"investigation_id": investigation_id, "edges": edges})


@mcp.tool()
def list_actions() -> dict:
    """The audit trail: every containment action applied, with its edge source and the run that proposed it."""
    return _call("GET", "/actions")


@mcp.tool()
def undo_action(action_id: str) -> dict:
    """Undo one applied action by id. The removed relationship is restored with its original source."""
    return _call("POST", f"/actions/{action_id}/undo")


if __name__ == "__main__":
    mcp.run()