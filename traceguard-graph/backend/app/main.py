import os, re, json, time, httpx
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .grounding import ungrounded_terms
from .graph import query
from .seed import seed_graph, graph_is_empty
from .actions import record_action, list_actions, undo_action, clear_actions
from .memory import save_investigation, list_memory, clear_memory, compare, who_found_paths_to
from .investigation import run_investigation, deterministic_answer, simulate_impact

REL_TYPES = {"CONNECTS_TO", "DEPENDS_ON", "HAS_ACCESS_TO"}


@asynccontextmanager
async def lifespan(_app):
    # First start: fill an empty graph so the UI is never blank. Never wipes existing data.
    try:
        if graph_is_empty():
            seed_graph()
    except Exception as e:
        print(f"[startup] could not auto-seed yet: {e}")
    yield


app = FastAPI(title="TraceGuard API", version="1.1.0", description="Graph-native synthetic cyber investigation demo", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)


class InvestigationRequest(BaseModel):
    identity: str = "elena.rostova"
    use_llm: bool = False


class SimulateRequest(BaseModel):
    node: str
    depth: int = 3


class NewIdentity(BaseModel):
    name: str
    role: str = "unspecified"


class Link(BaseModel):
    source: str
    target: str
    type: str = "CONNECTS_TO"


@app.get("/")
def root():
    return {"name": "TraceGuard API", "docs": "/docs"}


@app.get("/health")
def health():
    try:
        start = time.perf_counter()
        query("RETURN 1 AS ok")
        return {"status": "ok", "graph": "connected", "db_ms": round((time.perf_counter() - start) * 1000, 2)}
    except Exception as e:
        raise HTTPException(503, detail=f"Graph database not reachable: {e}")


@app.post("/demo/seed")
def seed():
    try:
        return seed_graph()
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.get("/graph/overview")
def overview():
    try:
        nodes = query("MATCH (n) WHERE NOT n:Investigation AND NOT n:Action RETURN count(n) AS count")[0]["count"]
        edges = query("MATCH (a)-[r]->(b) WHERE NOT a:Investigation AND NOT a:Action RETURN count(r) AS count")[0]["count"]
        runs = query("MATCH (m:Investigation) RETURN count(m) AS count")[0]["count"]
        return {"node_count": nodes, "edge_count": edges, "investigation_count": runs, "synthetic_demo_data": True}
    except Exception as e:
        raise HTTPException(503, detail=str(e))


@app.get("/graph/data")
def graph_data():
    try:
        ns = query("MATCH (n) WHERE NOT n:Investigation AND NOT n:Action RETURN id(n) AS id, labels(n) AS labels, properties(n) AS properties")
        es = query("MATCH (a)-[r]->(b) RETURN id(r) AS id, id(a) AS source, id(b) AS target, type(r) AS type, properties(r) AS properties")
        nodes = []
        for n in ns:
            p = dict(n.get("properties") or {})
            labels = n.get("labels") or []
            nodes.append({"id": str(n["id"]), "labels": labels, "type": labels[0] if labels else "Unknown", "name": p.get("name"), "properties": p})
        ids = {n["id"] for n in nodes}
        edges = [
            {"id": str(e["id"]), "source": str(e["source"]), "target": str(e["target"]), "type": e["type"], "label": e["type"], "properties": dict(e.get("properties") or {})}
            for e in es if str(e["source"]) in ids and str(e["target"]) in ids
        ]
        return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges), "synthetic_demo_data": True}
    except Exception as e:
        raise HTTPException(503, detail=str(e))


@app.get("/identities")
def identities():
    try:
        rows = query(
            """MATCH (i:Identity)
               OPTIONAL MATCH (a:Alert)-[:INVOLVES]->(i)
               RETURN i.name AS name, i.role AS role, i.status AS status,
                      count(a) AS alerts, sum(CASE WHEN a.severity = 'high' THEN 1 ELSE 0 END) AS high_alerts
               ORDER BY name"""
        )
        return {"identities": rows}
    except Exception as e:
        raise HTTPException(503, detail=str(e))

@app.delete("/actions")
def actions_clear():
    try:
        clear_actions()
        return {"status": "cleared"}
    except Exception as e:
        raise HTTPException(500, detail=str(e))

def _find(name):
    rows = query("MATCH (n) WHERE n.name = $name AND (n:Asset OR n:Identity) RETURN labels(n)[0] AS label", {"name": name})
    return rows[0]["label"] if rows else None


def _check_link(link: Link):
    if link.type not in REL_TYPES:
        raise HTTPException(400, detail=f"type must be one of {sorted(REL_TYPES)}")
    src, dst = _find(link.source), _find(link.target)
    if not src or not dst:
        raise HTTPException(404, detail="Source or target not found in the graph.")
    if link.type == "HAS_ACCESS_TO" and (src != "Identity" or dst != "Asset"):
        raise HTTPException(400, detail="HAS_ACCESS_TO must go from an identity to an asset.")
    if link.type != "HAS_ACCESS_TO" and (src != "Asset" or dst != "Asset"):
        raise HTTPException(400, detail=f"{link.type} must go from an asset to an asset.")
    if link.source == link.target:
        raise HTTPException(400, detail="Source and target must be different.")


@app.post("/graph/connect")
def connect(link: Link):
    _check_link(link)
    try:
        rows = query(
            f"MATCH (a {{name:$a}}), (b {{name:$b}}) WHERE (a:Asset OR a:Identity) AND b:Asset MERGE (a)-[r:{link.type}]->(b) ON CREATE SET r.source='analyst-change' RETURN r.source AS source",
            {"a": link.source, "b": link.target},
        )
        return {"status": "connected", "link": link.model_dump(), "source": rows[0]["source"] if rows else None}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.post("/graph/disconnect")
def disconnect(link: Link):
    _check_link(link)
    try:
        rows = query(
            f"MATCH (a {{name:$a}})-[r:{link.type}]->(b {{name:$b}}) DELETE r RETURN count(r) AS removed",
            {"a": link.source, "b": link.target},
        )
        removed = rows[0]["removed"] if rows else 0
        if not removed:
            raise HTTPException(404, detail="That relationship does not exist.")
        return {"status": "disconnected", "link": link.model_dump()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=str(e))


def ollama_summary(findings):
    base = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
    slim = {k: findings[k] for k in ("identity", "role", "risk_level", "paths", "alerts", "evidence", "blast_radius")}
    prompt = ("Summarize these synthetic security graph findings cautiously in 3 concise sentences. "
              "Do not claim compromise. Findings: " + json.dumps(slim))
    try:
        r = httpx.post(f"{base}/api/generate", json={"model": model, "prompt": prompt, "stream": False}, timeout=60)
        r.raise_for_status()
        text = (r.json().get("response") or "").strip()
        if not text:
            raise ValueError("empty response")
        bad = ungrounded_terms(text, findings)
        if bad:
            return {"requested": True, "status": "unavailable", "model": model, "text": None,
                    "error": f"Summary rejected: it named terms that are not in the graph findings ({', '.join(bad)}). Graph analysis was still completed."}
        return {"requested": True, "status": "ok", "model": model, "text": text}
    except Exception as e:
        return {"requested": True, "status": "unavailable", "model": model, "text": None,
                "error": f"Ollama not reachable or model missing ({type(e).__name__}). Graph analysis was still completed."}
@app.post("/agent/investigate")
def investigate(req: InvestigationRequest):
    identity = req.identity.strip()
    if not identity:
        raise HTTPException(400, detail="identity is required")
    try:
        findings = run_investigation(identity)
        if findings is None:
            raise HTTPException(404, detail=f"Identity '{identity}' is not in the graph. Add it first, or pick an existing identity.")

        findings["answer"] = deterministic_answer(findings)
        comparison = compare(identity, findings)      # compare BEFORE saving this run
        llm = ollama_summary(findings) if req.use_llm else {"requested": False, "status": "off", "text": None}
        record = save_investigation(identity, findings)
        return {
            "identity": identity,
            "mode": "llm_summary" if llm["status"] == "ok" else "graph_tool_pipeline",
            "answer": findings["answer"],
            "llm": llm,
            "risk_level": findings["risk_level"],
            "steps": findings["steps"],
            "findings": findings,
            "comparison": comparison,
            "investigation_id": record["id"],
            "created_at": record["created_at"],
            "caution": "Synthetic demo data only. Graph reachability is not proof of compromise; validate against authoritative logs.",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.get("/memory")
def memory_all():
    try:
        items = list_memory()
        return {"count": len(items), "investigations": items}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.delete("/memory")
def memory_clear(identity: Optional[str] = None):
    try:
        clear_memory(identity)
        return {"status": "cleared", "identity": identity}
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    
@app.get("/memory/asset/{asset}")
def memory_asset(asset: str):
    try:
        rows = who_found_paths_to(asset)
        return {"asset": asset, "count": len(rows), "investigations": rows}
    except Exception as e:
        raise HTTPException(500, detail=str(e))

@app.get("/memory/{identity}")
def memory(identity: str):
    try:
        items = list_memory(identity)
        return {"identity": identity, "count": len(items), "investigations": items}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.post("/memory/compare")
def memory_compare(body: dict):
    identity = body.get("identity", "elena.rostova")
    current = body.get("current_findings") or body.get("findings") or {}
    try:
        return compare(identity, current)
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.post("/graph/simulate")
def simulate(req: SimulateRequest):
    """Blast-radius what-if for one asset: what it can reach, and what depends on it."""
    try:
        result = simulate_impact(req.node.strip(), req.depth)
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    if result is None:
        raise HTTPException(404, detail=f"'{req.node}' is not an asset in the graph.")
    return {"status": "success", "data": result}


@app.post("/graph/identity")
def add_identity(body: NewIdentity):
    """Explicitly add an identity (no access links yet). Investigations never create identities on their own."""
    name = body.name.strip()
    if not re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", name):
        raise HTTPException(400, detail="Identity name: 1-64 characters, letters/digits and . _ @ - only.")
    try:
        if query("MATCH (i:Identity {name:$name}) RETURN i.name AS name", {"name": name}):
            raise HTTPException(409, detail=f"Identity '{name}' already exists.")
        query("CREATE (:Identity {name:$name, role:$role, status:'normal', source:'analyst-added'})",
              {"name": name, "role": body.role.strip()[:64] or "unspecified"})
        return {"status": "created", "identity": name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=str(e))

class ContainRequest(BaseModel):
    investigation_id: Optional[str] = None
    edges: list[Link]


@app.post("/graph/contain")
def contain(req: ContainRequest):
    """Apply a containment cut: remove the relationships and record each one as an Action in the graph."""
    if not req.edges:
        raise HTTPException(400, detail="No relationships to cut.")
    for link in req.edges:
        _check_link(link)
    found = []
    for link in req.edges:  # verify everything exists before changing anything
        rows = query(f"MATCH (a {{name:$a}})-[r:{link.type}]->(b {{name:$b}}) RETURN r.source AS source",
                     {"a": link.source, "b": link.target})
        if not rows:
            raise HTTPException(404, detail=f"{link.source} {link.type} {link.target} does not exist (already cut?).")
        found.append((link, rows[0]["source"]))
    try:
        actions = []
        for link, src in found:
            query(f"MATCH (a {{name:$a}})-[r:{link.type}]->(b {{name:$b}}) DELETE r", {"a": link.source, "b": link.target})
            actions.append(record_action(link, src, req.investigation_id))
        return {"status": "applied", "actions": actions}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.get("/actions")
def actions_all():
    try:
        items = list_actions()
        return {"count": len(items), "actions": items}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@app.post("/actions/{action_id}/undo")
def actions_undo(action_id: str):
    try:
        result = undo_action(action_id)
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    if result is None:
        raise HTTPException(404, detail="Unknown action.")
    if "error" in result:
        msg = {"already_undone": "That action was already undone.", "bad_type": "Unsupported relationship type.",
               "endpoints_missing": "The assets or identity no longer exist, so the link cannot be restored."}[result["error"]]
        raise HTTPException(409, detail=msg)
    return result

RISK_RANK = {"high": 2, "medium": 1, "low": 0}


@app.post("/agent/triage")
def triage():
    """Read-only scan of every identity, ranked by risk. Saves nothing."""
    try:
        rows = []
        for r in query("MATCH (i:Identity) RETURN i.name AS name"):
            f = run_investigation(r["name"])
            if f is None:
                continue
            c = f.get("containment")
            proposal = [{k: o[k] for k in ("from", "relationship", "to", "kind", "paths_removed", "paths_total")}
                        for o in (c["recommended"] if c else [])]
            rows.append({"identity": r["name"], "role": f["role"], "risk_level": f["risk_level"],
                         "paths": len(f["paths"]), "alerts": len(f["alerts"]), "proposal": proposal})
        rows.sort(key=lambda x: (-RISK_RANK.get(x["risk_level"], 0), -x["paths"], x["identity"]))
        return {"count": len(rows), "items": rows}
    except Exception as e:
        raise HTTPException(500, detail=str(e))