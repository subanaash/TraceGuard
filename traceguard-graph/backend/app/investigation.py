import time
from .graph import query
from .containment import recommend_containment
MAX_HOPS = 3


def _timed(steps, name, fn):
    start = time.perf_counter()
    result = fn()
    count = len(result) if hasattr(result, "__len__") else 1
    steps.append({"name": name, "duration_ms": round((time.perf_counter() - start) * 1000, 1), "count": count})
    return result


def find_attack_paths(identity):
    """Every route from the identity to a high-sensitivity asset, up to MAX_HOPS hops past the entry asset."""
    rows = query(
        f"""MATCH p=(i:Identity {{name:$name}})-[:HAS_ACCESS_TO]->(s:Asset)-[:CONNECTS_TO|DEPENDS_ON*0..{MAX_HOPS}]->(t:Asset {{sensitivity:'high'}})
            RETURN [x IN nodes(p) | x.name] AS names,
                   [r IN relationships(p) | type(r)] AS rels,
                   [r IN relationships(p) | r.source] AS sources""",
        {"name": identity},
    )
    paths = []
    for r in rows:
        names, rels, sources = r["names"], r["rels"], r["sources"]
        if len(set(names)) != len(names):  # skip loops
            continue
        provenance = [
            {"from": names[i], "relationship": rels[i], "to": names[i + 1], "source": sources[i] or "unknown"}
            for i in range(len(rels))
        ]
        paths.append({
            "nodes": names,
            "relationships": rels,
            "display": " → ".join(names),
            "hops": len(rels) - 1,
            "target": names[-1],
            "provenance": provenance,
        })
    paths.sort(key=lambda p: (p["hops"], p["display"]))
    return paths


def retrieve_alert_evidence(identity, asset_names):
    alerts = query(
        "MATCH (a:Alert)-[:INVOLVES]->(i:Identity {name:$name}) RETURN a.name AS id, a.severity AS severity, a.category AS category, a.source AS source",
        {"name": identity},
    )
    names = [identity] + [a["id"] for a in alerts] + list(asset_names)
    evidence = query(
        "MATCH (x)-[:SUPPORTED_BY]->(e:Evidence) WHERE x.name IN $names RETURN DISTINCT e.name AS id, e.description AS description, e.source AS source, x.name AS supports",
        {"names": names},
    )
    evidence.sort(key=lambda e: e["id"])
    return {"alerts": alerts, "evidence": evidence}


def calculate_blast_radius(identity):
    rows = query(
        f"""MATCH (i:Identity {{name:$name}})-[:HAS_ACCESS_TO]->(s:Asset)
            MATCH p=(s)-[:CONNECTS_TO|DEPENDS_ON*0..{MAX_HOPS}]->(a:Asset)
            RETURN a.name AS asset, a.kind AS kind, a.sensitivity AS sensitivity, min(length(p)) AS hops""",
        {"name": identity},
    )
    out = [{"asset": r["asset"], "kind": r["kind"], "sensitivity": r["sensitivity"],
            "risk": r["sensitivity"] or "low", "hops": r["hops"]} for r in rows]
    out.sort(key=lambda a: (a["hops"], a["asset"]))
    return out


def risk_level(paths, alerts):
    high_alert = any(a.get("severity") == "high" for a in alerts)
    if paths and high_alert:
        return "high", "A high-severity alert involves this identity and it can reach high-sensitivity assets."
    if paths:
        return "medium", "This identity can reach high-sensitivity assets, but no high-severity alert involves it."
    if high_alert:
        return "medium", "A high-severity alert involves this identity, but no path to a high-sensitivity asset was found."
    return "low", "No path to a high-sensitivity asset and no high-severity alert."


def run_investigation(identity):
    """Returns findings, or None if the identity is not in the graph."""
    found = query("MATCH (i:Identity {name:$name}) RETURN i.role AS role, i.status AS status", {"name": identity})
    if not found:
        return None
    steps = []
    paths = _timed(steps, "find_attack_paths", lambda: find_attack_paths(identity))
    blast = _timed(steps, "calculate_blast_radius", lambda: calculate_blast_radius(identity))
    asset_names = [b["asset"] for b in blast]
    ev = _timed(steps, "retrieve_alert_evidence", lambda: retrieve_alert_evidence(identity, asset_names))
    level, reason = risk_level(paths, ev["alerts"])
    if not blast:
        reason += " No access relationships are recorded for this identity, so 'low' means 'unknown', not 'safe'."
    return {
        "identity": identity,
        "role": found[0]["role"],
        "status": found[0]["status"],
        "risk_level": level,
        "risk_reason": reason,
        "paths": [p["display"] for p in paths],
        "path_details": paths,
        "assets": sorted(asset_names),
        "blast_radius": blast,
        "alerts": ev["alerts"],
        "evidence": ev["evidence"],
        "steps": steps,
        "containment": recommend_containment(paths),
    }


def deterministic_answer(f):
    n_paths, n_alerts, n_assets = len(f["paths"]), len(f["alerts"]), len(f["assets"])
    high = [b["asset"] for b in f["blast_radius"] if b["risk"] == "high"]
    text = (f"{f['identity']} ({f['role'] or 'unknown role'}) is rated {f['risk_level']} risk. "
            f"The graph shows {n_paths} path(s) to high-sensitivity assets, {n_alerts} related alert(s), "
            f"and {n_assets} reachable asset(s).")
    if high:
        text += " High-sensitivity assets in reach: " + ", ".join(high) + "."
    text += " These are graph relationships in synthetic data, not proof of compromise."
    return text


def simulate_impact(name, depth=MAX_HOPS):
    """What a compromised or failed asset touches. Returns None if `name` is not an asset.

    reachable  = assets it can reach going forward along CONNECTS_TO / DEPENDS_ON (compromise spread)
    dependents = assets that DEPEND_ON it, directly or indirectly (outage spread)
    """
    depth = max(1, min(int(depth), 5))
    if not query("MATCH (n:Asset {name:$n}) RETURN n.name AS name", {"n": name}):
        return None
    reach = query(
        f"""MATCH p=(s:Asset {{name:$n}})-[:CONNECTS_TO|DEPENDS_ON*1..{depth}]->(a:Asset)
            WHERE a.name <> $n
            RETURN a.name AS asset, a.kind AS kind, a.sensitivity AS sensitivity, min(length(p)) AS hops""",
        {"n": name},
    )
    dependents = query(
        f"""MATCH p=(a:Asset)-[:DEPENDS_ON*1..{depth}]->(s:Asset {{name:$n}})
            WHERE a.name <> $n
            RETURN a.name AS asset, a.kind AS kind, a.sensitivity AS sensitivity, min(length(p)) AS hops""",
        {"n": name},
    )
    order = lambda a: (a["hops"], a["asset"])
    reach.sort(key=order)
    dependents.sort(key=order)
    impacted = sorted({a["asset"] for a in reach} | {a["asset"] for a in dependents})
    return {"target": name, "depth": depth, "reachable": reach, "dependents": dependents, "impacted": impacted}


def test_memory_is_linked_in_the_graph_and_survives_reseed():
    client.post("/agent/investigate", json={"identity": "elena.rostova"})
    r = client.get("/memory/asset/customer-db").json()
    assert r["count"] == 1 and r["investigations"][0]["identity"] == "elena.rostova"
    client.post("/demo/seed")
    assert client.get("/memory/asset/customer-db").json()["count"] == 1
    assert client.get("/memory/asset/staging-db").json()["count"] == 0


def test_ungrounded_llm_summary_is_rejected(monkeypatch):
    import httpx
    class R:
        def raise_for_status(self): pass
        def json(self): return {"response": "elena.rostova reached payroll-db after ALERT-9999."}
    monkeypatch.setattr(httpx, "post", lambda *a, **k: R())
    j = client.post("/agent/investigate", json={"identity": "elena.rostova", "use_llm": True}).json()
    assert j["llm"]["status"] == "unavailable" and "payroll-db" in j["llm"]["error"]
    assert "elena.rostova" in j["answer"]