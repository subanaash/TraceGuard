import json, uuid
from datetime import datetime, timezone
from .graph import query


def save_investigation(identity, findings):
    record = {
        "id": str(uuid.uuid4()),
        "identity": identity,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }
    targets = sorted({p["target"] for p in findings.get("path_details", [])})
    query(
        "CREATE (m:Investigation {id:$id, identity:$identity, created_at:$created_at, findings_json:$findings_json, targets:$targets})",
        {"id": record["id"], "identity": identity, "created_at": record["created_at"],
         "findings_json": json.dumps(findings), "targets": targets},
    )
    link_memory()
    return record


def _rows_to_items(rows):
    items = []
    for r in rows:
        try:
            findings = json.loads(r.get("findings_json") or "{}")
        except Exception:
            findings = {}
        items.append({"id": r.get("id"), "identity": r.get("identity"), "created_at": r.get("created_at"), "findings": findings})
    return items


def list_memory(identity=None):
    if identity:
        rows = query(
            "MATCH (m:Investigation {identity:$identity}) RETURN m.id AS id, m.identity AS identity, m.created_at AS created_at, m.findings_json AS findings_json ORDER BY m.created_at DESC",
            {"identity": identity},
        )
    else:
        rows = query(
            "MATCH (m:Investigation) RETURN m.id AS id, m.identity AS identity, m.created_at AS created_at, m.findings_json AS findings_json ORDER BY m.created_at DESC"
        )
    return _rows_to_items(rows)


def clear_memory(identity=None):
    if identity:
        query("MATCH (m:Investigation {identity:$identity}) DELETE m", {"identity": identity})
    else:
        query("MATCH (m:Investigation) DELETE m")


def compare(identity, current, previous=None):
    """Compare current findings with the latest saved run (call this BEFORE saving the current run)."""
    previous = list_memory(identity) if previous is None else previous
    baseline = previous[0] if previous else None
    old = (baseline or {}).get("findings", {})
    ca, oa = set(current.get("assets", [])), set(old.get("assets", []))
    cp, op = set(current.get("paths", [])), set(old.get("paths", []))
    return {
        "has_previous": bool(baseline),
        "baseline_id": (baseline or {}).get("id"),
        "baseline_time": (baseline or {}).get("created_at"),
        "new_assets": sorted(ca - oa),
        "removed_assets": sorted(oa - ca),
        "new_paths": sorted(cp - op),
        "removed_paths": sorted(op - cp),
        "previous_count": len(previous),
        "previous_risk": old.get("risk_level"),
        "risk_changed": bool(baseline) and old.get("risk_level") != current.get("risk_level"),
    }

def link_memory():
    """Connect every saved investigation to what it examined and what it found. Safe to run repeatedly."""
    query("MATCH (m:Investigation), (i:Identity {name: m.identity}) MERGE (m)-[:EXAMINED]->(i)")
    query("MATCH (m:Investigation) UNWIND m.targets AS t MATCH (a:Asset {name: t}) MERGE (m)-[:FOUND_PATH]->(a)")

def who_found_paths_to(asset):
    """Graph-native recall: which saved investigations found a path to this asset?"""
    return query(
        "MATCH (m:Investigation)-[:FOUND_PATH]->(a:Asset {name:$a}) RETURN m.identity AS identity, m.created_at AS created_at, m.id AS id ORDER BY m.created_at DESC",
        {"a": asset},
    )    