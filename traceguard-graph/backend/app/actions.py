import uuid
from datetime import datetime, timezone
from .graph import query

REL_TYPES = {"CONNECTS_TO", "DEPENDS_ON", "HAS_ACCESS_TO"}


def record_action(link, edge_source, investigation_id=None):
    """Write one applied containment cut to the graph as an Action node, linked to the investigation that proposed it."""
    action = {
        "id": str(uuid.uuid4()),
        "kind": "cut",
        "from": link.source, "relationship": link.type, "to": link.target,
        "edge_source": edge_source,
        "investigation_id": investigation_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "applied",
    }
    query(
        "CREATE (:Action {id:$id, kind:$kind, from_name:$f, relationship:$r, to_name:$t, edge_source:$es, "
        "investigation_id:$inv, created_at:$ts, status:$status})",
        {"id": action["id"], "kind": action["kind"], "f": link.source, "r": link.type, "t": link.target,
         "es": edge_source, "inv": investigation_id or "", "ts": action["created_at"], "status": "applied"},
    )
    if investigation_id:
        query("MATCH (m:Investigation {id:$inv}), (a:Action {id:$id}) MERGE (m)-[:RECOMMENDED]->(a)",
              {"inv": investigation_id, "id": action["id"]})
    return action


def list_actions():
    rows = query(
        "MATCH (a:Action) RETURN a.id AS id, a.kind AS kind, a.from_name AS from_name, a.relationship AS relationship, "
        "a.to_name AS to_name, a.edge_source AS edge_source, a.investigation_id AS investigation_id, "
        "a.created_at AS created_at, a.status AS status, a.undone_at AS undone_at ORDER BY a.created_at DESC"
    )
    return [{"id": r["id"], "kind": r["kind"], "from": r["from_name"], "relationship": r["relationship"],
             "to": r["to_name"], "edge_source": r["edge_source"], "investigation_id": r["investigation_id"] or None,
             "created_at": r["created_at"], "status": r["status"], "undone_at": r["undone_at"]} for r in rows]


def undo_action(action_id):
    """Restore the removed relationship with its original source. Returns the action, or None if unknown."""
    rows = query(
        "MATCH (a:Action {id:$id}) RETURN a.from_name AS f, a.relationship AS r, a.to_name AS t, "
        "a.edge_source AS es, a.status AS status",
        {"id": action_id},
    )
    if not rows:
        return None
    a = rows[0]
    if a["status"] != "applied":
        return {"error": "already_undone"}
    if a["r"] not in REL_TYPES:
        return {"error": "bad_type"}
    made = query(
        f"MATCH (x {{name:$f}}), (y {{name:$t}}) WHERE (x:Asset OR x:Identity) AND y:Asset "
        f"MERGE (x)-[e:{a['r']}]->(y) ON CREATE SET e.source=$es RETURN count(e) AS n",
        {"f": a["f"], "t": a["t"], "es": a["es"]},
    )
    if not made or not made[0]["n"]:
        return {"error": "endpoints_missing"}
    query("MATCH (a:Action {id:$id}) SET a.status='undone', a.undone_at=$ts",
          {"id": action_id, "ts": datetime.now(timezone.utc).isoformat()})
    return {"id": action_id, "status": "undone", "from": a["f"], "relationship": a["r"], "to": a["t"]}
def clear_actions():
    query("MATCH (a:Action) DETACH DELETE a")