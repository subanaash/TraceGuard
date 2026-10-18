"""Integration tests. They need a running FalkorDB (docker compose up -d falkordb).
They use their own graph name so your demo data is never touched."""
import os
os.environ["GRAPH_NAME"] = "traceguard_test"

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.graph import query

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh():
    client.delete("/memory")
    query("MATCH (a:Action) DETACH DELETE a")
    assert client.post("/demo/seed").status_code == 200
    yield


def test_root_and_health():
    assert client.get("/").json()["name"] == "TraceGuard API"
    assert client.get("/health").json()["status"] == "ok"


def test_graph_data_has_nodes_and_edges():
    d = client.get("/graph/data").json()
    assert d["node_count"] >= 10 and d["edge_count"] >= 10
    ids = {n["id"] for n in d["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in d["edges"])


def test_elena_is_high_risk_with_paths_and_scoped_evidence():
    j = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    assert j["risk_level"] == "high"
    assert "elena.rostova → web-prod-01 → billing-api → customer-db" in j["findings"]["paths"]
    ev = {e["id"] for e in j["findings"]["evidence"]}
    assert "EVID-001" in ev and "EVID-004" not in ev   # sarah's evidence must not leak in


def test_low_risk_identity_has_no_paths():
    j = client.post("/agent/investigate", json={"identity": "sarah.chen"}).json()
    assert j["risk_level"] == "low" and j["findings"]["paths"] == []


def test_unknown_identity_404():
    assert client.post("/agent/investigate", json={"identity": "nobody"}).status_code == 404


def test_first_run_has_no_previous_then_drift_is_detected():
    first = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    assert first["comparison"]["has_previous"] is False
    again = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    assert again["comparison"]["has_previous"] is True and again["comparison"]["new_paths"] == []
    # change the graph: give elena's server a new route to the database
    assert client.post("/graph/connect", json={"source": "web-prod-01", "target": "customer-db", "type": "CONNECTS_TO"}).status_code == 200
    changed = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    assert "elena.rostova → web-prod-01 → customer-db" in changed["comparison"]["new_paths"]


def test_reseed_keeps_memory():
    client.post("/agent/investigate", json={"identity": "elena.rostova"})
    client.post("/demo/seed")
    assert client.get("/memory/elena.rostova").json()["count"] == 1


def test_connect_validation():
    bad = client.post("/graph/connect", json={"source": "elena.rostova", "target": "customer-db", "type": "CONNECTS_TO"})
    assert bad.status_code == 400
    assert client.post("/graph/disconnect", json={"source": "web-prod-01", "target": "customer-db", "type": "CONNECTS_TO"}).status_code == 404


def test_llm_failure_keeps_graph_answer(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:9")
    j = client.post("/agent/investigate", json={"identity": "elena.rostova", "use_llm": True}).json()
    assert j["llm"]["status"] == "unavailable" and "elena.rostova" in j["answer"]


def test_investigating_does_not_create_identities():
    assert client.post("/agent/investigate", json={"identity": "typo.name"}).status_code == 404
    assert "typo.name" not in {i["name"] for i in client.get("/identities").json()["identities"]}


def test_add_identity_then_low_means_unknown():
    assert client.post("/graph/identity", json={"name": "new.hire"}).status_code == 200
    assert client.post("/graph/identity", json={"name": "new.hire"}).status_code == 409
    assert client.post("/graph/identity", json={"name": "bad name!"}).status_code == 400
    j = client.post("/agent/investigate", json={"identity": "new.hire"}).json()
    assert j["risk_level"] == "low" and "unknown" in j["findings"]["risk_reason"]


def test_simulate_impact_follows_edges_both_ways():
    d = client.post("/graph/simulate", json={"node": "web-prod-01", "depth": 3}).json()["data"]
    assert {"billing-api", "backup-store", "customer-db"} <= set(d["impacted"])
    d = client.post("/graph/simulate", json={"node": "customer-db"}).json()["data"]
    assert d["reachable"] == [] and [a["asset"] for a in d["dependents"]] == ["billing-api"]
    assert client.post("/graph/simulate", json={"node": "elena.rostova"}).status_code == 404


def test_health_reports_measured_db_latency():
    assert client.get("/health").json()["db_ms"] >= 0

def test_containment_cut_removes_paths_and_records_drift():
    first = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    c = first["findings"]["containment"]
    assert c["paths_total"] == 4 and c["recommended"]
    for o in c["recommended"]:
        r = client.post("/graph/disconnect", json={"source": o["from"], "target": o["to"], "type": o["relationship"]})
        assert r.status_code == 200
    after = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    assert after["findings"]["paths"] == [] and after["findings"]["containment"] is None
    assert len(after["comparison"]["removed_paths"]) == 4
    assert after["comparison"]["risk_changed"] and after["comparison"]["previous_risk"] == "high"



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
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "elena.rostova reached payroll-db after ALERT-9999."}

    monkeypatch.setattr(httpx, "post", lambda *a, **k: R())
    j = client.post("/agent/investigate", json={"identity": "elena.rostova", "use_llm": True}).json()
    assert j["llm"]["status"] == "unavailable" and "payroll-db" in j["llm"]["error"]
    assert "elena.rostova" in j["answer"]    



def test_contain_records_actions_and_undo_restores_the_path():
    first = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    rec = first["findings"]["containment"]["recommended"]
    edges = [{"source": o["from"], "target": o["to"], "type": o["relationship"]} for o in rec]
    r = client.post("/graph/contain", json={"investigation_id": first["investigation_id"], "edges": edges})
    assert r.status_code == 200 and len(r.json()["actions"]) == len(edges)
    after = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    assert after["findings"]["paths"] == []
    log = client.get("/actions").json()["actions"]
    assert log[0]["status"] == "applied" and log[0]["investigation_id"] == first["investigation_id"]
    assert log[0]["edge_source"] == "synthetic-iam-export"
    assert "Action" not in {n["type"] for n in client.get("/graph/data").json()["nodes"]}
    # cutting again fails cleanly, then undo brings the paths back with their original source
    assert client.post("/graph/contain", json={"edges": edges}).status_code == 404
    assert client.post(f"/actions/{log[0]['id']}/undo").status_code == 200
    assert client.post(f"/actions/{log[0]['id']}/undo").status_code == 409
    back = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    assert len(back["findings"]["paths"]) == 4
    assert client.get("/actions").json()["actions"][0]["status"] == "undone"


def test_reseed_keeps_the_audit_trail():
    first = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    o = first["findings"]["containment"]["recommended"][0]
    client.post("/graph/contain", json={"investigation_id": first["investigation_id"],
                                        "edges": [{"source": o["from"], "target": o["to"], "type": o["relationship"]}]})
    client.post("/demo/seed")
    assert client.get("/actions").json()["count"] == 1    



def test_clear_audit_trail():
    first = client.post("/agent/investigate", json={"identity": "elena.rostova"}).json()
    o = first["findings"]["containment"]["recommended"][0]
    client.post("/graph/contain", json={"investigation_id": first["investigation_id"],
                                        "edges": [{"source": o["from"], "target": o["to"], "type": o["relationship"]}]})
    assert client.get("/actions").json()["count"] == 1
    assert client.delete("/actions").status_code == 200
    assert client.get("/actions").json()["count"] == 0    



def test_triage_ranks_identities_without_saving():
    t = client.post("/agent/triage").json()
    top = t["items"][0]
    assert top["identity"] == "elena.rostova" and top["risk_level"] == "high" and top["proposal"]
    assert client.get("/memory").json()["investigations"] == []    