from .graph import query

# All data below is synthetic.
NODES = [
    # identities
    "CREATE (:Identity {name:'elena.rostova', role:'contractor', status:'suspicious', source:'synthetic-iam-export'})",
    "CREATE (:Identity {name:'sarah.chen', role:'support engineer', status:'normal', source:'synthetic-iam-export'})",
    "CREATE (:Identity {name:'svc-backup-runner', role:'service account', status:'normal', source:'synthetic-iam-export'})",
    # assets
    "CREATE (:Asset {name:'web-prod-01', kind:'server', sensitivity:'medium', source:'synthetic-cmdb'})",
    "CREATE (:Asset {name:'billing-api', kind:'application', sensitivity:'high', source:'synthetic-service-catalog'})",
    "CREATE (:Asset {name:'customer-db', kind:'database', sensitivity:'high', source:'synthetic-cmdb'})",
    "CREATE (:Asset {name:'backup-store', kind:'storage', sensitivity:'high', source:'synthetic-cmdb'})",
    "CREATE (:Asset {name:'staging-web-01', kind:'server', sensitivity:'low', source:'synthetic-cmdb'})",
    "CREATE (:Asset {name:'staging-db', kind:'database', sensitivity:'low', source:'synthetic-cmdb'})",
    "CREATE (:Asset {name:'reporting-api', kind:'application', sensitivity:'medium', source:'synthetic-service-catalog'})",
    "CREATE (:Asset {name:'auth-gateway', kind:'application', sensitivity:'medium', source:'synthetic-service-catalog'})",
    # alerts and evidence
    "CREATE (:Alert {name:'ALERT-1042', severity:'high', category:'unusual-login', source:'synthetic-siem'})",
    "CREATE (:Alert {name:'ALERT-1077', severity:'low', category:'failed-login-burst', source:'synthetic-siem'})",
    "CREATE (:Evidence {name:'EVID-001', description:'Login from an unusual simulated location', source:'synthetic-siem'})",
    "CREATE (:Evidence {name:'EVID-002', description:'Identity has access to production server', source:'synthetic-iam-export'})",
    "CREATE (:Evidence {name:'EVID-003', description:'Billing API depends on customer database', source:'synthetic-service-catalog'})",
    "CREATE (:Evidence {name:'EVID-004', description:'Five failed logins followed by a normal login', source:'synthetic-siem'})",
]

EDGES = [
    ("Identity", "elena.rostova", "HAS_ACCESS_TO", "Asset", "web-prod-01", "synthetic-iam-export"),
    ("Identity", "sarah.chen", "HAS_ACCESS_TO", "Asset", "staging-web-01", "synthetic-iam-export"),
    ("Identity", "svc-backup-runner", "HAS_ACCESS_TO", "Asset", "backup-store", "synthetic-iam-export"),
    ("Asset", "web-prod-01", "CONNECTS_TO", "Asset", "billing-api", "synthetic-network-map"),
    ("Asset", "web-prod-01", "CONNECTS_TO", "Asset", "backup-store", "synthetic-network-map"),
    ("Asset", "web-prod-01", "CONNECTS_TO", "Asset", "auth-gateway", "synthetic-network-map"),
    ("Asset", "auth-gateway", "CONNECTS_TO", "Asset", "customer-db", "synthetic-network-map"),
    ("Asset", "billing-api", "DEPENDS_ON", "Asset", "customer-db", "synthetic-service-catalog"),
    ("Asset", "staging-web-01", "CONNECTS_TO", "Asset", "staging-db", "synthetic-network-map"),
    ("Asset", "staging-web-01", "CONNECTS_TO", "Asset", "reporting-api", "synthetic-network-map"),
    ("Alert", "ALERT-1042", "INVOLVES", "Identity", "elena.rostova", "synthetic-siem"),
    ("Alert", "ALERT-1077", "INVOLVES", "Identity", "sarah.chen", "synthetic-siem"),
    ("Alert", "ALERT-1042", "SUPPORTED_BY", "Evidence", "EVID-001", "synthetic-siem"),
    ("Alert", "ALERT-1077", "SUPPORTED_BY", "Evidence", "EVID-004", "synthetic-siem"),
    ("Identity", "elena.rostova", "SUPPORTED_BY", "Evidence", "EVID-002", "synthetic-iam-export"),
    ("Asset", "billing-api", "SUPPORTED_BY", "Evidence", "EVID-003", "synthetic-service-catalog"),
]


def seed_graph():
    """Reset the demo graph. Saved investigations (memory) are kept on purpose."""
    query("MATCH (n) WHERE NOT n:Investigation AND NOT n:Action DETACH DELETE n")
    for statement in NODES:
        query(statement)
    for la, a, rel, lb, b, src in EDGES:
        query(
            f"MATCH (x:{la} {{name:$a}}), (y:{lb} {{name:$b}}) CREATE (x)-[:{rel} {{source:$src}}]->(y)",
            {"a": a, "b": b, "src": src},
        )
        from .memory import link_memory
        link_memory()    
    return {"status": "seeded", "synthetic_demo_data": True}


def graph_is_empty():
    rows = query("MATCH (i:Identity) RETURN count(i) AS c")
    return not rows or rows[0]["c"] == 0