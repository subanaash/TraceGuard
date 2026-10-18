import os
import threading
from falkordb import FalkorDB

HOST = os.getenv("FALKORDB_HOST", "localhost")
PORT = int(os.getenv("FALKORDB_PORT", "6379"))
GRAPH_NAME = os.getenv("GRAPH_NAME", "traceguard")

_lock = threading.Lock()
_graph = None


def get_graph():
    """One shared connection, created on first use (not on every query)."""
    global _graph
    with _lock:
        if _graph is None:
            client = FalkorDB(host=HOST, port=PORT, socket_connect_timeout=3)
            _graph = client.select_graph(GRAPH_NAME)
        return _graph


def reset_connection():
    global _graph
    with _lock:
        _graph = None


def query(cypher, params=None):
    """Run a Cypher query and return rows as a list of dicts."""
    try:
        result = get_graph().query(cypher, params or {})
    except Exception:
        # connection may have dropped; try once more with a fresh one
        reset_connection()
        result = get_graph().query(cypher, params or {})
    headers = getattr(result, "header", []) or []
    rows = getattr(result, "result_set", []) or []
    names = [str(h[1] if isinstance(h, (list, tuple)) and len(h) > 1 else h) for h in headers]
    return [dict(zip(names, row)) for row in rows]
