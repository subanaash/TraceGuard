from itertools import combinations

MAX_CUT = 4  # largest cut set searched exhaustively; beyond that we fall back to greedy


def _edges(path):
    return [(p["from"], p["relationship"], p["to"]) for p in path["provenance"]]


def _option(edge, info, total, displays):
    covered = sorted(info["paths"])
    return {
        "from": edge[0], "relationship": edge[1], "to": edge[2],
        "source": info["source"],
        "kind": "access" if edge[1] == "HAS_ACCESS_TO" else "network",
        "paths_removed": len(covered),
        "paths_total": total,
        "removes": [displays[i] for i in covered],
    }


def _smallest_cover(candidates, n_paths):
    """Smallest set of edges that hits every path; ties prefer fewer access grants, then name order."""
    universe = set(range(n_paths))
    edges = sorted(candidates)
    best = None
    for size in range(1, min(MAX_CUT, len(edges)) + 1):
        for combo in combinations(edges, size):
            covered = set().union(*(candidates[e]["paths"] for e in combo))
            if covered == universe:
                score = (sum(1 for e in combo if e[1] == "HAS_ACCESS_TO"), combo)
                if best is None or score < best[0]:
                    best = (score, combo)
        if best:
            return list(best[1])
    # greedy fallback
    left, chosen = set(universe), []
    while left and edges:
        e = max(edges, key=lambda x: (len(candidates[x]["paths"] & left), x))
        if not candidates[e]["paths"] & left:
            break
        chosen.append(e)
        left -= candidates[e]["paths"]
    return chosen


def recommend_containment(path_details):
    """Which relationships to cut so the identity can no longer reach a high-sensitivity asset.

    Works only from the already-found paths, so every suggestion traces back to a path and its source system.
    Returns None when there is nothing to contain.
    """
    if not path_details:
        return None
    displays = [p["display"] for p in path_details]
    cands = {}
    for i, p in enumerate(path_details):
        for pv in p["provenance"]:
            e = (pv["from"], pv["relationship"], pv["to"])
            c = cands.setdefault(e, {"paths": set(), "source": pv["source"]})
            c["paths"].add(i)
    total = len(path_details)
    options = [_option(e, c, total, displays) for e, c in cands.items()]
    options.sort(key=lambda o: (-o["paths_removed"], o["kind"] == "access", o["from"], o["to"]))

    def as_set(edges):
        return [_option(e, cands[e], total, displays) for e in edges]

    recommended = as_set(_smallest_cover(cands, total))
    network_cands = {e: c for e, c in cands.items() if e[1] != "HAS_ACCESS_TO"}
    network_only = as_set(_smallest_cover(network_cands, total)) if network_cands else []
    if network_only:
        covered = set().union(*(network_cands[(o["from"], o["relationship"], o["to"])]["paths"] for o in network_only))
        if len(covered) != total:
            network_only = []
    return {
        "paths_total": total,
        "recommended": recommended,
        "network_only": network_only,
        "options": options,
        "note": "Cutting these relationships removes every path found. Revoking access is the broadest action; "
                "the network-only set keeps the account working but needs more cuts.",
    }