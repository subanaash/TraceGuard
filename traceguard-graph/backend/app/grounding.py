import re

# Words that appear inside ordinary hyphenated English and are not graph names.
_PLAIN = {"high", "low", "medium", "severity", "sensitivity", "multi", "hop", "hops", "path", "paths", "non",
          "production", "graph", "based", "read", "only", "well", "known", "cross", "run", "first", "third"}
_TOKEN = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:[-.][A-Za-z0-9]+)+\b")


def known_terms(findings):
    """Every name the findings actually contain."""
    names = {findings.get("identity", "")}
    names.update(findings.get("assets", []))
    names.update(a.get("asset") for a in findings.get("blast_radius", []))
    names.update(a.get("id") for a in findings.get("alerts", []))
    names.update(e.get("id") for e in findings.get("evidence", []))
    for p in findings.get("path_details", []):
        names.update(p.get("nodes", []))
    return {n.lower() for n in names if n}


def ungrounded_terms(text, findings):
    """Graph-name-like terms in `text` that are not in the findings. Heuristic, not a proof of correctness."""
    known = known_terms(findings)
    bad = []
    for tok in _TOKEN.findall(text or ""):
        t = tok.lower().rstrip(".")
        if t in known:
            continue
        if all(seg in _PLAIN for seg in re.split(r"[-.]", t)):
            continue
        if t not in bad:
            bad.append(t)
    return bad