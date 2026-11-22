"""The wallet side of the committed (Merkle, per-leaf salted) form of an Intent Map: maps an Intent Map onto the leaf layout
of intent_map.commit_map. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .intent_map import commit_map
from .pca import hash_canonical, _is_safe_int


def _num_cell_count(lo: Any, hi: Any, cuts: List[Any]) -> int:
    n = 0
    cur = lo
    for c in cuts:
        if c < lo or c > hi:
            continue
        if cur <= c - 1:
            n += 1
        n += 1
        cur = c + 1
    return n + 1 if cur <= hi else n


def commit_intent_map(m: dict, secret: bytes) -> Dict[str, Any]:
    """Commit an Intent Map; `secret` (32 random bytes kept per session) derives every leaf salt."""
    headers = []
    for v in m["omega"]["verbs"]:
        dims = []
        for d in v["dims"]:
            if d["kind"] == "num":
                dims.append({"kind": "num", "path": d["path"], "lo": d["lo"], "hi": d["hi"], "cuts": [c for c in (d.get("cuts") or []) if d["lo"] <= c <= d["hi"]]})
            else:
                dims.append({"kind": "cat", "path": d["path"], "values": [{"kind": x["kind"], "value": x["value"]} for x in (d.get("values") or [])]})
        headers.append({"verb": v["verb"], "dims": dims})
    cells: Dict[str, List[dict]] = {}
    for v in m["omega"]["verbs"]:
        counts = [_num_cell_count(d["lo"], d["hi"], d.get("cuts") or []) if d["kind"] == "num" else len(d.get("values") or []) for d in v["dims"]]
        total = 1
        for c in counts:
            total *= c
        slots: List[Optional[dict]] = [None] * total
        for c in m["cells"]:
            if c["verb"] != v["verb"]:
                continue
            if len(c["cell"]) != len(counts):
                raise ValueError("commitIntentMap: cell of %s has the wrong arity" % v["verb"])
            flat = 0
            for j, i in enumerate(c["cell"]):
                if not (_is_safe_int(i) and i >= 0 and i < counts[j]):
                    raise ValueError("commitIntentMap: cell index out of range for %s" % v["verb"])
                flat = flat * counts[j] + i
            slots[flat] = {"cell": list(c["cell"]), "p_ppm": c["p_ppm"], "in_grant": c["in_grant"]}
        if any(s is None for s in slots) or len(slots) != total:
            raise ValueError("commitIntentMap: the map does not list every cell of %s" % v["verb"])
        cells[v["verb"]] = slots  # type: ignore[assignment]
    metrics = {k: x for k, x in m["metrics"].items() if k != "log2_vs_mbits"}
    if m["metrics"].get("log2_vs_mbits") is not None:
        metrics["log2_vs_mbits"] = m["metrics"]["log2_vs_mbits"]
    return commit_map(headers, cells, metrics, hash_canonical(m["learner"]), secret)
