"""Outcome-space dimensions filled by the verifier: world facts (env.world.*), provenance (env.prov.*) and attested
classifier labels (env.class.*). Every helper only adds a dimension, which refines the space. Native port of the
TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

import functools
from typing import Any, Dict, List, Optional

from .intent_omega import OTHER, is_number, u16key
from .intent_v2 import compare_utf8

WORLD_PREFIX = "env.world."
PROV_PREFIX = "env.prov."
CLASS_PREFIX = "env.class."


def world_dim(name: str, o: dict) -> dict:
    """A numeric world dimension env.world.<name> with the given domain and cuts."""
    cuts: List[Any] = []
    for c in (o.get("cuts") or []):
        if c not in cuts:
            cuts.append(c)
    cuts = sorted(c for c in cuts if o["lo"] <= c <= o["hi"])
    dist = o.get("dist")
    return {"kind": "num", "path": WORLD_PREFIX + name, "lo": o["lo"], "hi": o["hi"], "cuts": cuts, "dist": "uniform" if dist is None else dist}


def excess_dim(name: str, hi: Any, slacks: Optional[List[Any]] = None) -> dict:
    """The optimality dimension: excess >= 0, cuts at 0 and at every slack literal."""
    return world_dim(name, {"lo": 0, "hi": hi, "cuts": [0] + list(slacks or []), "dist": "loguniform"})


def optimality_condition(name: str, slack: Any = 0) -> dict:
    """The default slot compiler's optimality constraint: excess <= slack."""
    return {"field": WORLD_PREFIX + name, "op": "lte", "value": slack}


def provenance_dim(param_path: str) -> dict:
    """env.prov.<path> with the cells {first_party}, {trusted} and the OTHER cell = the tainted values."""
    return {"kind": "cat", "path": PROV_PREFIX + param_path,
            "values": [{"kind": "exact", "value": "first_party"}, {"kind": "exact", "value": "trusted"}, {"kind": "other", "value": OTHER}]}


def classifier_dim(id_: str, labels: List[str]) -> dict:
    """env.class.<id> over the classifier's closed label set (the OTHER cell is never output)."""
    uniq = list(dict.fromkeys(labels))
    uniq.sort(key=functools.cmp_to_key(compare_utf8))
    return {"kind": "cat", "path": CLASS_PREFIX + id_, "values": [{"kind": "exact", "value": v} for v in uniq] + [{"kind": "other", "value": OTHER}]}


def with_dims(omega: dict, verb: str, dims: List[dict]) -> dict:
    """A copy of the space with dims added to verb (dimensions kept sorted by path)."""
    verbs = []
    for vs in omega["verbs"]:
        if vs["verb"] != verb:
            verbs.append({**vs, "dims": list(vs["dims"])})
            continue
        have = {d["path"] for d in vs["dims"]}
        for d in dims:
            if d["path"] in have:
                raise ValueError("withDims: %s already has a dimension %s" % (verb, d["path"]))
        verbs.append({**vs, "dims": sorted(list(vs["dims"]) + list(dims), key=lambda d: u16key(d["path"]))})
    if not any(v["verb"] == verb for v in verbs):
        raise ValueError("withDims: no verb %s in Ω" % verb)
    return {**omega, "verbs": verbs}


_MISSING = object()


def _get(root: Any, segs: List[str]) -> Any:
    cur = root
    for s in segs:
        if isinstance(cur, dict) and s in cur:
            cur = cur[s]
        elif isinstance(cur, list) and s.isascii() and s.isdigit() and str(int(s)) == s and int(s) < len(cur):
            cur = cur[int(s)]
        else:
            return _MISSING
    return cur


def lift_outcome(o: dict, env: dict, dim_paths: List[str]) -> dict:
    """Lift a concrete outcome with the verifier-computed env: fill every world / prov / class dimension path from it. A
    provenance dimension with no computed label is `agent` (fail closed: the tainted cell)."""
    values = dict(o["values"])
    world, prov, cls = env.get("world"), env.get("prov"), env.get("class")
    for p in dim_paths:
        if p.startswith(WORLD_PREFIX):
            v = _get(world, [p[len(WORLD_PREFIX):]])
            if is_number(v) or isinstance(v, str):
                values[p] = v
        elif p.startswith(PROV_PREFIX):
            v = _get(prov, p[len(PROV_PREFIX):].split("."))
            values[p] = v if isinstance(v, str) else "agent"
        elif p.startswith(CLASS_PREFIX):
            v = _get(cls, [p[len(CLASS_PREFIX):]])
            if isinstance(v, str):
                values[p] = v
    return {"verb": o["verb"], "values": values}
