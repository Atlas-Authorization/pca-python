"""Trajectory intent as ordinary intent: the augmented outcome space (one numeric dimension per accumulator, one
categorical dimension per monitor), the verifier-computed lift of an action, the trajectory step rule and the wallet's
default accumulators. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

import functools
import math
import re
from typing import Any, Callable, Dict, List, Optional

from .intent_history import acc_post, monitor_state
from .intent_omega import _at, cell_of, is_number, num_cells
from .intent_schema import canon_value
from .intent_v2 import _js_string, accumulation_params, compare_utf8, monitor_states

ACC_DIM_PREFIX = "env.acc."
MON_DIM_PREFIX = "env.mon."
_UTF8 = functools.cmp_to_key(compare_utf8)


def acc_dim_path(id_: str) -> str:
    return "%s%s.post" % (ACC_DIM_PREFIX, id_)


def mon_dim_path(id_: str) -> str:
    return "%s%s.state" % (MON_DIM_PREFIX, id_)


def dim_kind_of(path: str) -> str:
    """The v2 dimension kind of a path (a naming convention over the v1 dimensions)."""
    for prefix, kind in (("action.params.", "param"), (ACC_DIM_PREFIX, "acc"), (MON_DIM_PREFIX, "mon"), ("env.canon.", "canon"),
                         ("env.world.", "world"), ("env.rel.", "rel"), ("env.prov.", "prov"), ("env.class.", "class")):
        if path.startswith(prefix):
            return kind
    return "other"


def _pred_verbs(p: dict) -> List[str]:
    v = p["verb"]
    return list(v) if isinstance(v, list) else [v]


def augment_omega(omega: dict, psi: dict, opts: Optional[dict] = None) -> dict:
    """The augmented space from the space and Psi (wallet-held accumulators are not dimensions)."""
    opts = opts or {}
    schema = opts.get("schema")

    def selects(a: dict, verb: str) -> bool:
        if verb in ((a.get("sel") or {}).get("verbs") or []):
            return True
        unit = (a.get("sel") or {}).get("accumulates_into")
        if unit is not None:
            v = next((x for x in schema["verbs"] if x["verb"] == verb), None) if schema else None
            return bool(v) and len(accumulation_params(v, unit)) > 0
        return False

    verbs = []
    for vs in omega["verbs"]:
        extra: List[dict] = []
        for a in psi["accumulators"]:
            if a["holder"]["kind"] == "wallet":
                continue
            if opts.get("scope") == "selected" and not selects(a, vs["verb"]):
                continue
            if a.get("domain_max") is None:
                raise ValueError("augmentOmega: accumulator '%s' needs domain_max (A_psi) to be a dimension" % a["id"])
            dm = a["domain_max"]
            raw = (opts.get("cuts") or {}).get(a["id"]) or []
            cuts = sorted(set(c for c in raw if is_number(c) and float(c).is_integer() and 0 <= c <= dm and abs(c) <= 9007199254740991))
            extra.append({"kind": "num", "path": acc_dim_path(a["id"]), "lo": 0, "hi": dm, "cuts": cuts, "dist": "loguniform"})
        for m in psi["monitors"]:
            if opts.get("scope") == "selected" and not ((vs["verb"] in _pred_verbs(m["q"]) or "*" in _pred_verbs(m["q"])) if m.get("q") else True):
                continue
            extra.append({"kind": "cat", "path": mon_dim_path(m["id"]), "values": [{"kind": "exact", "value": v} for v in (monitor_states(m) or [])]})
        dims = [d for d in vs["dims"] if dim_kind_of(d["path"]) not in ("acc", "mon")] + extra
        dims.sort(key=lambda d: _UTF8(d["path"]))
        verbs.append({**vs, "dims": dims})
    return {"v": 1, "approximate": list(omega["approximate"]), "verbs": verbs}


def _own(d: Any, k: str) -> Any:
    return d[k] if isinstance(d, dict) and k in d else None


def lift_action(omega_tilde: dict, psi: dict, history: List[dict], cand: dict, schema: Any = None) -> Optional[dict]:
    """lift(history, action, t) as an outcome of the augmented space; None when the verb is not in it."""
    vs = next((v for v in omega_tilde["verbs"] if v["verb"] == cand["verb"]), None)
    if vs is None:
        return None
    decl = next((v for v in schema["verbs"] if v["verb"] == cand["verb"]), None) if schema else None
    values: Dict[str, Any] = {}
    params = cand["params"]
    for d in vs["dims"]:
        k = dim_kind_of(d["path"])
        if k == "param":
            x = _own(params, d["path"][len("action.params."):])
            if is_number(x) or isinstance(x, str):
                values[d["path"]] = x
        elif k == "canon":
            name = d["path"][len("env.canon."):]
            pd = ((decl or {}).get("params") or {}).get("action.params." + name)
            if pd and isinstance(params, dict) and name in params:
                values[d["path"]] = canon_value(pd, params[name])
        elif k == "acc":
            id_ = d["path"][len(ACC_DIM_PREFIX):-len(".post")]
            a = next((x for x in psi["accumulators"] if x["id"] == id_), None)
            if a:
                values[d["path"]] = acc_post(a, history, cand["verb"], cand["params"], cand["t"], schema)
        elif k == "mon":
            id_ = d["path"][len(MON_DIM_PREFIX):-len(".state")]
            m = next((x for x in psi["monitors"] if x["id"] == id_), None)
            if m:
                values[d["path"]] = monitor_state(m, history)
        elif d["path"] == "action.resource":
            values[d["path"]] = cand["resource"]
    return {"verb": cand["verb"], "values": values}


def lifted_cell(omega_tilde: dict, o: dict) -> Optional[dict]:
    """The per-dimension cell of the lift, or None when it lies outside the space (fail closed)."""
    vs = next((v for v in omega_tilde["verbs"] if v["verb"] == o["verb"]), None)
    if vs is None:
        return None
    cell = cell_of(vs, o)
    return {"vs": vs, "cell": cell} if cell is not None else None


def step_trajectory(omega_tilde: dict, psi: dict, history: List[dict], cand: dict, in_grant: Callable[[str, List[int]], bool],
                    schema: Any = None) -> dict:
    """Admit the action iff its lift lies in a cell the grant accepts; the history grows by a `reserved` event on admission."""
    lifted = lift_action(omega_tilde, psi, history, cand, schema)
    c = lifted_cell(omega_tilde, lifted) if lifted else None
    ok = c is not None and bool(in_grant(cand["verb"], c["cell"]))
    hist = list(history)
    if ok:
        hist.append({"id": cand["id"], "verb": cand["verb"], "resource": cand["resource"], "params": cand["params"], "t": cand["t"], "status": "reserved"})
    return {"admitted": ok, "history": hist, "lifted": lifted}


def _sanitize(u: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", u)[:58]


def default_accumulators(schema: dict, o: dict) -> List[dict]:
    """The accumulators the wallet always adds: a per-task spend sum per accumulation unit, a per-verb spend sum for every
    untagged money.amount parameter, and the wallet-held question counter."""
    holder = o.get("holder") or {"kind": "site_local"}
    units: Dict[str, None] = {}
    untagged: List[dict] = []
    for v in schema["verbs"]:
        for path, d in v["params"].items():
            into = d.get("accumulates_into") or []
            for u in into:
                units[u] = None
            if d.get("type") == "integer" and d.get("semantic") == "money.amount" and not into:
                untagged.append({"verb": v["verb"], "path": path})
    out: List[dict] = []
    for u in sorted(units, key=_UTF8):
        out.append({"id": "spend_%s" % _sanitize(u), "agg": "sum", "unit": u, "sel": {"accumulates_into": u}, "win": {"kind": "task"},
                    "key": None, "domain_max": o["spendDomainMax"], "holder": holder})
    for x in sorted(untagged, key=lambda x: _UTF8(x["verb"] + x["path"])):
        out.append({"id": ("spend_%s_%s" % (_sanitize(x["verb"]), _sanitize(x["path"][len("action.params."):])))[:64], "agg": "sum", "val": x["path"],
                    "sel": {"verbs": [x["verb"]]}, "win": {"kind": "task"}, "key": None, "domain_max": o["spendDomainMax"], "holder": holder})
    cap = o.get("questionCap")
    out.append({"id": "questions", "agg": "count", "sel": {"event": "intent_required"}, "win": {"kind": "task"}, "key": None,
                "cap": 6 if cap is None else cap, "holder": {"kind": "wallet"}})
    return out


def describe_acc_cell(d: dict, cell_index: int, label: str, this_action: Any = None, fmt: Callable[[Any], str] = _js_string) -> str:
    """The fact line for an accumulator dimension of a cell."""
    cells = num_cells(d)
    if cell_index < 0 or cell_index >= len(cells):
        raise ValueError("describeAccCell: no such cell")
    c = cells[cell_index]
    rng = "exactly %s" % fmt(c["lo"]) if c["lo"] == c["hi"] else "between %s and %s" % (fmt(c["lo"]), fmt(c["hi"]))
    return "%s: %s%s" % (label, rng, " (this action: %s)" % fmt(this_action) if this_action is not None else "")


def trajectory_harm_range(max_session_length: Any, harm_max: Any) -> float:
    """The per-session harm range of a trajectory Monte Carlo estimate is [0, L_max * H_max]."""
    ok_len = isinstance(max_session_length, (int, float)) and not isinstance(max_session_length, bool) and float(max_session_length).is_integer() \
        and 0 <= max_session_length <= 9007199254740991
    ok_h = isinstance(harm_max, (int, float)) and not isinstance(harm_max, bool) and harm_max >= 0
    if not ok_len or not ok_h:
        raise ValueError("trajectoryHarmRange: bad arguments")
    return max_session_length * harm_max
