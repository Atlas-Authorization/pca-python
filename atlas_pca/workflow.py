"""Workflow (DAG) admission (K5, verification side): ``admit_step`` / ``bind_promises`` / ``plan_root_authorized``. Total, pure
functions (no clock, no store, no I/O) shaped like the shared vectors (``workflow-vectors.json``). Everything unknown, malformed,
unsigned, out of order or unplanned denies; only a pipelined step with an unconstrained promised input and an "ask a human"
label escalate. Integers only: a float or a bool is never an integer. Signing is the reference implementation's job."""
import re
from typing import Any, Callable, Dict, List, Optional

from .k3 import is_obj, is_str, verify_body
from .pca import decode_b64u_strict, hash_canonical

WORKFLOW_DOMAIN = "atlas-pca/workflow/v1\0"
WF_RECEIPT_DOMAIN = "atlas-pca/wf-receipt/v1\0"
_WF_REF = "atlas-pca/workflow-ref/v1"
_WR_REF = "atlas-pca/wf-receipt-ref/v1"
_VAL = "atlas-pca/wf-value/v1"
LIMITS = {"steps": 64, "edges": 256, "deps": 16, "labels": 16, "fields": 32, "cost": 8, "id": 64}

ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
LABEL_RE = re.compile(r"[a-z0-9_.:-]{1,64}")
NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
UNIT_RE = re.compile(r"[A-Za-z0-9_.:-]{1,16}")
_MAX_SAFE = 2**53 - 1


# ---- shared strict helpers (also used by readside.py) ---------------------------------------------------------------------

def rx(r: "re.Pattern[str]", s: Any) -> bool:
    """Full-match (no trailing-newline slack) and never the literal ``__proto__`` (the reference's lookahead)."""
    return isinstance(s, str) and r.fullmatch(s) is not None and s != "__proto__"


def is_int(n: Any) -> bool:
    return isinstance(n, int) and not isinstance(n, bool) and abs(n) <= _MAX_SAFE


def is_uint(n: Any) -> bool:
    return is_int(n) and n >= 0


def is_b32(x: Any) -> bool:
    return decode_b64u_strict(x, 32) is not None


def sorted_unique(x: Any, r: "re.Pattern[str]", mx: int) -> bool:
    """Strictly ascending (bytewise; ASCII only) with every member matching ``r``."""
    if not isinstance(x, list) or len(x) > mx:
        return False
    for i, s in enumerate(x):
        if not rx(r, s) or (i > 0 and not x[i - 1] < s):
            return False
    return True


def only_keys(o: dict, keys: Any) -> bool:
    return len(o) == len(keys) and all(k in o for k in keys)


def _scalar(v: Any) -> bool:
    return isinstance(v, str) or isinstance(v, bool) or is_int(v)


def is_scalar_map(x: Any) -> bool:
    return is_obj(x) and len(x) <= LIMITS["fields"] and all(rx(NAME_RE, k) and _scalar(v) for k, v in x.items())


def value_digest(v: Any) -> str:
    return hash_canonical({"d": _VAL, "v": v})


# ---- validation -----------------------------------------------------------------------------------------------------------

_STEP_KEYS = ("id", "verb", "resource", "params_digest", "deps", "sink", "deny_labels", "escalate_labels", "fresh_ms", "cost")
_EDGE_KEYS = ("from", "to", "op", "unit", "deny_labels", "promise")
_BODY_KEYS = ("v", "id", "principal", "goal_digest", "plan_root", "issued_at", "expires_at", "steps", "edges", "budget")
_OPS = ("eq", "le", "ge", "lt", "gt")


def _null_or(x: Any, ok: Callable[[Any], bool]) -> bool:
    return x is None or ok(x)


def _is_id(x: Any) -> bool:
    return rx(ID_RE, x)


def _is_name(x: Any) -> bool:
    return rx(NAME_RE, x)


def _is_unit(x: Any) -> bool:
    return isinstance(x, str) and UNIT_RE.fullmatch(x) is not None


def _uint_map(x: Any, mx: int) -> bool:
    return is_obj(x) and len(x) <= mx and all(rx(NAME_RE, k) and is_uint(v) for k, v in x.items())


def _is_one(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v == 1


def _valid_step(s: Any) -> bool:
    if not is_obj(s) or not only_keys(s, _STEP_KEYS):
        return False
    return (_is_id(s["id"]) and is_str(s["verb"], 128) and is_str(s["resource"], 512) and _null_or(s["params_digest"], is_b32)
            and sorted_unique(s["deps"], ID_RE, LIMITS["deps"]) and _null_or(s["sink"], _is_id)
            and sorted_unique(s["deny_labels"], LABEL_RE, LIMITS["labels"]) and sorted_unique(s["escalate_labels"], LABEL_RE, LIMITS["labels"])
            and _null_or(s["fresh_ms"], is_uint) and _uint_map(s["cost"], LIMITS["cost"]))


def _valid_edge(e: Any) -> bool:
    if not is_obj(e) or not only_keys(e, _EDGE_KEYS):
        return False
    f, t = e["from"], e["to"]
    return (is_obj(f) and only_keys(f, ("step", "field")) and _is_id(f["step"]) and _is_name(f["field"])
            and is_obj(t) and only_keys(t, ("step", "param")) and _is_id(t["step"]) and _is_name(t["param"])
            and isinstance(e["op"], str) and e["op"] in _OPS and _null_or(e["unit"], _is_unit)
            and sorted_unique(e["deny_labels"], LABEL_RE, LIMITS["labels"]) and _null_or(e["promise"], _is_id))


def valid_workflow_body(b: Any) -> bool:
    """Shape of the body only (no signature, no DAG semantics)."""
    if not is_obj(b) or not only_keys(b, _BODY_KEYS) or not _is_one(b["v"]):
        return False
    if not (_is_id(b["id"]) and is_b32(b["principal"]) and _null_or(b["goal_digest"], is_b32) and _null_or(b["plan_root"], is_b32)
            and is_uint(b["issued_at"]) and is_uint(b["expires_at"])):
        return False
    steps, edges = b["steps"], b["edges"]
    if not isinstance(steps, list) or not 0 < len(steps) <= LIMITS["steps"] or not all(_valid_step(s) for s in steps):
        return False
    if not isinstance(edges, list) or len(edges) > LIMITS["edges"] or not all(_valid_edge(e) for e in edges):
        return False
    bg = b["budget"]
    if not is_obj(bg) or not only_keys(bg, ("max_steps", "caps")) or not is_uint(bg["max_steps"]) or not _uint_map(bg["caps"], LIMITS["cost"]):
        return False
    # every cost name must be capped
    return all(k in bg["caps"] for s in steps for k in s["cost"])


def dag_error(b: dict) -> Optional[str]:
    """Unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency."""
    ids: Dict[str, dict] = {}
    for s in b["steps"]:
        if s["id"] in ids:
            return "duplicate step id"
        ids[s["id"]] = s
    for s in b["steps"]:
        for d in s["deps"]:
            if d == s["id"] or d not in ids:
                return "bad dependency"
    anc = ancestors(b)
    if anc is None:
        return "cycle"
    for e in b["edges"]:
        if e["from"]["step"] not in ids or e["to"]["step"] not in ids or e["from"]["step"] not in anc[e["to"]["step"]]:
            return "edge does not follow a dependency"
    return None


def ancestors(b: dict) -> Optional[Dict[str, set]]:
    """step id -> the set of its transitive dependencies; None on a cycle."""
    by_id = {s["id"]: s for s in b["steps"]}
    out: Dict[str, set] = {}
    state: Dict[str, int] = {}

    def visit(i: str) -> bool:
        if state.get(i) == 2:
            return True
        if state.get(i) == 1:
            return False
        state[i] = 1
        acc: set = set()
        for d in by_id[i]["deps"]:
            if not visit(d):
                return False
            acc.add(d)
            acc |= out[d]
        out[i] = acc
        state[i] = 2
        return True

    for s in b["steps"]:
        if not visit(s["id"]):
            return None
    return out


def workflow_digest(b: dict) -> str:
    return hash_canonical({"d": _WF_REF, "w": b})


def receipt_ref(r: dict) -> str:
    return hash_canonical({"d": _WR_REF, "r": r})


_REC_KEYS = ("v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer")


def _rec_body(r: dict) -> dict:
    return {k: r[k] for k in _REC_KEYS}


def _valid_receipt_shape(r: Any) -> bool:
    if not is_obj(r) or not only_keys(r, _REC_KEYS + ("sig",)) or not _is_one(r["v"]):
        return False
    if not (is_b32(r["wf"]) and _is_id(r["step"]) and is_uint(r["seq"]) and _null_or(r["prev"], is_b32) and (r["seq"] == 0) == (r["prev"] is None)
            and r["outcome"] in ("ok", "failed") and isinstance(r["outcome"], str)):
        return False
    if not (is_b32(r["params_digest"]) and is_uint(r["issued_at"]) and is_b32(r["signer"]) and isinstance(r["sig"], str)):
        return False
    o = r["outputs"]
    if not is_obj(o) or len(o) > LIMITS["fields"]:
        return False
    return all(rx(NAME_RE, k) and is_obj(v) and only_keys(v, ("digest", "num", "unit", "labels")) and is_b32(v["digest"])
               and _null_or(v["num"], is_uint) and _null_or(v["unit"], _is_unit) and sorted_unique(v["labels"], LABEL_RE, LIMITS["labels"])
               for k, v in o.items())


# ---- admission ------------------------------------------------------------------------------------------------------------

def _res(decision: str, code: Optional[str], step: Optional[str], at: Optional[int] = None, pending: Optional[List[int]] = None) -> dict:
    return {"decision": decision, "code": code, "step": step, "at": at, "pending": list(pending or [])}


def _deny(code: str, step: Optional[str] = None, at: Optional[int] = None) -> dict:
    return _res("deny", code, step, at)


def plan_root_authorized(workflow: Any, principal: Any, now: Any, root: Any) -> bool:
    """Is ``root`` the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes?"""
    try:
        w = workflow
        return bool(is_obj(w) and valid_workflow_body(w.get("body")) and dag_error(w["body"]) is None and w["body"]["principal"] == principal
                    and verify_body(WORKFLOW_DOMAIN, w["body"], principal, w.get("sig")) and is_int(now)
                    and w["body"]["issued_at"] <= now < w["body"]["expires_at"] and w["body"]["plan_root"] == root)
    except Exception:
        return False


def _valid_request(r: Any) -> bool:
    return (is_obj(r) and only_keys(r, ("step", "verb", "resource", "params", "units", "goal_digest", "plan_root")) and _is_id(r["step"])
            and is_str(r["verb"], 128) and is_str(r["resource"], 512) and is_scalar_map(r["params"]) and is_obj(r["units"])
            and all(rx(NAME_RE, k) and _is_unit(v) for k, v in r["units"].items())
            and _null_or(r["goal_digest"], is_b32) and _null_or(r["plan_root"], is_b32))


def _receipt_error(w: dict, rs_signer: str, receipts: list, now: int) -> Optional[int]:
    wd = workflow_digest(w)
    by_id = {s["id"]: s for s in w["steps"]}
    index: Dict[str, int] = {}
    prev: Optional[dict] = None
    for i, r in enumerate(receipts):
        if not _valid_receipt_shape(r) or r["signer"] != rs_signer or r["wf"] != wd or r["seq"] != i or r["issued_at"] > now:
            return i
        if r["step"] not in by_id or r["step"] in index:
            return i
        if (r["prev"] is not None if prev is None else r["prev"] != receipt_ref(prev)) or not verify_body(WF_RECEIPT_DOMAIN, _rec_body(r), rs_signer, r["sig"]):
            return i
        # a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
        for d in by_id[r["step"]]["deps"]:
            if d in index:
                continue
            es = [e for e in w["edges"] if e["from"]["step"] == d and e["to"]["step"] == r["step"]]
            if not es or any(e["promise"] is None for e in es):
                return i
        index[r["step"]] = i
        prev = r
    return None


def _evaluate(inp: dict, bind: bool) -> dict:
    sw = inp.get("workflow")
    principal, rs, now, receipts, q = inp.get("principal"), inp.get("rs_signer"), inp.get("now"), inp.get("receipts"), inp.get("request")
    if (not is_obj(sw) or not only_keys(sw, ("body", "sig")) or not valid_workflow_body(sw["body"]) or not _valid_request(q)
            or not isinstance(receipts, list) or not is_b32(principal) or not is_b32(rs) or not is_uint(now)):
        return _deny("bad_workflow")
    w = sw["body"]
    if dag_error(w) is not None:
        return _deny("bad_dag", q["step"])
    if w["principal"] != principal or not verify_body(WORKFLOW_DOMAIN, w, principal, sw["sig"]):
        return _deny("bad_signature", q["step"])
    if now < w["issued_at"]:
        return _deny("not_yet", q["step"])
    if now >= w["expires_at"]:
        return _deny("expired", q["step"])
    if q["goal_digest"] != w["goal_digest"]:
        return _deny("goal_mismatch", q["step"])
    if q["plan_root"] != w["plan_root"]:
        return _deny("plan_root_mismatch", q["step"])
    bad = _receipt_error(w, rs, receipts, now)
    if bad is not None:
        return _deny("bad_receipt", q["step"], bad)
    rec = {r["step"]: r for r in receipts}
    step = next((s for s in w["steps"] if s["id"] == q["step"]), None)
    if step is None:
        return _deny("unplanned_step", q["step"])
    if step["verb"] != q["verb"] or step["resource"] != q["resource"]:
        return _deny("step_mismatch", q["step"])
    pd = hash_canonical(q["params"])
    if step["params_digest"] is not None and step["params_digest"] != pd:
        return _deny("params_mismatch", q["step"])
    mine = rec.get(step["id"])
    if bind:
        if mine is None or mine["params_digest"] != pd:
            return _deny("params_mismatch", q["step"])
    else:
        if mine is not None:
            return _deny("already_done", q["step"])
        if len(receipts) + 1 > w["budget"]["max_steps"]:
            return _deny("budget_exceeded", q["step"])
        by_id = {s["id"]: s for s in w["steps"]}
        for name, cap in w["budget"]["caps"].items():
            spent = sum(by_id[r["step"]]["cost"].get(name, 0) for r in receipts) + step["cost"].get(name, 0)
            if spent > cap:
                return _deny("budget_exceeded", q["step"])
    pending: List[int] = []
    unconstrained = False
    for d in step["deps"]:
        dr = rec.get(d)
        if dr is None:
            es = [e for e in w["edges"] if e["from"]["step"] == d and e["to"]["step"] == step["id"]]
            if bind or not es:
                return _deny("deps_unmet", q["step"])
            if any(e["promise"] is None for e in es):
                unconstrained = True
            continue
        if dr["outcome"] != "ok":
            return _deny("dep_failed", q["step"])
        if step["fresh_ms"] is not None and now - dr["issued_at"] > step["fresh_ms"]:
            return _deny("stale_dep", q["step"])
    for i, e in enumerate(w["edges"]):
        if e["to"]["step"] != step["id"]:
            continue
        src = rec.get(e["from"]["step"])
        if src is None:
            pending.append(i)
            continue
        out = src["outputs"].get(e["from"]["field"])
        val = q["params"].get(e["to"]["param"])
        if out is None or val is None:
            return _deny("edge_missing", q["step"], i)
        if out["unit"] != q["units"].get(e["to"]["param"]) or out["unit"] != e["unit"]:
            return _deny("edge_unit", q["step"], i)
        if e["op"] == "eq":
            if value_digest(val) != out["digest"]:
                return _deny("edge_digest", q["step"], i)
        else:
            if not is_int(val) or out["num"] is None:
                return _deny("edge_value", q["step"], i)
            n, op = out["num"], e["op"]
            ok = val <= n if op == "le" else val >= n if op == "ge" else val < n if op == "lt" else val > n
            if not ok:
                return _deny("edge_relation", q["step"], i)
        if any(lb in e["deny_labels"] for lb in out["labels"]):
            return _deny("taint_flow", q["step"], i)
    if bind and pending:
        return _deny("deps_unmet", q["step"])
    anc = ancestors(w)
    inherited = {lb for a in anc[step["id"]] if a in rec for o in rec[a]["outputs"].values() for lb in o["labels"]}
    if any(lb in inherited for lb in step["deny_labels"]):
        return _deny("taint_flow", q["step"])
    if unconstrained:
        return _res("escalate", "pipeline_unconstrained", q["step"])
    if any(lb in inherited for lb in step["escalate_labels"]):
        return _res("escalate", "taint_escalate", q["step"])
    return _res("allow", None, q["step"], None, pending)


def admit_step(inp: Any) -> dict:
    """Admit ONE step of the committed workflow, or deny / escalate. ``inp``: workflow, principal, rs_signer, receipts, now, request."""
    try:
        return _evaluate(inp, False)
    except Exception:
        return _deny("bad_workflow")


def bind_promises(inp: Any) -> dict:
    """Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge."""
    try:
        return _evaluate(inp, True)
    except Exception:
        return _deny("bad_workflow")
