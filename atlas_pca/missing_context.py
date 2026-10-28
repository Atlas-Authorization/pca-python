"""Typed missing context and the stored-wins merge. When a permit condition cannot be decided because a value is absent the
verifier names what is missing and who may supply it (principal | discharge_issuer | rs_observation | agent_declared_untrusted);
a supplied value never replaces a bound one. Total: nothing raises, every malformed input is a deny. Port of
packages/pca/src/missing-context.ts; replays missing-context-vectors.json."""
import copy
import re
from typing import Any, Dict, List, Optional, Set

from .decision import _js_keys
from .k3 import u16key
from .pca import hash_canonical
from .predicates import evaluate_condition_tri, is_group_condition, resolve_path

SUPPLIERS = ("principal", "discharge_issuer", "rs_observation", "agent_declared_untrusted")
_FORBIDDEN = ("__proto__", "constructor", "prototype")
_KEY_RE = re.compile(r"(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*")


def supplier_of(path: str, table: Dict[str, str]) -> str:
    """The longest table key equal to ``path`` or a segment-boundary prefix of it; unmatched is ``principal``."""
    best: Optional[str] = None
    for k in table:
        if (path == k or path.startswith(k + ".")) and (best is None or len(k) > len(best)):
            best = k
    return "principal" if best is None else table[best]


def supplier_table_error(t: Any) -> Optional[str]:
    if not isinstance(t, dict):
        return "the supplier table must be an object"
    for k in _js_keys(t):
        v = t[k]
        if not _KEY_RE.fullmatch(k) or any(s in _FORBIDDEN for s in k.split(".")):
            return f"bad supplier path '{k}'"
        if not isinstance(v, str) or v not in SUPPLIERS:
            return f"bad supplier for '{k}'"
    return None


def _leaves(v: Any, prefix: str, out: Dict[str, Any], depth: int = 0) -> None:
    """Flatten a plain-object tree into dotted leaf paths. Arrays and non-plain values are leaves."""
    if depth > 16:
        out[prefix] = v
    elif isinstance(v, dict) and len(v) > 0:
        for k in sorted(v, key=u16key):
            if k not in _FORBIDDEN:
                _leaves(v[k], f"{prefix}.{k}", out, depth + 1)
    else:
        out[prefix] = v


def _set_path(root: dict, segs: List[str], value: Any) -> None:
    cur = root
    for s in segs[:-1]:
        if s not in cur or not isinstance(cur[s], dict):
            cur[s] = {}
        cur = cur[s]
    cur[segs[-1]] = value


def _digest(v: Any) -> str:
    return hash_canonical({"v": v})


def bind_context(bound: Any, supplied: Any, table: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Merge request-supplied context into the bound context. Bound wins. Returns {context, conflicts, dropped}."""
    table = table if isinstance(table, dict) else {}
    ctx = copy.deepcopy(bound)
    conflicts: List[str] = []
    dropped: List[str] = []
    if not isinstance(supplied, dict):
        return {"context": ctx, "conflicts": conflicts, "dropped": dropped}
    flat: Dict[str, Any] = {}
    try:
        a = supplied.get("action")
        if isinstance(a, dict) and isinstance(a.get("params"), dict):
            _leaves(a["params"], "action.params", flat)
        if isinstance(supplied.get("subject"), dict):
            _leaves(supplied["subject"], "subject", flat)
        if isinstance(supplied.get("env"), dict):
            _leaves(supplied["env"], "env", flat)
        for path in sorted(flat, key=u16key):
            value = flat[path]
            if supplier_of(path, table) == "agent_declared_untrusted":
                dropped.append(path)
                continue
            r = resolve_path(ctx, path)
            if r["found"]:
                if _digest(r["value"]) != _digest(value):
                    conflicts.append(path)
                continue
            segs = path.split(".")
            blocked = False
            for i in range(2, len(segs)):
                r2 = resolve_path(ctx, ".".join(segs[:i]))
                if r2["found"] and not isinstance(r2["value"], dict):
                    blocked = True  # a bound leaf sits above the supplied path: writing it would replace the bound value
            if blocked or not isinstance(ctx, dict):
                conflicts.append(path)
                continue
            if path.startswith("action.params"):
                act = ctx.get("action")
                if act is None:
                    act = {"verb": "", "resource": ""}
                if not isinstance(act, dict):
                    conflicts.append(path)  # the reference throws here; refused
                    continue
                if not isinstance(act.get("params"), dict):
                    act["params"] = {}
                ctx["action"] = act
            _set_path(ctx, segs, copy.deepcopy(value))
    except Exception:
        conflicts = sorted(set(conflicts) | set(flat) or {"?"}, key=u16key)  # fail closed: the call is refused
    return {"context": ctx, "conflicts": conflicts, "dropped": dropped}


def _collect(c: Any, ctx: Any, out: Set[str], ill: List[bool], depth: int = 0) -> None:
    if depth > 64 or not isinstance(c, (dict, list)):
        ill[0] = True
        return
    if is_group_condition(c):
        kids = c["all_of"] if "all_of" in c else c["any_of"] if "any_of" in c else [c["not"]]
        if not isinstance(kids, list) or len(kids) == 0:
            ill[0] = True
            return
        for k in kids:
            _collect(k, ctx, out, ill, depth + 1)
        return
    if evaluate_condition_tri(c, ctx) != "unknown":
        return
    field = c.get("field") if isinstance(c, dict) else None
    ref = c.get("ref") if isinstance(c, dict) else None
    absent = False
    for p in (field, ref):
        if isinstance(p, str) and len(p) > 0 and not resolve_path(ctx, p)["found"]:
            out.add(p)
            absent = True
    if isinstance(field, str) and (field == "action.params" or field.startswith("action.params.")):
        act = ctx.get("action") if isinstance(ctx, dict) else None
        p = act.get("params") if isinstance(act, dict) else None
        if not isinstance(p, (dict, list)):
            out.add(field)
            absent = True
    if not absent:
        ill[0] = True


def _deny(reason: str, missing: Optional[List[dict]] = None) -> Dict[str, Any]:
    return {"decision": "deny", "reason": reason, "missing": missing or []}


def decide_with_missing(where: Any, bound: Any, supplied: Any = None, suppliers: Any = None) -> Dict[str, Any]:
    """Decide a permit condition list (implicit AND) over the bound context plus whatever the request supplied."""
    try:
        if not isinstance(bound, dict) or not isinstance(bound.get("action"), dict):
            return _deny("bad_context")
        table = {} if suppliers is None else suppliers
        te = supplier_table_error(table)
        if te:
            return _deny(f"bad supplier table: {te}")
        if not isinstance(where, list) or len(where) == 0:
            return _deny("condition_false")
        b = bind_context(bound, supplied, table)
        if b["conflicts"]:
            return _deny("context_shadow: " + ",".join(b["conflicts"]))
        t = evaluate_condition_tri({"all_of": where}, b["context"])
        if t == "true":
            return {"decision": "allow", "missing": []}
        if t == "false":
            return _deny("condition_false")
        paths: Set[str] = set()
        ill = [False]
        for c in where:
            _collect(c, b["context"], paths, ill)
        if not paths or ill[0]:
            return _deny("ill_typed_context")
        missing = [{"path": p, "supplier": supplier_of(p, table)} for p in sorted(paths, key=u16key)]
        untrusted = [m["path"] for m in missing if m["supplier"] == "agent_declared_untrusted"]
        if untrusted:
            return _deny("missing_context_untrusted: " + ",".join(untrusted), missing)
        return {"decision": "escalate", "reason": "escalate: missing_context " + ",".join(f"{m['supplier']}:{m['path']}" for m in missing),
                "missing": missing}
    except Exception:
        return _deny("evaluation error (fail closed)")
