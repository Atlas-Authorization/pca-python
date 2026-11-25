"""Frame and side-effect constraints: monitored state snapshots, write sets, the frame condition over everything a verb does
not write and the verb's postconditions (exact numeric deltas, predicate conditions over env.pre / env.post / env.effect).
Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

import functools
from typing import Any, Callable, Dict, List, Optional

from .intent_omega import is_number
from .intent_v2 import _UNDEF, _js_string, compare_utf8
from .pca import b64u, canonical_bytes, sha256
from .predicates import evaluate_predicates, is_group_condition, is_leaf_condition

FRAME_STATE_DOMAIN = "atlas-pca/intent-frame-state/v1"
_UTF8 = functools.cmp_to_key(compare_utf8)


def state_digest(value: Any) -> str:
    """Digest of a state value (site-local, never cross-language: the lenient canonical form)."""
    return b64u(sha256(canonical_bytes({"d": FRAME_STATE_DOMAIN, "v": None if value is _UNDEF else value})))


def snapshot_state(values: Dict[str, Any], keep_values: bool = True) -> Dict[str, dict]:
    """Snapshot already-read values."""
    return {k: ({"digest": state_digest(v), "value": v} if keep_values else {"digest": state_digest(v)}) for k, v in values.items()}


def capture_state(readers: Dict[str, Callable[[], Any]], keep_values: bool = True) -> Dict[str, dict]:
    """Read every monitored variable through its (synchronous) reader and snapshot it."""
    values: Dict[str, Any] = {}
    for k in sorted(readers, key=_UTF8):
        values[k] = readers[k]()
    return snapshot_state(values, keep_values)


def _get(root: Any, path: str) -> Any:
    cur = root
    for s in path.split("."):
        if isinstance(cur, dict) and s in cur:
            cur = cur[s]
        elif isinstance(cur, list) and s.isascii() and s.isdigit() and str(int(s)) == s and int(s) < len(cur):
            cur = cur[int(s)]
        else:
            return _UNDEF
    return cur


def write_set_of(spec: dict, action: dict) -> List[str]:
    """W(action): the declared list, or the parameter-selected list (unknown parameter value: default, else empty)."""
    writes = spec["writes"]
    d = writes.get(action["verb"]) if isinstance(writes, dict) and action["verb"] in writes else None
    if d is None:
        return []
    if isinstance(d, list):
        return list(d)
    p = d["param"]
    v = _get(action.get("params") or {}, p[len("action.params."):] if p.startswith("action.params.") else p)
    key = _js_string(v) if (isinstance(v, (str, bool)) or is_number(v)) else None
    mp = d["map"]
    return list(mp[key] if key is not None and key in mp else (d.get("default") or []))


def _env_reads(c: Any, out: List[str]) -> None:
    if c is None or not isinstance(c, dict):
        return
    if is_group_condition(c):
        if "all_of" in c and isinstance(c["all_of"], list):
            for x in c["all_of"]:
                _env_reads(x, out)
        elif "any_of" in c and isinstance(c["any_of"], list):
            for x in c["any_of"]:
                _env_reads(x, out)
        elif "not" in c:
            _env_reads(c["not"], out)
        return
    if is_leaf_condition(c):
        if c["field"].startswith("env."):
            out.append(c["field"])
        if isinstance(c.get("ref"), str) and c["ref"].startswith("env."):
            out.append(c["ref"])


def _nest(s: Dict[str, dict]) -> Dict[str, Any]:
    root: Dict[str, Any] = {}
    for k, v in s.items():
        if "value" not in v:
            continue
        segs = k.split(".")
        cur = root
        for seg in segs[:-1]:
            if seg not in cur or not isinstance(cur[seg], dict):
                cur[seg] = {}
            cur = cur[seg]
        cur[segs[-1]] = v["value"]
    return root


def check_frame(spec: Any, action: Any, pre: Any, post: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Check one executed action: the frame condition over the monitored state outside its write set and the verb's
    postconditions. Total: never raises. attributions = [{var, actor}] excuse a change by an actor other than `self`."""
    opts = opts or {}
    rep: Dict[str, Any] = {"status": "ok", "outOfFrame": [], "attributed": [], "postViolated": [], "missing": [], "unmonitored": False}
    try:
        if not isinstance(spec, dict) or not isinstance(spec.get("state"), list) or not isinstance(action, dict) \
                or not isinstance(pre, dict) or not isinstance(post, dict):
            raise ValueError("spec, action, pre and post must be objects (spec.state an array)")
        rep["unmonitored"] = len(spec["state"]) == 0
        W = set(write_set_of(spec, action))
        for v in sorted(spec["state"], key=_UTF8):
            if v in W:
                continue
            a = pre.get(v)
            b = post.get(v)
            if a is None or b is None:
                rep["missing"].append(v)
                continue
            if a["digest"] == b["digest"]:
                continue
            other = any(x["var"] == v and x["actor"] != opts.get("self") for x in (opts.get("attributions") or []))
            rep["attributed" if other else "outOfFrame"].append(v)
        env = {"pre": _nest(pre), "post": _nest(post), "effect": opts.get("effect") or {}}
        ctx = {"action": {"verb": action["verb"], "resource": action["resource"], "params": action.get("params") or {}}, "env": env}
        for pc in spec.get("post") or []:
            if pc["verb"] != action["verb"]:
                continue
            pending = False
            for d in pc.get("deltas") or []:
                x = _get(env["pre"], d["path"])
                y = _get(env["post"], d["path"])
                if not is_number(x) or not is_number(y):
                    rep["missing"].append("%s:%s" % (pc["id"], d["path"]))
                    pending = True
                elif y != x + d["by"]:
                    rep["postViolated"].append(pc["id"])
                    pending = True
                    break
            if pending:
                continue
            reads: List[str] = []
            for c in pc.get("where") or []:
                _env_reads(c, reads)
            absent = [r for r in reads if _get({"env": env}, r) is _UNDEF]
            if absent:
                rep["missing"].extend("%s:%s" % (pc["id"], r) for r in absent)
                continue
            where = pc.get("where")
            if where and len(where) and not evaluate_predicates([{"verb": action["verb"], "where": where}], ctx)["allowed"]:
                rep["postViolated"].append(pc["id"])
    except Exception as e:  # noqa: BLE001
        rep["missing"].append("error: %s" % e)
    rep["missing"] = sorted(set(rep["missing"]), key=_UTF8)
    rep["postViolated"] = sorted(set(rep["postViolated"]), key=_UTF8)
    rep["status"] = "violated" if rep["outOfFrame"] or rep["postViolated"] else "pending" if rep["missing"] else "ok"
    return rep


def apply_frame_report(l: Any, o: dict, report: Any) -> Dict[str, Any]:
    """Feed a frame report back: a violation is a negative runtime observation that vetoes the outcome's cell for good;
    `ok` and `pending` change nothing (a met frame is not the principal's endorsement)."""
    from .intent_mapkit import apply_divergence
    if not isinstance(report, dict) or report.get("status") != "violated":
        return {}
    return {"signal": "postcondition-violation", "divergence": apply_divergence(l, o, 0)}
