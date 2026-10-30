"""Ternary decision, tighten-only model rule (rule 21) and units check (rule 20). Port of packages/pca/src/decision.ts
(the TypeScript is authoritative; goal-to-decision track T2, security contract C-50..C-55).

A decision is `deny < escalate < allow`; `meet` (the minimum) is the only combinator, so `escalate` never becomes `allow`.
Every function is total and never raises; anything malformed fails closed (deny / ok False)."""
import math
import re
from typing import Any, Dict, List, Optional

from .predicates import _UNDEF, _js_string, evaluate_condition_tri

__all__ = [
    "meet", "meet_all", "signal_ceiling", "tighten", "decision_of", "pep_decision", "is_model_derived_path",
    "model_paths_read", "tighten_list_error", "decide_tighten", "unit_tags_error", "decide_units", "fold_v2_reasons",
]

_RANK = {"deny": 0, "escalate": 1, "allow": 2}
ESCALATE_REASON_PREFIXES = ("intent_required:", "escalate:")
MODEL_ENV_ROOTS = ("class", "prov", "judge", "detect")
MAX_TIGHTEN_RULES = 64
_NAME_SOURCE = "^[a-z][a-z0-9_]{0,63}$"  # the reference prints the pattern in its reasons
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")  # matched with fullmatch: `$` would also accept a trailing newline
_PARAM_PATH_RE = re.compile(r"action\.params\.[A-Za-z0-9_-]{1,64}")


def _is_obj(v: Any) -> bool:
    """A plain object: not null, not an array."""
    return isinstance(v, dict)


def _safe_int(v: Any) -> bool:
    """`Number.isSafeInteger(v) && !Object.is(v, -0)` for a parsed JSON number (2.0 is the number 2)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) <= 2**53 - 1
    if isinstance(v, float):
        return math.isfinite(v) and v == math.floor(v) and abs(v) <= 2**53 - 1 and not (v == 0 and math.copysign(1.0, v) < 0)
    return False


def _u16(s: str) -> int:
    """`s.length` of a JavaScript string: UTF-16 code units."""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]{0,9}")


def _js_keys(o: dict) -> List[str]:
    """`Object.keys(o)` of the JSON value: canonical array-index keys first (ascending), then the rest in text order."""
    idx = sorted((k for k in o if _ARRAY_INDEX.fullmatch(k) and int(k) < 2**32 - 1), key=int)
    return idx + [k for k in o if k not in set(idx)]


def _utf8_key(s: str) -> bytes:
    return s.encode("utf-8", "surrogatepass")


def meet(a: Any, b: Any) -> str:
    x, y = _RANK.get(a), _RANK.get(b)
    if x is None or y is None:
        return "deny"
    return a if x <= y else b


def meet_all(ds: List[Any]) -> str:
    acc = "allow"
    for d in ds:
        acc = meet(acc, d)
    return acc


def signal_ceiling(s: Any) -> str:
    return "allow" if s == "ok" else ("escalate" if s == "escalate" else "deny")


def tighten(base: Any, signal: Any) -> str:
    return meet(base, signal_ceiling(signal))


def decision_of(v: Any) -> str:
    try:
        if v.get("allow") is True:
            return "allow"
        failing = 0
        reasons = v.get("reasons") or []
        for name, status in v["checks"].items():
            if status != "fail":
                continue
            failing += 1
            head = f"{name}: "
            own = [r for r in reasons if isinstance(r, str) and r.startswith(head)]
            if not own:
                return "deny"
            if not all(any(r[len(head):].startswith(p) for p in ESCALATE_REASON_PREFIXES) for r in own):
                return "deny"
        return "escalate" if failing > 0 else "deny"
    except Exception:
        return "deny"


def pep_decision(d: Any, answered: Any) -> Any:
    """`d === 'escalate' && answered === true ? 'allow' : d`: anything but an answered escalate is returned UNCHANGED (as the
    reference does, whatever `d` is)."""
    return "allow" if d == "escalate" and isinstance(d, str) and answered is True else d


def is_model_derived_path(path: Any, single_source: Any = ()) -> bool:
    if not isinstance(path, str):
        return False
    seg = path.split(".")
    if seg[0] != "env" or len(seg) < 2:
        return False
    if seg[1] in MODEL_ENV_ROOTS:
        return True
    if seg[1] == "world":
        return len(single_source) > 0 if len(seg) == 2 else seg[2] in single_source
    return False


def _collect_paths(c: Any, out: set, depth: int) -> None:
    if depth > 64 or not isinstance(c, (dict, list)) or isinstance(c, list):
        return
    for k in ("all_of", "any_of"):
        if isinstance(c.get(k), list):
            for x in c[k]:
                _collect_paths(x, out, depth + 1)
    if c.get("not") is not None:
        _collect_paths(c["not"], out, depth + 1)
    for k in ("field", "ref", "collection"):
        if isinstance(c.get(k), str):
            out.add(c[k])


def model_paths_read(predicate_lists: Any, single_source: Any = ()) -> List[str]:
    found: set = set()
    for lst in predicate_lists if isinstance(predicate_lists, list) else []:
        if not isinstance(lst, list):
            continue
        for p in lst:
            w = p.get("where") if isinstance(p, dict) else None
            if isinstance(w, list):
                for c in w:
                    _collect_paths(c, found, 0)
    return sorted((p for p in found if is_model_derived_path(p, single_source)), key=_utf8_key)


def _closed(o: dict, required: tuple, optional: tuple, where: str) -> Optional[str]:
    for k in _js_keys(o):
        if k not in required and k not in optional:
            return f"unknown member '{where}.{k}'"
    for k in required:
        if k not in o:
            return f"missing member '{where}.{k}'"
    return None


def tighten_list_error(t: Any = _UNDEF) -> Optional[str]:
    """None = well-formed. `_UNDEF` (absent) is well-formed; JSON null is NOT (it is not an array)."""
    if t is _UNDEF:
        return None
    if not isinstance(t, list):
        return "tighten must be an array"
    if len(t) > MAX_TIGHTEN_RULES:
        return f"tighten has more than {MAX_TIGHTEN_RULES} rules"
    ids = set()
    for i, r in enumerate(t):
        if not _is_obj(r):
            return f"tighten[{i}] must be an object"
        e = _closed(r, ("id", "when", "signal"), ("reason",), f"tighten[{i}]")
        if e:
            return e
        if not isinstance(r["id"], str) or not _NAME_RE.fullmatch(r["id"]):
            return f"tighten[{i}].id must match {_NAME_SOURCE}"
        if r["id"] in ids:
            return f"tighten[{i}].id '{r['id']}' is a duplicate"
        ids.add(r["id"])
        if not _is_obj(r["when"]):
            return f"tighten[{i}].when must be a condition object"
        if r["signal"] not in ("escalate", "deny") or not isinstance(r["signal"], str):
            return f"tighten[{i}].signal must be 'escalate' or 'deny'"
        if "reason" in r and (not isinstance(r["reason"], str) or _u16(r["reason"]) > 256):
            return f"tighten[{i}].reason must be a string of at most 256 characters"
    return None


def decide_tighten(inp: Any) -> Dict[str, Any]:
    def res(outcome: str, legacy: bool, offending: List[str], reason: Optional[str] = None) -> Dict[str, Any]:
        out = {"outcome": outcome, "legacy": legacy, "offending": offending}
        if reason is not None:
            out["reason"] = reason
        return out

    try:
        ss = inp.get("single_source")
        single = [x for x in ss if isinstance(x, str)] if isinstance(ss, list) else []
        pol = inp.get("polarity", _UNDEF)
        if pol is not _UNDEF and pol != "legacy":  # JSON null is present, and is not 'legacy'
            return res("deny", False, [], "model_polarity must be 'legacy' when present")
        tl = inp.get("tighten", _UNDEF)
        le = tighten_list_error(tl)
        if le:
            return res("deny", False, [], f"malformed tighten list: {le}")
        preds = inp.get("predicates")
        offending = model_paths_read(preds if isinstance(preds, list) else [], single)
        legacy = pol == "legacy" and len(offending) > 0
        if offending and not legacy:
            return res("deny", False, offending, "a grant's where reads model-derived path(s) " + ", ".join(offending)
                       + ": a model may only tighten (move them into tighten[]) (rule 21)")
        out = "ok"
        reason = None
        ctx = inp.get("context") if _is_obj(inp.get("context")) else {}
        for r in ([] if tl is _UNDEF else tl):
            t = evaluate_condition_tri(r["when"], ctx)
            sig = r["signal"] if t == "true" else ("escalate" if t == "unknown" else None)
            if sig is None:
                continue
            if t == "true":
                why = ("denied by" if sig == "deny" else "escalate: asked by") + f" tighten rule '{r['id']}'"
                if "reason" in r:
                    why += f" ({r['reason']})"
            else:
                why = f"escalate: rule '{r['id']}' could not be decided (a value it reads is missing or ill-typed)"
            if _RANK[signal_ceiling(sig)] < _RANK[signal_ceiling(out)]:
                out = sig
                reason = why
        return res(out, legacy, offending, reason)
    except Exception as e:  # fail closed
        return res("deny", False, [], f"evaluation error (fail closed): {e}")


def unit_tags_error(u: Any) -> Optional[str]:
    if not _is_obj(u):
        return "units must be an object"
    if len(u) > 64:
        return "units has more than 64 entries"
    for k in _js_keys(u):
        t = u[k]
        if not _PARAM_PATH_RE.fullmatch(k):
            return f"units key '{k}' must be an action.params.<name> path"
        if not _is_obj(t):
            return f"units['{k}'] must be an object"
        e = _closed(t, ("kind",), ("currency", "exponent"), f"units['{k}']")
        if e:
            return e
        if not isinstance(t["kind"], str) or not 1 <= _u16(t["kind"]) <= 64:
            return f"units['{k}'].kind must be a string of 1..64 characters"
        if "currency" in t and (not isinstance(t["currency"], str) or not 1 <= _u16(t["currency"]) <= 16):
            return f"units['{k}'].currency must be a string of 1..16 characters"
        if "exponent" in t and not (_safe_int(t["exponent"]) and 0 <= t["exponent"] <= 18):
            return f"units['{k}'].exponent must be an integer in [0, 18]"
    return None


def _strict_eq(a: Any, b: Any) -> bool:
    """JavaScript `===` over parsed JSON values (absent is `_UNDEF`; two parsed objects are never identical)."""
    if a is _UNDEF or b is _UNDEF:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def _same_tag(a: dict, b: dict) -> bool:
    return all(_strict_eq(a.get(k, _UNDEF), b.get(k, _UNDEF)) for k in ("kind", "currency", "exponent"))


def _tag_text(t: Optional[dict]) -> str:
    if t is None:
        return "no unit"
    kind = t.get("kind", _UNDEF)
    cur, exp = t.get("currency", _UNDEF), t.get("exponent", _UNDEF)
    return ("?" if kind is _UNDEF or kind is None else _js_string(kind)) \
        + ("" if cur is _UNDEF else "/" + _js_string(cur)) + ("" if exp is _UNDEF else "/e" + _js_string(exp))


def _verb_in_scope(p: Any, verb: str) -> bool:
    v = p.get("verb") if isinstance(p, dict) else None
    return v == "*" or v == verb or (isinstance(v, list) and verb in v)


def decide_units(inp: Any) -> Dict[str, Any]:
    def fail(m: str) -> Dict[str, Any]:
        return {"ok": False, "reason": m}

    try:
        te = unit_tags_error(inp.get("units", None))
        if te:
            return fail(te)
        tags = inp["units"]
        verb = inp.get("verb")
        if not isinstance(verb, str) or not verb:
            return fail("the verb is missing")
        s_units = inp.get("schema_units", _UNDEF)
        s_units = {} if s_units is _UNDEF else s_units  # null is NOT absent
        if not _is_obj(s_units):
            return fail("the schema units table must be an object")
        params = inp.get("verb_params")
        if not _is_obj(params):
            return fail(f"the schema does not declare verb '{verb}'")

        def declared(path: str):
            d = params.get(path)
            if not _is_obj(d):
                return False, None
            uid = d.get("unit")
            tag = s_units.get(uid) if isinstance(uid, str) else None
            return True, tag if _is_obj(tag) else None

        for path in sorted(tags, key=_utf8_key):
            has, tag = declared(path)
            if not has:
                continue
            if tag is None or not _same_tag(tag, tags[path]):
                return fail(f"'{path}' is declared as {_tag_text(tag)} by the action schema but the policy term is tagged "
                            f"{_tag_text(tags[path])} (unit confusion)")
        read: set = set()
        for lst in inp.get("predicates") if isinstance(inp.get("predicates"), list) else []:
            if not isinstance(lst, list):
                continue
            for p in lst:
                if not _verb_in_scope(p, verb):
                    continue
                w = p.get("where") if isinstance(p, dict) else None
                if isinstance(w, list):
                    for c in w:
                        _collect_paths(c, read, 0)
        for path in sorted(read, key=_utf8_key):
            if not _PARAM_PATH_RE.fullmatch(path):
                continue
            has, tag = declared(path)
            if has and tag is not None and path not in tags:
                return fail(f"a policy term reads '{path}' ({_tag_text(tag)}) without a unit tag")
        return {"ok": True}
    except Exception as e:
        return fail(f"evaluation error (fail closed): {e}")


def fold_v2_reasons(base: Any, v2: Any) -> List[str]:
    """The ordered reason list of a verdict: `base` (the core's own reasons), then one `<check>: <reason>` for EVERY failing
    intent-v2 check not already listed (the core keeps only its first failure). A failing check without a reason adds nothing.
    Mirrors `foldV2Reasons` (decision.ts)."""
    out = list(base)
    for c in v2:
        if c.get("ok") is not True and c.get("reason") is not None:
            r = "%s: %s" % (c["name"], c["reason"])
            if r not in out:
                out.append(r)
    return out
