"""Decision obligations (verification side): validate, merge, the PEP gate and the overdue outcome. An allow whose obligations the
enforcement point cannot all perform becomes a deny. Total: no function raises. Replays obligations-vectors.json."""
import re
from typing import Any, Dict, List, Optional

from .decision import pep_decision
from .k3 import is_obj, is_str, is_uint
from .pca import canonicalize_strict

OBLIGATION_KINDS = ("log", "notify", "redact", "watermark", "require_receipt")
MAX_OBLIGATIONS = 16
_MAX_REDACT_FIELDS = 32
_FIELD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}")
_ALLOWED = {"log": ("sink",), "notify": ("to",), "redact": ("fields",), "watermark": ("id",), "require_receipt": ()}


def _params_error(kind: str, p: dict) -> Optional[str]:
    for k in p:
        if k not in _ALLOWED[kind]:
            return f"unknown parameter '{k}' for '{kind}'"
    if kind == "log" and "sink" in p and not is_str(p["sink"], 128):
        return "log.sink must be a non-empty string of at most 128 characters"
    if kind == "notify" and not is_str(p.get("to"), 256):
        return "notify.to is required (a non-empty string of at most 256 characters)"
    if kind == "watermark" and not is_str(p.get("id"), 128):
        return "watermark.id is required (a non-empty string of at most 128 characters)"
    if kind == "redact":
        f = p.get("fields")
        if not isinstance(f, list) or not 0 < len(f) <= _MAX_REDACT_FIELDS or not all(isinstance(x, str) and _FIELD_RE.fullmatch(x) for x in f):
            return "redact.fields must be 1..32 dotted field paths"
        if len(set(f)) != len(f):
            return "redact.fields has a duplicate"
    return None


def obligation_error(o: Any) -> Optional[str]:
    """None = well formed."""
    if not is_obj(o):
        return "an obligation must be an object"
    for k in o:
        if k not in ("kind", "params", "due"):
            return f"unknown member '{k}'"
    kind = o.get("kind")
    if not isinstance(kind, str) or kind not in OBLIGATION_KINDS:
        return f"unknown obligation kind '{kind}'"
    if "due" in o and not is_uint(o["due"]):
        return "due must be a non-negative safe integer"
    p = o["params"] if "params" in o else {}
    if not is_obj(p):
        return "params must be an object"
    return _params_error(kind, p)


def obligation_key(o: dict) -> str:
    """The canonical identity of an obligation (kind, parameters, due). Raises TypeError outside the strict profile."""
    params = o.get("params")
    body = {"kind": o["kind"], "params": {} if params is None else params}
    if "due" in o:
        body["due"] = o["due"]
    return canonicalize_strict(body)


def obligations_error(lst: Any) -> Optional[str]:
    """None = a well-formed, duplicate-free list of at most 16. Absent (None) is the empty list."""
    if lst is None:
        return None
    if not isinstance(lst, list):
        return "obligations must be an array"
    if len(lst) > MAX_OBLIGATIONS:
        return f"more than {MAX_OBLIGATIONS} obligations"
    seen = set()
    for i, o in enumerate(lst):
        e = obligation_error(o)
        if e:
            return f"obligations[{i}]: {e}"
        try:
            key = obligation_key(o)
        except Exception:
            return f"obligations[{i}]: not canonicalizable"
        if key in seen:
            return f"obligations[{i}] duplicates an earlier obligation"
        seen.add(key)
    return None


def merge_obligations(*lists: Any) -> dict:
    """The union of obligation lists, deduplicated by key and sorted by key in UTF-8 byte order."""
    try:
        by: Dict[str, dict] = {}
        for l in lists:
            e = obligations_error(l)
            if e:
                return {"ok": False, "reason": e}
            for o in (l or []):
                by[obligation_key(o)] = o
        if len(by) > MAX_OBLIGATIONS:
            return {"ok": False, "reason": f"more than {MAX_OBLIGATIONS} obligations after merging"}
        return {"ok": True, "obligations": [by[k] for k in sorted(by, key=lambda s: s.encode("utf-8"))]}
    except Exception:
        return {"ok": False, "reason": "evaluation error (fail closed)"}


def _gate_deny(reason: Optional[str] = None, unsupported: Optional[List[str]] = None) -> dict:
    r = {"decision": "deny", "perform": [], "unsupported": unsupported or []}
    if reason:
        r["reason"] = reason
    return r


def pep_obligation_gate(decision: Any, answered: Any, obligations: Any, supported: Any) -> dict:
    try:
        eff = pep_decision(decision, answered)
        if eff != "allow":
            return {"decision": "escalate" if eff == "escalate" else "deny", "perform": [], "unsupported": []}
        e = obligations_error(obligations)
        if e:
            return _gate_deny(f"malformed obligations: {e}")
        if not isinstance(supported, list) or not all(isinstance(s, str) for s in supported):
            return _gate_deny("the supported obligation kinds are malformed")
        lst = obligations or []
        missing = sorted({o["kind"] for o in lst if o["kind"] not in supported}, key=lambda s: s.encode("utf-8"))
        if missing:
            return _gate_deny("the enforcement point does not support obligation(s) " + ", ".join(missing), missing)
        return {"decision": "allow", "perform": lst, "unsupported": []}
    except Exception:
        return _gate_deny("evaluation error (fail closed)")


def obligation_outcome(obligations: Any, fulfilled: Any, now: Any) -> dict:
    try:
        lst = obligations if isinstance(obligations, list) else []
        bad = obligations_error(obligations) is not None or not isinstance(fulfilled, list) or not all(is_uint(i) for i in fulfilled) or not is_uint(now)
        if bad:
            return {"outcome": "escalate", "overdue": list(range(len(lst))), "status": "obligation_unmet"}
        done = set(fulfilled)
        overdue = [i for i, o in enumerate(lst) if "due" in o and o["due"] <= now and i not in done]
        return {"outcome": "escalate", "overdue": overdue, "status": "obligation_unmet"} if overdue else {"outcome": "ok", "overdue": []}
    except Exception:
        return {"outcome": "escalate", "overdue": [], "status": "obligation_unmet"}
