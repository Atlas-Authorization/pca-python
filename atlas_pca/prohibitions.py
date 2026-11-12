"""The veto-polarity trigger of the prohibition language (the part of ``prohibitions.ts`` that forbid-wins policies and constitutions share):
``validate_when``, ``when_matches`` and ``when_affirmative``.

A trigger is ``{"verb", "resource"?, "where"?}``, the same shape as a permission predicate. ``when_matches`` is the VETO reading: fully
fail-closed, so a malformed trigger, an unsafe or oversized regex, an unknown op, a missing field or operand, unavailable params or
incomparable operands all count as MATCHED (the veto applies); it never raises. ``when_affirmative`` is the plain permission reading
(anything that cannot be decided is not matched)."""
import math
from typing import Any, Dict, List, Optional

from .pca import _verify_b64u, b64u, hash_canonical, sha256
from . import ed25519
from .predicates import (
    _UNDEF,
    _is_num,
    _js_string,
    _jsnum,
    MAX_RE_RESOURCE_LEN,
    evaluate_condition,
    evaluate_condition_tri,
    is_safe_regex_source,
    predicate_matches,
    resolve_path,
)
from .safe_regex import regex_refusals, utf16_len, with_regex_budget

_MAX_CONDITION_DEPTH = 32
_OPS = ("eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of")


def _has(o: Any, k: str) -> bool:
    return isinstance(o, dict) and k in o


def validate_condition(c: Any, depth: int = 0) -> Optional[str]:
    """The structural problem of a condition (None = well formed): a leaf, or an all_of / any_of / not grouping."""
    if not isinstance(c, dict):
        return "condition not an object"
    if depth > _MAX_CONDITION_DEPTH:
        return "condition nesting too deep"
    if _has(c, "all_of") or _has(c, "any_of") or _has(c, "not"):
        if _has(c, "not"):
            return validate_condition(c["not"], depth + 1)
        key = "all_of" if _has(c, "all_of") else "any_of"
        arr = c[key]
        if not isinstance(arr, list) or len(arr) == 0:
            return "condition.%s must be a non-empty array" % key
        for child in arr:
            e = validate_condition(child, depth + 1)
            if e:
                return e
        return None
    if not isinstance(c.get("field"), str) or not c["field"]:
        return "condition.field missing"
    if not isinstance(c.get("op"), str) or c["op"] not in _OPS:
        return "unknown condition op %s" % _js_string(c.get("op", _UNDEF))
    if "ref" in c and (not isinstance(c["ref"], str) or not c["ref"]):
        return "bad condition.ref"
    if c["op"] == "member_of" and "collection" in c and (not isinstance(c["collection"], str) or not c["collection"]):
        return "bad condition.collection"
    return None


def validate_when(w: Any, label: str) -> Optional[str]:
    """The structural problem of a trigger (None = well formed)."""
    if not isinstance(w, dict):
        return "%s: not an object" % label
    v = w.get("verb")
    verb_ok = (isinstance(v, str) and len(v) > 0) or (isinstance(v, list) and len(v) > 0 and all(isinstance(x, str) and len(x) > 0 for x in v))
    if not verb_ok:
        return "%s: bad verb" % label
    if "resource" in w:
        if not isinstance(w["resource"], str):
            return "%s: bad resource" % label
        if w["resource"].startswith("re:"):
            src = w["resource"][3:]
            # an unsafe, over-long or uncompilable regex would make the matcher return false: the veto would silently NOT apply
            if utf16_len(src) > 200 or not is_safe_regex_source(src):
                return "%s: unsafe regex resource" % label
    if "where" in w:
        if not isinstance(w["where"], list):
            return "%s: where not an array" % label
        for c in w["where"]:
            e = validate_condition(c)
            if e:
                return "%s: %s" % (label, e)
    return None


def when_matches(w: Any, ctx: Any) -> bool:
    """Does a prohibition trigger match? Verb and resource exactly as the permission DSL, the where-conditions conservatively; every
    failure to decide counts as MATCHED (the veto applies). Never raises."""
    try:
        if validate_when(w, "when"):
            return True
        a = ctx.get("action") if isinstance(ctx, dict) else None
        if not isinstance(a, dict) or not isinstance(a.get("verb"), str) or not isinstance(a.get("resource"), str):
            return True
        oversized = isinstance(w.get("resource"), str) and w["resource"].startswith("re:") and len(a["resource"]) > MAX_RE_RESOURCE_LEN
        # an oversized subject for a regex resource: the matcher would say "no match", a veto must say "match"; a regex evaluation REFUSED
        # by the document budget is "could not decide", never "no match"
        refused0 = regex_refusals()
        trigger = {"verb": w["verb"]}
        if not oversized and "resource" in w:
            trigger["resource"] = w["resource"]
        if not predicate_matches(trigger, ctx):
            if regex_refusals() == refused0:
                return False
        for c in w.get("where") or []:
            if evaluate_condition_tri(c, ctx) == "false":
                return False
        return True
    except Exception:  # noqa: BLE001 - cannot evaluate: the veto applies
        return True


def when_affirmative(w: Any, ctx: Any) -> bool:
    """AFFIRMATIVE trigger match (plain permission semantics, unresolvable = not matched)."""
    try:
        return validate_when(w, "when") is None and predicate_matches(w, ctx)
    except Exception:  # noqa: BLE001
        return False


# ---- the full engine: constitution, monitor state, evidence (port of the rest of prohibitions.ts) ---------------------------------

CONSTITUTION_VERSION = 1
CONSTITUTION_SIG_DOMAIN = "atlas-pca/constitution/v1\0"
EVIDENCE_VERSION = 1
SAFETY_EVIDENCE_SIG_DOMAIN = "atlas-pca/safety-evidence/v1\0"
STATE_DIGEST_DOMAIN = "atlas-pca/monitor-state/v1"
STATE_CHAIN_DOMAIN = "atlas-pca/monitor-state-link/v1"
MAX_LEDGER = 10_000
MAX_INVARIANTS = 256
MAX_DEADLINE = 1_000_000
_MAX_STATE_ENTRIES = 100_000
_MAX_STATE_KEYS = 1024
_MAX_ID_LEN = 128
_FORBIDDEN_IDS = ("__proto__", "constructor", "prototype")
UNHASHABLE = "<unhashable>"
_DEFAULT = object()


def _is_obj(x: Any) -> bool:
    return isinstance(x, dict)


def _fin(x: Any) -> bool:
    """`typeof x === 'number' && Number.isFinite(x)` (a bool is not a number)."""
    return _is_num(x) and math.isfinite(_jsnum(x))


def _is_integer(x: Any) -> bool:
    """`Number.isInteger(x)`."""
    return _fin(x) and _jsnum(x) == math.floor(_jsnum(x))


def _neg_zero(x: Any) -> bool:
    return isinstance(x, float) and x == 0 and math.copysign(1.0, x) < 0


def _prop(o: Any, k: str) -> Any:
    """JS `o.k`: undefined (None here) on a non-object, a TypeError on null."""
    if o is None:
        raise TypeError("cannot read properties of null")
    return o.get(k) if isinstance(o, dict) else None


def _n(x: Any) -> str:
    return _js_string(x)


def _truthy(v: Any) -> bool:
    if v is None or v is False or v is _UNDEF:
        return False
    if _is_num(v):
        return v != 0 and v == v
    if isinstance(v, str):
        return len(v) > 0
    return True


def _text(v: Any) -> str:
    """The `String(x)` of a JSON value, `undefined` for an absent one."""
    return _js_string(v)


def empty_state(now: Any) -> Dict[str, Any]:
    """Genesis monitor state at time `now`: empty ledger, no latches, seq 0, no parent."""
    return {"now": now, "seq": 0, "parent": None, "ledger": {}, "latched": {}}


def _body(c: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in c.items() if k not in ("id", "sig")}


def _domain_message(domain: str, id_: str) -> bytes:
    return domain.encode("utf-8") + sha256(id_.encode("utf-8", "surrogatepass"))


def constitution_id(c: Dict[str, Any]) -> str:
    """Content address of a constitution body. Raises only on non-canonicalizable input (authoring time)."""
    return hash_canonical(_body(c))


def sign_constitution(c: Dict[str, Any], principal_seed: bytes) -> Dict[str, Any]:
    problems = validate_constitution(c)
    if problems:
        raise TypeError("signConstitution: " + "; ".join(problems))
    id_ = constitution_id(c)
    return {**_body(c), "id": id_, "sig": b64u(ed25519.sign(principal_seed, _domain_message(CONSTITUTION_SIG_DOMAIN, id_)))}


def verify_constitution(sc: Any, expected_principal: Optional[str] = None) -> Dict[str, Any]:
    """Well-formed, id matches content, signature by `expected_principal` (or the embedded one). Never raises."""
    try:
        problems = validate_constitution(sc)
        if problems:
            return {"ok": False, "reason": problems[0]}
        if expected_principal is not None and sc["principal"] != expected_principal:
            return {"ok": False, "reason": "principal mismatch"}
        if not isinstance(sc.get("id"), str) or sc["id"] != constitution_id(sc):
            return {"ok": False, "reason": "id does not match content"}
        if not isinstance(sc.get("sig"), str) or not _verify_b64u(sc["principal"], _domain_message(CONSTITUTION_SIG_DOMAIN, sc["id"]), sc["sig"]):
            return {"ok": False, "reason": "bad signature"}
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "verification error (fail closed)"}


def _validate_conditions(cs: Any, label: str) -> Optional[str]:
    if not isinstance(cs, list) or len(cs) == 0:
        return "%s must be a non-empty array" % label
    for c in cs:
        e = validate_condition(c)
        if e:
            return e
    return None


def _action_path(v: Any) -> bool:
    return isinstance(v, str) and v.startswith("action.")


def validate_invariant(inv: Any) -> List[str]:
    """Structural problems with an invariant (empty = well-formed)."""
    if not _is_obj(inv):
        return ["invariant not an object"]
    raw_id = inv.get("id")
    if not isinstance(raw_id, str) or not raw_id:
        return ["<no id>: missing id"]
    id_ = raw_id

    def err(m: str) -> List[str]:
        return ["%s: %s" % (id_, m)]

    if utf16_len(id_) > _MAX_ID_LEN:
        return err("id too long")
    if id_ in _FORBIDDEN_IDS:
        return err("forbidden id")
    kind = inv.get("kind", _UNDEF)
    if kind == "never":
        e = validate_when(inv.get("when"), "when")
        return err(e) if e else []
    if kind == "never_unless":
        e = validate_when(inv.get("when"), "when")
        if e:
            return err(e)
        e = _validate_conditions(inv.get("unless"), "unless")
        if e:
            return err(e)
        return []
    if kind == "cap":
        e = validate_when(inv.get("when"), "when")
        if e:
            return err(e)
        if not _action_path(inv.get("amount")):
            return err("amount must be an action.* path")
        if not _fin(inv.get("max")) or inv["max"] < 0:
            return err("max must be a finite number >= 0")
        if "window_secs" in inv and (not _fin(inv["window_secs"]) or inv["window_secs"] <= 0):
            return err("bad window_secs")
        return []
    if kind == "rate":
        e = validate_when(inv.get("when"), "when")
        if e:
            return err(e)
        m = inv.get("max")
        if not _is_integer(m) or m < 0 or _neg_zero(m) or m > MAX_LEDGER:
            return err("max must be an integer in [0,10000]")
        if not _fin(inv.get("window_secs")) or inv["window_secs"] <= 0:
            return err("window_secs must be > 0")
        return []
    if kind == "never_after":
        e = validate_when(inv.get("after"), "after") or validate_when(inv.get("forbid"), "forbid")
        return err(e) if e else []
    if kind == "require_prior":
        e = validate_when(inv.get("when"), "when") or validate_when(inv.get("prior"), "prior")
        return err(e) if e else []
    if kind == "require_approval_over":
        e = validate_when(inv.get("when"), "when")
        if e:
            return err(e)
        if not _action_path(inv.get("amount")):
            return err("amount must be an action.* path")
        if not _fin(inv.get("threshold")) or inv["threshold"] < 0:
            return err("threshold must be a finite number >= 0")
        e = _validate_conditions(inv.get("approved"), "approved")
        if e:
            return err(e)
        return []
    return err("unknown invariant kind %s" % _text(kind))


def validate_constitution(c: Any) -> List[str]:
    """Structural problems with a constitution (empty = well-formed)."""
    if not _is_obj(c):
        return ["constitution not an object"]
    out: List[str] = []
    version = c.get("version")
    if not (_is_num(version) and version == CONSTITUTION_VERSION):
        out.append("unsupported version %s" % _text(c.get("version", _UNDEF)))
    if not isinstance(c.get("principal"), str) or not c["principal"]:
        out.append("principal missing")
    invs = c.get("invariants")
    if not isinstance(invs, list):
        return out + ["invariants not an array"]
    if len(invs) > MAX_INVARIANTS:
        out.append("too many invariants")
    seen = set()
    for inv in invs:
        out.extend(validate_invariant(inv))
        id_ = inv.get("id") if _is_obj(inv) else None
        if isinstance(id_, str):
            if id_ in seen:
                out.append("%s: duplicate id" % id_)
            seen.add(id_)
    return out


# ---- canonical monitor state ---------------------------------------------------------------------------------------------------

def state_problem(state: Any) -> Optional[str]:
    """Structural problem with a monitor state (None = well-formed). Total; never raises."""
    try:
        if not _is_obj(state) or not _fin(state.get("now")) or not _is_obj(state.get("ledger")) or not _is_obj(state.get("latched")):
            return "malformed monitor state"
        seq = state.get("seq")
        if not _is_integer(seq) or seq < 0 or _neg_zero(seq):
            return "malformed monitor state: seq"
        parent = state.get("parent", _UNDEF)
        if parent is not None and not isinstance(parent, str):
            return "malformed monitor state: parent"
        if seq == 0 and parent is not None:
            return "malformed monitor state: genesis has a parent"
        if seq > 0 and parent is None:
            return "malformed monitor state: missing chain link"
        now = state["now"]
        if len(state["ledger"]) > _MAX_STATE_KEYS or len(state["latched"]) > _MAX_STATE_KEYS:
            return "malformed monitor state: too many keys"
        total = 0
        for k, l in state["ledger"].items():
            if k in _FORBIDDEN_IDS or utf16_len(k) > _MAX_ID_LEN:
                return "malformed monitor state: bad ledger key"
            if not isinstance(l, list) or len(l) > MAX_LEDGER:
                return "malformed monitor state: bad ledger"
            total += len(l)
            for e in l:
                if not _is_obj(e) or not _fin(e.get("t")) or not _fin(e.get("amount")) or e["amount"] < 0:
                    return "malformed monitor state: bad ledger entry"
                # an entry from the "future" would be ignored by the window and so UNDER-count: refuse (clock regression)
                if e["t"] > now:
                    return "malformed monitor state: ledger entry after now (clock regression)"
        if total > _MAX_STATE_ENTRIES:
            return "malformed monitor state: too many entries"
        for k, t in state["latched"].items():
            if k in _FORBIDDEN_IDS or utf16_len(k) > _MAX_ID_LEN:
                return "malformed monitor state: bad latch key"
            if not _fin(t) or t > now:
                return "malformed monitor state: bad latch"
        if "deadlines" in state:
            dl = state["deadlines"]
            if not _is_obj(dl):
                return "malformed monitor state: deadlines"
            if len(dl) > _MAX_STATE_KEYS:
                return "malformed monitor state: too many deadline keys"
            for k, d in dl.items():
                if k in _FORBIDDEN_IDS or utf16_len(k) > _MAX_ID_LEN:
                    return "malformed monitor state: bad deadline key"
                if not _is_integer(d) or d < 1 or d > MAX_DEADLINE:
                    return "malformed monitor state: bad deadline"
        return None
    except Exception:  # noqa: BLE001
        return "malformed monitor state"


def _entry_key(e: Dict[str, Any]):
    return (e["t"], e["amount"])


def canonical_state(state: Any) -> Dict[str, Any]:
    """Canonical form of a state: unknown fields dropped, ledger entries reduced to {t, amount} and sorted, empty ledger arrays
    omitted. Raises TypeError on a malformed state."""
    p = state_problem(state)
    if p:
        raise TypeError(p)
    ledger: Dict[str, Any] = {}
    for k, v in state["ledger"].items():
        l = sorted(({"t": e["t"], "amount": e["amount"]} for e in v), key=_entry_key)
        if l:
            ledger[k] = l
    base = {"d": STATE_DIGEST_DOMAIN, "now": state["now"], "seq": state["seq"], "parent": state["parent"], "ledger": ledger, "latched": dict(state["latched"])}
    if "deadlines" in state:
        deadlines = dict(state["deadlines"])
        if deadlines:
            base["deadlines"] = deadlines
    return base


def state_digest(state: Any) -> str:
    return hash_canonical(canonical_state(state))


def tick_state(state: Any, now: Any) -> Dict[str, Any]:
    """The same state at a later `now`; refuses regression. Never raises."""
    if state_problem(state):
        return {"ok": False, "reason": "malformed monitor state"}
    if not _fin(now) or now < state["now"]:
        return {"ok": False, "reason": "clock regression"}
    return {"ok": True, "state": {**state, "now": now}}


# ---- the monitor ---------------------------------------------------------------------------------------------------------------

def _all_hold(cs: List[Any], ctx: Any) -> bool:
    return all(evaluate_condition(c, ctx) for c in cs)


def _window_entries(state: Dict[str, Any], id_: str, window_secs: Any) -> List[Dict[str, Any]]:
    l = state["ledger"].get(id_)
    if not isinstance(l, list):
        return []
    lo = -math.inf if window_secs is None else state["now"] - window_secs * 1000
    return sorted((e for e in l if e["t"] > lo and e["t"] <= state["now"]), key=_entry_key)


def _reason(inv: Dict[str, Any], default: str) -> str:
    d = inv.get("description")
    return default if d is None else d


def _eval_one(inv: Dict[str, Any], ctx: Any, state: Dict[str, Any]) -> Dict[str, Any]:
    kind = inv["kind"]
    if kind == "never":
        return {"ok": False, "reason": _reason(inv, "forbidden action")} if when_matches(inv["when"], ctx) else {"ok": True}
    if kind == "never_unless":
        if not when_matches(inv["when"], ctx):
            return {"ok": True}
        # exceptions must hold AFFIRMATIVELY (unresolvable => false => still forbidden)
        return {"ok": True} if _all_hold(inv["unless"], ctx) else {"ok": False, "reason": _reason(inv, "forbidden without required condition")}
    if kind == "cap":
        if not when_matches(inv["when"], ctx):
            return {"ok": True}
        a = resolve_path(ctx, inv["amount"])
        if not a["found"] or not _fin(a["value"]) or a["value"] < 0:
            return {"ok": False, "reason": "amount unresolvable (fail closed)"}
        spent = 0.0
        for e in _window_entries(state, inv["id"], inv.get("window_secs")):
            spent += _jsnum(e["amount"])
        total = spent + _jsnum(a["value"])
        if total <= _jsnum(inv["max"]):
            return {"ok": True}
        return {"ok": False, "reason": "cap exceeded: %s + %s > %s" % (_n(spent), _n(a["value"]), _n(inv["max"]))}
    if kind == "rate":
        if not when_matches(inv["when"], ctx):
            return {"ok": True}
        n = len(_window_entries(state, inv["id"], inv.get("window_secs")))
        if n + 1 <= inv["max"]:
            return {"ok": True}
        return {"ok": False, "reason": "rate exceeded: %d > %s per %ss" % (n + 1, _n(inv["max"]), _n(inv["window_secs"]))}
    if kind == "never_after":
        if inv["id"] not in state["latched"] or not when_matches(inv["forbid"], ctx):
            return {"ok": True}
        return {"ok": False, "reason": _reason(inv, "forbidden after trigger")}
    if kind == "require_prior":
        if not when_matches(inv["when"], ctx):
            return {"ok": True}
        return {"ok": True} if inv["id"] in state["latched"] else {"ok": False, "reason": _reason(inv, "required prior action not admitted")}
    if kind == "require_approval_over":
        if not when_matches(inv["when"], ctx):
            return {"ok": True}
        a = resolve_path(ctx, inv["amount"])
        over = not a["found"] or not _fin(a["value"]) or a["value"] < 0 or a["value"] > inv["threshold"]
        if not over:
            return {"ok": True}
        return {"ok": True} if _all_hold(inv["approved"], ctx) else {"ok": False, "reason": _reason(inv, "approval required over %s" % _n(inv["threshold"]))}
    raise ValueError("unknown invariant kind")  # unreachable after validation; the caller turns it into a fail-closed row


def check_prohibitions(action: Any, constitution: Any, state: Any) -> Dict[str, Any]:
    """Evaluate EVERY invariant (no short-circuit) against the action and running state. Pure, total, fail-closed."""
    return with_regex_budget(lambda: _check_prohibitions_inner(action, constitution, state))


def _action_ok(action: Any) -> bool:
    a = action.get("action") if isinstance(action, dict) else None
    return isinstance(a, dict) and isinstance(a.get("verb"), str) and isinstance(a.get("resource"), str)


def _check_prohibitions_inner(action: Any, constitution: Any, state: Any) -> Dict[str, Any]:
    def fail(id_: str, reason: str) -> Dict[str, Any]:
        return {"ok": False, "violated": [id_], "reasons": [reason], "evaluated": [{"id": id_, "kind": "structural", "result": "violated", "reason": reason}]}

    try:
        cp = validate_constitution(constitution)
        if cp:
            return fail("<constitution>", cp[0])
        if not _action_ok(action):
            return fail("<action>", "malformed action")
        sp = state_problem(state)
        if sp:
            return fail("<state>", sp)
        evaluated: List[Dict[str, Any]] = []
        for inv in constitution["invariants"]:
            try:
                r = _eval_one(inv, action, state)
            except Exception:  # noqa: BLE001
                r = {"ok": False, "reason": "evaluation error (fail closed)"}
            row = {"id": inv["id"], "kind": inv["kind"], "result": "pass" if r["ok"] else "violated"}
            if _truthy(r.get("reason")):
                row["reason"] = r["reason"]
            evaluated.append(row)
        bad = [e for e in evaluated if e["result"] == "violated"]
        return {"ok": len(bad) == 0, "violated": [e["id"] for e in bad],
                "reasons": ["%s: %s" % (e["id"], _text(e["reason"]) if "reason" in e else "violated") for e in bad], "evaluated": evaluated}
    except Exception:  # noqa: BLE001
        return fail("<monitor>", "monitor error (fail closed)")


def advance_state_strict(action: Any, constitution: Any, state: Any, now: Any = _DEFAULT) -> Dict[str, Any]:
    """Pure state transition for an ADMITTED action; `{"ok": False, "reason"}` on anything it cannot record faithfully. Never raises."""
    if now is _DEFAULT:
        now = state.get("now") if isinstance(state, dict) else None
    return with_regex_budget(lambda: _advance_inner(action, constitution, state, now))


def _advance_inner(action: Any, constitution: Any, state: Any, now: Any) -> Dict[str, Any]:
    try:
        cp = validate_constitution(constitution)
        if cp:
            return {"ok": False, "reason": cp[0]}
        sp = state_problem(state)
        if sp:
            return {"ok": False, "reason": sp}
        if not _fin(now) or now < state["now"]:
            return {"ok": False, "reason": "clock regression"}
        if not _action_ok(action):
            return {"ok": False, "reason": "malformed action"}
        canon = canonical_state(state)
        prev_digest = hash_canonical(canon)
        action_digest = hash_canonical(action)
        ledger: Dict[str, Any] = {k: list(v) for k, v in canon["ledger"].items()}
        latched: Dict[str, Any] = dict(canon["latched"])
        for inv in constitution["invariants"]:
            if inv["kind"] in ("cap", "rate"):
                prev = ledger.get(inv["id"], [])
                lo = -math.inf if inv.get("window_secs") is None else now - inv["window_secs"] * 1000
                kept = [e for e in prev if e["t"] > lo]
                if when_matches(inv["when"], action):
                    amount: Any = 1
                    if inv["kind"] == "cap":
                        r = resolve_path(action, inv["amount"])
                        if not r["found"] or not _fin(r["value"]) or r["value"] < 0:
                            return {"ok": False, "reason": "%s: amount unresolvable" % inv["id"]}
                        amount = r["value"]
                    kept.append({"t": now, "amount": amount})
                kept.sort(key=_entry_key)
                if len(kept) > MAX_LEDGER:
                    if inv["kind"] == "rate":
                        return {"ok": False, "reason": "%s: rate ledger overflow" % inv["id"]}
                    while len(kept) > MAX_LEDGER:
                        x, y = kept[0], kept[1]  # merge oldest two; keeps the LATER time => never under-counts a cap
                        kept[:2] = [{"t": y["t"], "amount": _sum_amount(x["amount"], y["amount"])}]
                if kept:
                    ledger[inv["id"]] = kept
                else:
                    ledger.pop(inv["id"], None)
            elif inv["kind"] == "never_after":
                # conservative match: an ambiguous trigger latches (stricter)
                if inv["id"] not in latched and when_matches(inv["after"], action):
                    latched[inv["id"]] = now
            elif inv["kind"] == "require_prior":
                # AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
                if inv["id"] not in latched and when_affirmative(inv["prior"], action):
                    latched[inv["id"]] = now
        nxt = {"now": now, "seq": state["seq"] + 1, "parent": hash_canonical({"d": STATE_CHAIN_DOMAIN, "state": prev_digest, "action": action_digest}),
               "ledger": ledger, "latched": latched}
        if state_problem(nxt):
            return {"ok": False, "reason": "resulting state invalid"}
        return {"ok": True, "state": nxt}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "advance error (fail closed)"}


def _sum_amount(a: Any, b: Any) -> Any:
    s = _jsnum(a) + _jsnum(b)
    return int(s) if s == math.floor(s) and abs(s) <= 2 ** 53 else s


def advance_state(action: Any, constitution: Any, state: Any, now: Any = _DEFAULT) -> Any:
    """`advance_state_strict` that returns the INPUT state unchanged on failure."""
    r = advance_state_strict(action, constitution, state, now)
    return r["state"] if r["ok"] else state


# ---- per-action safety evidence ------------------------------------------------------------------------------------------------

def _safe(f: Any) -> str:
    try:
        return f()
    except Exception:  # noqa: BLE001
        return UNHASHABLE


def prove_safety(action: Any, constitution: Any, state: Any) -> Dict[str, Any]:
    """Build the evidence a verifier re-checks. Never raises."""
    return _evidence_from(check_prohibitions(action, constitution, state), action, constitution, state)


def _evidence_from(r: Dict[str, Any], action: Any, constitution: Any, state: Any) -> Dict[str, Any]:
    cid = _safe(lambda: constitution_id(constitution))
    adg = _safe(lambda: hash_canonical(action))
    sdg = _safe(lambda: state_digest(state))
    extra = []
    if cid == UNHASHABLE:
        extra.append("<constitution>")
    if adg == UNHASHABLE:
        extra.append("<action>")
    if sdg == UNHASHABLE:
        extra.append("<state>")
    return {
        "v": EVIDENCE_VERSION, "constitution": cid, "action_digest": adg, "state_digest": sdg,
        "now": state["now"] if isinstance(state, dict) and _fin(state.get("now")) else 0,
        "evaluated": [dict(e) for e in r["evaluated"]],
        "ok": r["ok"] and len(extra) == 0,
        "violated": list(r["violated"]) + [x for x in extra if x not in r["violated"]],
    }


def evidence_digest(e: Any) -> str:
    return hash_canonical(e)


def verify_safety_evidence(evidence: Any, action: Any, constitution: Any, state: Any) -> Dict[str, Any]:
    """Recompute the monitor and require the evidence to match EXACTLY. Never raises."""
    try:
        if not _is_obj(evidence) or evidence.get("v") != EVIDENCE_VERSION:
            return {"ok": False, "reason": "unsupported evidence version"}
        fresh = prove_safety(action, constitution, state)
        if fresh["constitution"] != evidence.get("constitution"):
            return {"ok": False, "reason": "constitution mismatch"}
        if fresh["action_digest"] != evidence.get("action_digest"):
            return {"ok": False, "reason": "action digest mismatch"}
        if fresh["state_digest"] != evidence.get("state_digest"):
            return {"ok": False, "reason": "state digest mismatch"}
        if hash_canonical(fresh) != hash_canonical(evidence):
            return {"ok": False, "reason": "evidence does not reproduce"}
        if not fresh["ok"]:
            return {"ok": False, "reason": "prohibition violated: " + ",".join(fresh["violated"])}
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "verification error (fail closed)"}


def safety_binding_id(evidence: Dict[str, Any], signer: str) -> str:
    return hash_canonical({"d": SAFETY_EVIDENCE_SIG_DOMAIN, "signer": signer, "evidence": hash_canonical(evidence),
                           "constitution": evidence["constitution"], "action_digest": evidence["action_digest"], "state_digest": evidence["state_digest"]})


def sign_safety_evidence(evidence: Any, signer_seed: bytes, signer_public: str) -> Dict[str, Any]:
    if not _is_obj(evidence) or evidence.get("v") != EVIDENCE_VERSION:
        raise TypeError("signSafetyEvidence: unsupported evidence")
    for d in (evidence.get("constitution"), evidence.get("action_digest"), evidence.get("state_digest")):
        if not isinstance(d, str) or not d or d == UNHASHABLE:
            raise TypeError("signSafetyEvidence: unbound evidence")
    if not isinstance(signer_public, str) or not signer_public:
        raise TypeError("signSafetyEvidence: signer missing")
    id_ = safety_binding_id(evidence, signer_public)
    return {"evidence": evidence, "signer": signer_public, "id": id_, "sig": b64u(ed25519.sign(signer_seed, _domain_message(SAFETY_EVIDENCE_SIG_DOMAIN, id_)))}


def verify_signed_safety_evidence(signed: Any, expected: Any) -> Dict[str, Any]:
    """Verify signed evidence offline (signer pinned, binding id, signature, bound digests, internal consistency, full recomputation)."""
    def no(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}

    try:
        if not _is_obj(signed) or not _is_obj(signed.get("evidence")) or not _is_obj(expected):
            return no("malformed input")
        ev = signed["evidence"]
        if ev.get("v") != EVIDENCE_VERSION:
            return no("unsupported evidence version")
        signers = expected.get("signer") if isinstance(expected.get("signer"), list) else [expected.get("signer")]
        if not signers or any(not isinstance(s, str) or not s for s in signers):
            return no("no pinned signer")
        if not isinstance(signed.get("signer"), str) or signed["signer"] not in signers:
            return no("signer not trusted")
        if "action" not in expected and "actionDigest" not in expected:
            return no("unbound: action not specified")
        if "constitution" not in expected and "constitutionId" not in expected:
            return no("unbound: constitution not specified")
        if "state" not in expected and "stateDigest" not in expected:
            return no("unbound: state not specified")
        if not isinstance(signed.get("id"), str) or signed["id"] != safety_binding_id(ev, signed["signer"]):
            return no("binding id mismatch")
        if not isinstance(signed.get("sig"), str) or not _verify_b64u(signed["signer"], _domain_message(SAFETY_EVIDENCE_SIG_DOMAIN, signed["id"]), signed["sig"]):
            return no("bad signature")

        want_action = hash_canonical(expected["action"]) if "action" in expected else expected["actionDigest"]
        if "action" in expected and "actionDigest" in expected and expected["actionDigest"] != want_action:
            return no("expected action and digest disagree")
        if ev.get("action_digest") != want_action:
            return no("action digest mismatch (evidence bound to another action)")

        if "principal" in expected:
            sc = expected.get("constitution")
            if not _is_obj(sc) or not isinstance(sc.get("sig"), str):
                return no("principal pin requires a signed constitution")
            vc = verify_constitution(sc, expected["principal"])
            if not vc["ok"]:
                return no("constitution not authentic: " + _text(vc.get("reason", _UNDEF)))
        want_const = constitution_id(expected["constitution"]) if "constitution" in expected else expected["constitutionId"]
        if "constitution" in expected and "constitutionId" in expected and expected["constitutionId"] != want_const:
            return no("expected constitution and id disagree")
        if ev.get("constitution") != want_const:
            return no("constitution mismatch (evidence bound to another constitution)")
        # a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row
        if "constitution" in expected:
            cp = validate_constitution(expected["constitution"])
            if cp:
                return no("constitution malformed: " + cp[0])

        want_state = state_digest(expected["state"]) if "state" in expected else expected["stateDigest"]
        if "state" in expected and "stateDigest" in expected and expected["stateDigest"] != want_state:
            return no("expected state and digest disagree")
        if ev.get("state_digest") != want_state:
            return no("state digest mismatch (evidence bound to another state)")

        if not isinstance(ev.get("evaluated"), list) or not isinstance(ev.get("violated"), list):
            return no("malformed evidence")
        if any(_is_obj(r) and "id" in r and not isinstance(r["id"], str) for r in ev["evaluated"]):
            return no("malformed evidence")
        bad_rows = [r for r in ev["evaluated"] if not (_is_obj(r) and r.get("result") == "pass")]
        if ev.get("ok") is not (len(bad_rows) == 0 and len(ev["violated"]) == 0):
            return no("evidence verdict inconsistent with rows")

        if "action" in expected and "constitution" in expected and "state" in expected:
            full = verify_safety_evidence(ev, expected["action"], expected["constitution"], expected["state"])
            if not full["ok"] and ev["ok"]:
                return no(full.get("reason") or "evidence does not reproduce")
            if not full["ok"] and not ev["ok"] and full.get("reason") is not None and not full["reason"].startswith("prohibition violated"):
                return no(full["reason"])
        elif ev["ok"] and "constitution" in expected:
            ids = [_prop(i, "id") for i in expected["constitution"]["invariants"]]
            if len(ev["evaluated"]) != len(ids) or any(_prop(r, "id") != ids[i] for i, r in enumerate(ev["evaluated"])):
                return no("evidence does not cover every invariant")
        if expected.get("requireOk") is not False and not ev["ok"]:
            return no("prohibition violated: " + ",".join(ev["violated"]))
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return no("verification error (fail closed)")


# ---- composition: permissions grant, prohibitions veto -------------------------------------------------------------------------

def compose_authority(permitted: Any, action: Any, constitution: Any, state: Any) -> Dict[str, Any]:
    """allow = permitted AND prohibitions.ok; the monitor runs unconditionally so denial reasons are complete."""
    return _compose_from(permitted, check_prohibitions(action, constitution, state))


def _compose_from(permitted: Any, prohibition: Dict[str, Any]) -> Dict[str, Any]:
    p = permitted is True
    return {"allow": p and prohibition["ok"], "decidedBy": "prohibition" if not prohibition["ok"] else ("none" if p else "permission"),
            "permitted": p, "prohibition": prohibition}


def check_and_advance(permitted: Any, action: Any, constitution: Any, state: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The pure kernel of the server's critical section: CAS guards, compose, evidence over the pre-state, next state on allow.
    ``opts`` may carry ``expectedSeq`` and ``expectedStateDigest``. Never raises."""
    opts = opts or {}
    monitored = check_prohibitions(action, constitution, state)
    evidence = _evidence_from(monitored, action, constitution, state)
    decision = _compose_from(permitted, monitored)

    def refuse(decided_by: str, reason: Optional[str] = None) -> Dict[str, Any]:
        out = {"allow": False, "decidedBy": decided_by, "evidence": evidence, "prohibition": decision["prohibition"], "next": state}
        if reason:
            out["reason"] = reason
        return out

    try:
        if "expectedSeq" in opts and (not _is_obj(state) or state.get("seq") != opts["expectedSeq"]):
            return refuse("state", "stale state head (seq)")
        if "expectedStateDigest" in opts and _safe(lambda: state_digest(state)) != opts["expectedStateDigest"]:
            return refuse("state", "stale state head (digest)")
        if not decision["allow"]:
            return refuse("permission" if decision["decidedBy"] == "none" else decision["decidedBy"])
        if not evidence["ok"]:
            return refuse("prohibition", "evidence not attestable")
        adv = advance_state_strict(action, constitution, state)
        if not adv["ok"]:
            return refuse("state", "advance failed: " + adv["reason"])
        return {"allow": True, "decidedBy": "none", "evidence": evidence, "prohibition": decision["prohibition"], "next": adv["state"]}
    except Exception:  # noqa: BLE001
        return refuse("state", "check-and-advance error (fail closed)")
