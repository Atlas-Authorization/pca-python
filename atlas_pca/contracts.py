"""Bounded safety-LTL behavioural contracts (port of packages/pca/src/contracts.ts; the TypeScript is authoritative).

A contract is an optional embedded prohibition constitution (``invariants``) plus temporal ``clauses`` (always, never, precedes,
requires_prior, responds_within, and) over one shared, hash-chained monitor state. A contract without clauses behaves exactly like
the prohibition monitor. Everything malformed, unknown or unresolvable fails closed; nothing here raises."""
from typing import Any, Dict, List, Optional

from . import ed25519
from .pca import _verify_b64u, b64u, hash_canonical
from .predicates import _UNDEF, _js_string
from .prohibitions import (
    MAX_DEADLINE,
    MAX_INVARIANTS,
    _domain_message,
    _is_integer,
    _is_obj,
    _safe,
    _truthy,
    advance_state_strict,
    check_prohibitions,
    state_digest,
    state_problem,
    validate_invariant,
    validate_when,
    when_affirmative,
    when_matches,
)
from .safe_regex import utf16_len, with_regex_budget

CONTRACT_VERSION = 1
CONTRACT_SIG_DOMAIN = "atlas-pca/contract/v1\0"
MAX_CLAUSES = 256
MAX_CLAUSE_DEPTH = 16
_MAX_ID_LEN = 128
_FORBIDDEN_IDS = ("__proto__", "constructor", "prototype")


def validate_clause(cl: Any, seen: set, depth: int) -> List[str]:
    """Structural problems with a clause (empty = well-formed); collects ids into ``seen`` for global uniqueness."""
    if depth > MAX_CLAUSE_DEPTH:
        return ["clause nesting too deep"]
    if not _is_obj(cl):
        return ["clause not an object"]
    raw_id = cl.get("id")
    if not isinstance(raw_id, str) or not raw_id:
        return ["<no id>: missing clause id"]
    id_ = raw_id

    def err(m: str) -> List[str]:
        return ["%s: %s" % (id_, m)]

    if utf16_len(id_) > _MAX_ID_LEN:
        return err("id too long")
    if id_ in _FORBIDDEN_IDS:
        return err("forbidden id")
    if id_ in seen:
        return err("duplicate id")
    seen.add(id_)
    kind = cl.get("kind", _UNDEF)
    if kind in ("always", "never"):
        e = validate_when(cl.get("p"), "p")
        return err(e) if e else []
    if kind in ("precedes", "requires_prior"):
        e = validate_when(cl.get("p"), "p")
        if e:
            return err(e)
        e = validate_when(cl.get("q"), "q")
        if e:
            return err(e)
        return []
    if kind == "responds_within":
        e = validate_when(cl.get("p"), "p")
        if e:
            return err(e)
        e = validate_when(cl.get("q"), "q")
        if e:
            return err(e)
        within = cl.get("within")
        if not _is_integer(within) or within < 1 or within > MAX_DEADLINE:
            return err("within must be an integer in [1, MAX_DEADLINE]")
        return []
    if kind == "and":
        subs = cl.get("clauses")
        if not isinstance(subs, list) or len(subs) == 0:
            return err("and.clauses must be a non-empty array")
        out: List[str] = []
        for sub in subs:
            out.extend(validate_clause(sub, seen, depth + 1))
        return out
    return err("unknown clause kind %s" % _js_string(kind))


def _count_clauses(cls: List[Any], depth: int = 1) -> int:
    # bounded recursion: an absurdly deep nest is "too many" at once (validate_clause then reports the depth)
    if depth > MAX_CLAUSE_DEPTH + 1:
        return MAX_CLAUSES + 1
    n = 0
    for cl in cls:
        n += 1
        if _is_obj(cl) and cl.get("kind") == "and" and isinstance(cl.get("clauses"), list):
            n += _count_clauses(cl["clauses"], depth + 1)
    return n


def validate_contract(c: Any) -> List[str]:
    """Structural problems with a contract (empty = well-formed). Total."""
    if not _is_obj(c):
        return ["contract not an object"]
    out: List[str] = []
    version = c.get("version")
    if not (isinstance(version, (int, float)) and not isinstance(version, bool) and version == CONTRACT_VERSION):
        out.append("unsupported version %s" % _js_string(c.get("version", _UNDEF)))
    if not isinstance(c.get("principal"), str) or not c["principal"]:
        out.append("principal missing")
    ids: set = set()
    if "invariants" in c:
        invariants = c["invariants"]
        if not isinstance(invariants, list):
            return out + ["invariants not an array"]
        if len(invariants) > MAX_INVARIANTS:
            out.append("too many invariants")
        for inv in invariants:
            out.extend(validate_invariant(inv))
            id_ = inv.get("id") if _is_obj(inv) else None
            if isinstance(id_, str):
                if id_ in ids:
                    out.append("%s: duplicate id" % id_)
                ids.add(id_)
    if "clauses" in c:
        clauses = c["clauses"]
        if not isinstance(clauses, list):
            return out + ["clauses not an array"]
        if _count_clauses(clauses) > MAX_CLAUSES:
            out.append("too many clauses")
        # clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
        for cl in clauses:
            out.extend(validate_clause(cl, ids, 1))
    return out


# ---- contract commitment -------------------------------------------------------------------------------------------------------

def _body(c: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in c.items() if k not in ("id", "sig")}


def contract_id(c: Dict[str, Any]) -> str:
    """Content address of a contract body. Raises only on non-canonicalizable input (authoring time)."""
    return hash_canonical(_body(c))


def sign_contract(c: Dict[str, Any], principal_seed: bytes) -> Dict[str, Any]:
    problems = validate_contract(c)
    if problems:
        raise TypeError("signContract: " + "; ".join(problems))
    id_ = contract_id(c)
    return {**_body(c), "id": id_, "sig": b64u(ed25519.sign(principal_seed, _domain_message(CONTRACT_SIG_DOMAIN, id_)))}


def verify_contract(sc: Any, expected_principal: Optional[str] = None) -> Dict[str, Any]:
    """Well-formed, id matches content, signature by ``expected_principal`` (or the embedded one). Never raises."""
    try:
        problems = validate_contract(sc)
        if problems:
            return {"ok": False, "reason": problems[0]}
        if expected_principal is not None and sc["principal"] != expected_principal:
            return {"ok": False, "reason": "principal mismatch"}
        if not isinstance(sc.get("id"), str) or sc["id"] != contract_id(sc):
            return {"ok": False, "reason": "id does not match content"}
        if not isinstance(sc.get("sig"), str) or not _verify_b64u(sc["principal"], _domain_message(CONTRACT_SIG_DOMAIN, sc["id"]), sc["sig"]):
            return {"ok": False, "reason": "bad signature"}
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "verification error (fail closed)"}


def embedded_constitution(c: Dict[str, Any]) -> Dict[str, Any]:
    return {"version": 1, "principal": c["principal"], "invariants": c["invariants"] if isinstance(c.get("invariants"), list) else []}


def contract_from_constitution(c: Dict[str, Any]) -> Dict[str, Any]:
    return {"version": CONTRACT_VERSION, "principal": c["principal"], "invariants": c["invariants"], "clauses": []}


# ---- clause evaluation ---------------------------------------------------------------------------------------------------------

def _row(cl: Dict[str, Any], ok: bool, reason: Any = None) -> Dict[str, Any]:
    row = {"id": cl["id"], "kind": cl["kind"], "result": "pass" if ok else "violated"}
    if _truthy(reason):
        row["reason"] = reason
    return row


def _base(cl: Dict[str, Any], ok: bool, reason: Any = None) -> Dict[str, Any]:
    t: Dict[str, Any] = {"ok": ok, "rows": [_row(cl, ok, reason)], "latchSet": {}, "deadlineSet": {}}
    if _truthy(reason):
        t["reason"] = reason
    return t


def _desc(cl: Dict[str, Any], default: str) -> Any:
    d = cl.get("description")
    return default if d is None else d


def _eval_clause(cl: Dict[str, Any], ctx: Any, state: Dict[str, Any], now: Any) -> Dict[str, Any]:
    """Per-clause transition: the verdict plus the intended latch / deadline updates (applied only if the whole contract is ok)."""
    latched = state["latched"]
    deadlines = state.get("deadlines") or {}
    try:
        kind = cl["kind"]
        if kind == "always":
            return _base(cl, True) if when_affirmative(cl["p"], ctx) else _base(cl, False, _desc(cl, "always-invariant violated (action does not satisfy p)"))
        if kind == "never":
            return _base(cl, False, _desc(cl, "never-invariant violated (forbidden action)")) if when_matches(cl["p"], ctx) else _base(cl, True)
        if kind in ("precedes", "requires_prior"):
            is_q = when_matches(cl["q"], ctx)  # guarded action, conservative
            held = cl["id"] in latched
            ok = (not is_q) or held
            t = _base(cl, ok, None if ok else _desc(cl, "precedence violated (prerequisite p not yet admitted before q)"))
            # latch the prerequisite on an AFFIRMATIVE match (an ambiguous prerequisite must not count)
            if not held and when_affirmative(cl["p"], ctx):
                t["latchSet"][cl["id"]] = now
            return t
        if kind == "responds_within":
            violated = False
            carried: Any = None
            if cl["id"] in deadlines:
                cur = deadlines[cl["id"]]
                if when_affirmative(cl["q"], ctx):
                    carried = None  # any response discharges all open obligations
                else:
                    r = cur - 1
                    if r <= 0:
                        violated = True  # window exhausted with no response => violation at this action
                    else:
                        carried = r
            if violated:
                reason = _desc(cl, "bounded-liveness deadline missed (no q within %s actions of p)" % _js_string(cl["within"]))
                row = _row(cl, False, reason)
                return {"ok": False, "reason": row.get("reason"), "rows": [row], "latchSet": {}, "deadlineSet": {}}
            nxt = carried
            if when_matches(cl["p"], ctx):
                nxt = cl["within"] if nxt is None else min(nxt, cl["within"])
            return {"ok": True, "rows": [_row(cl, True)], "latchSet": {}, "deadlineSet": {cl["id"]: nxt}}
        if kind == "and":
            rows: List[Any] = []
            latch_set: Dict[str, Any] = {}
            deadline_set: Dict[str, Any] = {}
            ok = True
            reason = None
            for sub in cl["clauses"]:
                r = _eval_clause(sub, ctx, state, now)
                rows.extend(r["rows"])
                latch_set.update(r["latchSet"])
                deadline_set.update(r["deadlineSet"])
                if not r["ok"] and ok:
                    ok = False
                    reason = r.get("reason")
            out = {"ok": ok, "rows": rows, "latchSet": latch_set, "deadlineSet": deadline_set}
            if _truthy(reason):
                out["reason"] = reason
            return out
        return _base(cl, False, "unknown clause kind (fail closed)")
    except Exception:  # noqa: BLE001
        return _base(cl, False, "clause evaluation error (fail closed)")


# ---- the contract monitor ------------------------------------------------------------------------------------------------------

def check_contract(action: Any, contract: Any, state: Any) -> Dict[str, Any]:
    """Evaluate a whole contract (embedded constitution + temporal clauses) against one action, WITHOUT advancing. Total, fail-closed."""
    return with_regex_budget(lambda: _check_contract_inner(action, contract, state))


def _check_contract_inner(action: Any, contract: Any, state: Any) -> Dict[str, Any]:
    def fail(id_: str, reason: str) -> Dict[str, Any]:
        return {"ok": False, "violated": [id_], "reasons": ["%s: %s" % (id_, reason)],
                "evaluated": [{"id": id_, "kind": "structural", "result": "violated", "reason": reason}]}

    try:
        cp = validate_contract(contract)
        if cp:
            return fail("<contract>", cp[0])
        a = action.get("action") if isinstance(action, dict) else None
        if not isinstance(a, dict) or not isinstance(a.get("verb"), str) or not isinstance(a.get("resource"), str):
            return fail("<action>", "malformed action")
        sp = state_problem(state)
        if sp:
            return fail("<state>", sp)
        evaluated: List[Dict[str, Any]] = []
        constitution = embedded_constitution(contract)
        if constitution["invariants"]:
            evaluated.extend(check_prohibitions(action, constitution, state)["evaluated"])
        now = state["now"]
        for cl in contract.get("clauses") or []:
            try:
                t = _eval_clause(cl, action, state, now)
            except Exception:  # noqa: BLE001
                t = {"rows": [{"id": cl["id"], "kind": cl.get("kind", "clause"), "result": "violated", "reason": "clause evaluation error (fail closed)"}]}
            evaluated.extend(t["rows"])
        bad = [e for e in evaluated if e["result"] == "violated"]
        return {"ok": len(bad) == 0, "violated": [e["id"] for e in bad],
                "reasons": ["%s: %s" % (e["id"], _js_string(e["reason"]) if "reason" in e else "violated") for e in bad], "evaluated": evaluated}
    except Exception:  # noqa: BLE001
        return fail("<monitor>", "monitor error (fail closed)")


def advance_contract(state: Any, action: Any, contract: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Check the whole contract against one action and, iff it holds, advance the hash-chained monitor state. ``opts`` may carry
    ``now``, ``expectedSeq`` and ``expectedStateDigest``. Fail closed; ``next`` is the input state unless ``ok``. Never raises."""
    opts = opts or {}

    def refuse(decided_by: str, r: Optional[Dict[str, Any]] = None, reason: Optional[str] = None) -> Dict[str, Any]:
        base = r if r is not None else check_contract(action, contract, state)
        violated = ([v for v in base["violated"] if v != "<state>"] + ["<state>"]) if reason else base["violated"]
        reasons = (base["reasons"] + ["<state>: %s" % reason]) if reason else base["reasons"]
        return {"ok": False, "violated": violated, "reasons": reasons, "evaluated": base["evaluated"], "next": state, "decidedBy": decided_by}

    try:
        now = opts["now"] if opts.get("now") is not None else (state.get("now") if isinstance(state, dict) else None)
        # CAS on the chain head FIRST: a rolled-back / stale state is refused before anything else
        if "expectedSeq" in opts and (not _is_obj(state) or state.get("seq") != opts["expectedSeq"]):
            return refuse("state", None, "stale state head (seq)")
        if "expectedStateDigest" in opts and _safe(lambda: state_digest(state)) != opts["expectedStateDigest"]:
            return refuse("state", None, "stale state head (digest)")

        verdict = check_contract(action, contract, state)
        if not verdict["ok"]:
            structural = any(v.startswith("<") and v.endswith(">") for v in verdict["violated"])
            return {**verdict, "next": state, "decidedBy": "state" if structural else "contract"}

        constitution = embedded_constitution(contract)
        adv = advance_state_strict(action, constitution, state, now)
        if not adv["ok"]:
            return refuse("state", verdict, "advance failed: " + adv["reason"])

        latched = dict(adv["state"]["latched"])
        deadlines = dict(state.get("deadlines") or {})

        def overlay() -> None:
            for cl in contract.get("clauses") or []:
                t = _eval_clause(cl, action, state, now)
                for k, v in t["latchSet"].items():
                    if k not in latched:
                        latched[k] = v
                for k, v in t["deadlineSet"].items():
                    if v is None:
                        deadlines.pop(k, None)
                    else:
                        deadlines[k] = v

        with_regex_budget(overlay)
        nxt = {**adv["state"], "latched": latched}
        if deadlines:
            nxt["deadlines"] = deadlines
        sp = state_problem(nxt)
        if sp:
            return refuse("state", verdict, "resulting state invalid: " + sp)
        return {**verdict, "next": nxt, "decidedBy": "none"}
    except Exception:  # noqa: BLE001
        return refuse("state", None, "advance error (fail closed)")


def check_and_advance_contract(permitted: Any, state: Any, action: Any, contract: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """``allow = permitted AND contract.ok``; on allow the state advances. The contract monitor runs unconditionally."""
    adv = advance_contract(state, action, contract, opts)
    p = permitted is True
    if not adv["ok"]:
        return {**adv, "allow": False, "permitted": p}
    if not p:
        return {"ok": False, "violated": adv["violated"], "reasons": adv["reasons"] + ["<permission>: not permitted"], "evaluated": adv["evaluated"],
                "next": state, "decidedBy": "contract", "allow": False, "permitted": p}
    return {**adv, "allow": True, "permitted": p}
