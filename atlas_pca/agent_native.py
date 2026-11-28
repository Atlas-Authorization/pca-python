"""Agent-native authority primitives (the reference's `agentNative` namespace): uncertainty attestation, rationale binding, the
semantic firewall (tool-schema caveats), capability introspection and the authority lease.

    from atlas_pca import agent_native as an
    claim = an.sign_caution({"action_digest": d, "caution": 0.4, "holder": key.public}, key)
    an.combine_signed_caution(claim, d, 0.2, key.public)   # {"effectiveRisk": 0.4, "honoured": True, "escalated": True}

Pure and deterministic: no clocks (callers pass ``now``) and no randomness except the default rationale salt. The verifiers and
evaluators are total and fail closed (they never raise on malformed input); the AUTHORING helpers (``sign_caution``,
``bind_rationale``, ``tool_schema_caveat``, ``grant_lease``) raise on invalid input, so a bad artefact is never minted.

Values are the reference's JSON: dicts, lists, strings, numbers (a number is a finite IEEE double; a bool is never a number)
and None. The member names are the reference's (``effectiveRisk``, ``hasEnvelope``, ``remainingBudgetHints``, ...).
``renew_capability_lease`` is the reference's pure ``renewLease(lease, heartbeat, now)``; ``atlas_pca.lease.renew_lease`` is the
grants LeaseRegistry renewal, a different feature."""
import json
import math
from ._fin import fin
import os
from typing import Any, Callable, Dict, List, Optional

from .authorize import (ABSOLUTE_MAX_ARRAY_ITEMS, ABSOLUTE_MAX_STRING_LEN, DEFAULT_MAX_ARRAY_ITEMS, DEFAULT_MAX_STRING_LEN,
                        MAX_ENUM_VALUES, MAX_OBJECT_PROPS, MAX_SCHEMA_DEPTH, MAX_SCHEMA_NODES, MAX_VALUE_NODES, _check_object,
                        _jslen, _show, read_envelope, validate_arg_schema)
from .authorize import evaluate_tool_schema as _evaluate_tool_schema
from .intent_v2 import _UNDEF
from .pca import (REVERSIBILITY_ORDER, _caveat_satisfied, _fin, _neg_zero, _utf8_key, b64u, canonicalize, canonical_bytes_strict,
                  decode_b64u_strict, hash_canonical, verify_chain)
from .pca import _verify_b64u
from .predicates import _js_string, predicate_matches
from .signers_more import MAX_CAUTION_REASON_LEN, sign_caution, sign_heartbeat

__all__ = [
    "CAVEAT_ENVELOPE", "CAVEAT_EXPIRES", "CAVEAT_NOT_BEFORE", "CAVEAT_RATE", "CAVEAT_MAX_BLAST_RADIUS", "CAVEAT_REVERSIBILITY_MAX",
    "CAVEAT_DELEGATION_DEPTH", "CAVEAT_PREDICATES", "CAVEAT_TOOL_SCHEMA", "CAVEAT_MAX_SPEND", "MAX_CAUTION_REASON_LEN",
    "MIN_SALT_BYTES", "MIN_SALT_DISTINCT_BYTES", "MAX_RATIONALE_LEN", "MAX_SCHEMA_DEPTH", "MAX_SCHEMA_NODES", "MAX_OBJECT_PROPS",
    "MAX_ENUM_VALUES", "DEFAULT_MAX_ARRAY_ITEMS", "ABSOLUTE_MAX_ARRAY_ITEMS", "DEFAULT_MAX_STRING_LEN", "ABSOLUTE_MAX_STRING_LEN",
    "MAX_VALUE_NODES", "HEARTBEAT_SKEW_MS", "MAX_LEASE_TTL_MS",
    "sign_caution", "verify_caution", "combine_caution", "combine_signed_caution", "check_caution_monotone", "is_strong_salt",
    "bind_rationale", "verify_rationale", "audit_rationale", "validate_arg_schema", "tool_schema_caveat", "evaluate_tool_schema",
    "tool_schema_evaluator", "predicates_caveat", "action_spend_usd", "agent_native_caveat_evaluator", "describe_envelope",
    "envelope_permits", "envelope_permits_tool_call", "grant_lease", "lease_state", "sign_heartbeat", "renew_capability_lease",
]

CAVEAT_ENVELOPE = "envelope"
CAVEAT_EXPIRES = "expires"
CAVEAT_NOT_BEFORE = "not_before"
CAVEAT_RATE = "rate"
CAVEAT_MAX_BLAST_RADIUS = "max_blast_radius"
CAVEAT_REVERSIBILITY_MAX = "reversibility_max"
CAVEAT_DELEGATION_DEPTH = "delegation_depth"
CAVEAT_PREDICATES = "predicates"
CAVEAT_TOOL_SCHEMA = "tool_schema"
CAVEAT_MAX_SPEND = "max_spend"

MIN_SALT_BYTES = 16
MIN_SALT_DISTINCT_BYTES = 8
MAX_RATIONALE_LEN = 8192
HEARTBEAT_SKEW_MS = 30_000
MAX_LEASE_TTL_MS = 7 * 24 * 3_600_000

_SAFE_INT = 2 ** 53 - 1
_ABSENT = object()
_REASON_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-")
_SALT_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_CAUTION_KEYS = ("action_digest", "caution", "reason", "holder", "sig")
_HB_KEYS = ("cap_id", "seq", "at", "holder", "lease_issued_at", "sig")


# ---- JS-shaped helpers ---------------------------------------------------------------------------------------------------

def _isfin(x: Any) -> bool:
    return _fin(x) is not None


def _is_int(x: Any) -> bool:
    f = _fin(x)
    return f is not None and f.is_integer()


def _nz(x: float) -> Any:
    """A computed double as the caller's number: an integral value inside the safe range is an int (no -0)."""
    if isinstance(x, float) and x.is_integer() and abs(x) <= _SAFE_INT:
        return int(x)
    return x


def _same_num(a: Any) -> Any:
    return _nz(a) if isinstance(a, float) else a


def _clamp01(x: float) -> float:
    return min(1.0, max(0.0, float(x)))


def _msg_of(domain: str, body: Any) -> bytes:
    return canonical_bytes_strict({"d": domain, "b": body})


def _only_keys(o: dict, allowed: Any) -> bool:
    return all(k in allowed for k in o)


def _strict_eq(a: Any, b: Any) -> bool:
    """JavaScript ``===`` for the scalars compared here (a bool is not a number)."""
    fa, fb = _fin(a), _fin(b)
    if fa is not None or fb is not None:
        return fa is not None and fb is not None and fa == fb
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def _truthy(x: Any) -> bool:
    if x is None or x is False or x == "" or (isinstance(x, (int, float)) and not isinstance(x, bool) and (x == 0 or x != x)):
        return False
    return True


def _prop(o: Any, k: str) -> Any:
    """JavaScript ``o.k``: undefined for a non-object (a TypeError for null)."""
    if o is None:
        raise TypeError("cannot read property of null")
    if isinstance(o, dict):
        return o[k] if k in o else _UNDEF
    return _UNDEF


def _parse_int(t: str) -> Any:
    n = int(t)
    return float(n) if abs(n) > 2 ** 53 else n


def _clone(x: Any) -> Any:
    """JSON.parse(canonicalize(x)): the lenient canonical form, deep-cloned (-0 becomes 0, a non-finite number raises)."""
    return json.loads(canonicalize(x), parse_int=_parse_int)


# ---- 1. uncertainty attestation ------------------------------------------------------------------------------------------

def _caution_body_error(b: Any) -> Optional[str]:
    if not isinstance(b, dict):
        return "not an object"
    if not isinstance(b.get("action_digest"), str) or not b["action_digest"]:
        return "action_digest required"
    if not isinstance(b.get("holder"), str) or not b["holder"]:
        return "holder required"
    c = b.get("caution")
    if _fin(c) is None or c < 0 or c > 1:
        return "caution must be a finite number in [0,1]"
    if "reason" in b:
        r = b["reason"]
        if not isinstance(r, str) or not r or _jslen(r) > MAX_CAUTION_REASON_LEN or set(r) - _REASON_CHARS:
            return "invalid reason"
    return None


def verify_caution(claim: Any, expected_action_digest: Optional[str] = None, expected_holder: Optional[str] = None) -> bool:
    """Verify a caution claim: strict shape (no smuggled member), caution in [0,1], a valid signature by ``claim["holder"]``,
    bound to ``expected_action_digest`` (when given) and signed by ``expected_holder`` (when given: production callers MUST pass
    the PCActn's holder, otherwise any key may attest). Total."""
    try:
        if not isinstance(claim, dict) or not isinstance(claim.get("sig"), str) or not _only_keys(claim, _CAUTION_KEYS):
            return False
        if _caution_body_error(claim) is not None:
            return False
        if expected_action_digest is not None and claim["action_digest"] != expected_action_digest:
            return False
        if expected_holder is not None and claim["holder"] != expected_holder:
            return False
        body = {k: v for k, v in claim.items() if k != "sig"}
        return _verify_b64u(claim["holder"], _msg_of("atlas-pca/caution/v1", body), claim["sig"])
    except Exception:  # noqa: BLE001 - total
        return False


def combine_caution(agent_declared_caution: Any, server_risk: Any) -> float:
    """``max(declared, server_risk)`` clamped to [0,1]: never below the server's figure, non-decreasing in the declaration; an
    unusable declaration is ignored and an unusable server risk fails closed to 1."""
    s = _clamp01(_fin(server_risk)) if _isfin(server_risk) else 1.0
    if not _isfin(agent_declared_caution):
        return s
    return max(_clamp01(_fin(agent_declared_caution)), s)


def combine_signed_caution(claim: Any, action_digest: Any, server_risk: Any, expected_holder: Optional[str] = None) -> Dict[str, Any]:
    """The same, taking a signed claim: only a valid claim bound to THIS action (and, when given, THIS holder) is honoured."""
    s = _clamp01(_fin(server_risk)) if _isfin(server_risk) else 1.0
    ok = claim is not None
    if ok:
        try:
            body = claim
            ok = isinstance(body, dict) and isinstance(body.get("sig"), str) and _only_keys(body, _CAUTION_KEYS) \
                and _caution_body_error(body) is None and body["action_digest"] == action_digest \
                and (expected_holder is None or body["holder"] == expected_holder) \
                and _verify_b64u(body["holder"], _msg_of("atlas-pca/caution/v1", {k: v for k, v in body.items() if k != "sig"}),
                                 body["sig"])
        except Exception:  # noqa: BLE001 - total
            ok = False
    eff = combine_caution(claim["caution"] if ok else None, s)
    return {"effectiveRisk": eff, "honoured": bool(ok), "escalated": eff > s}


def check_caution_monotone(grid: Any) -> Dict[str, Any]:
    """Exhaustive-grid check of the monotonicity property (non-finite and non-number grid entries are dropped)."""
    g = [x for x in grid if _isfin(x)]
    for s in g:
        for d in g:
            e = combine_caution(d, s)
            if e < _clamp01(_fin(s)):
                return {"ok": False, "counterexample": [d, s]}
            for d2 in g:
                if _fin(d2) >= _fin(d) and combine_caution(d2, s) < e:
                    return {"ok": False, "counterexample": [d2, s]}
    return {"ok": True}


# ---- 2. rationale binding ------------------------------------------------------------------------------------------------

def is_strong_salt(salt: Any) -> bool:
    """Entropy floor of a commitment salt: base64url of >= 16 bytes with >= 8 distinct byte values (at most 256 characters)."""
    if not isinstance(salt, str) or len(salt) == 0 or len(salt) > 256 or set(salt) - _SALT_CHARS:
        return False
    b = decode_b64u_strict(salt)
    return b is not None and len(b) >= MIN_SALT_BYTES and len(set(b)) >= MIN_SALT_DISTINCT_BYTES


def _commit_digest(action_digest: str, salt: str, rationale: str) -> str:
    return hash_canonical({"d": "atlas-pca/rationale/v1", "a": action_digest, "s": salt, "r": rationale})


def bind_rationale(action: Any, rationale: Any, salt: Any = _ABSENT) -> Dict[str, Any]:
    """The agent commits to its stated reason: publish ``commitment``, KEEP ``reveal``. ``salt`` (b64u, >= 16 bytes with >= 8
    distinct values) defaults to 32 random bytes. Raises on a weak salt, a non-string or oversized rationale or an action that
    cannot be canonicalized."""
    if salt is _ABSENT:
        salt = b64u(os.urandom(32))
    if not isinstance(rationale, str):
        raise TypeError("bind_rationale: rationale must be a string")
    if _jslen(rationale) > MAX_RATIONALE_LEN:
        raise ValueError("bind_rationale: rationale too long")
    if not is_strong_salt(salt):
        raise ValueError("bind_rationale: salt must be b64u of >=%d bytes with >=%d distinct values" % (MIN_SALT_BYTES, MIN_SALT_DISTINCT_BYTES))
    action_digest = hash_canonical(action)
    return {"commitment": {"v": 1, "action_digest": action_digest, "commitment": _commit_digest(action_digest, salt, rationale)},
            "reveal": {"rationale": rationale, "salt": salt}}


def _commitment_ok(c: Any) -> bool:
    v = c.get("v") if isinstance(c, dict) else None
    return isinstance(c, dict) and _fin(v) is not None and v == 1 and isinstance(c.get("action_digest"), str) and c["action_digest"] != "" \
        and isinstance(c.get("commitment"), str) and c["commitment"] != ""


def verify_rationale(commitment: Any, reveal: Any, action: Any = _ABSENT) -> bool:
    """Does the revealed rationale open the commitment (and, when ``action`` is given, for that very action)? A salt below the
    entropy floor is refused even if it hashes correctly. Total."""
    try:
        if not isinstance(commitment, dict) or not isinstance(reveal, dict) or not _commitment_ok(commitment):
            return False
        if not isinstance(reveal.get("rationale"), str) or _jslen(reveal["rationale"]) > MAX_RATIONALE_LEN \
                or not is_strong_salt(reveal.get("salt")):
            return False
        if action is not _ABSENT and hash_canonical(action) != commitment["action_digest"]:
            return False
        return _commit_digest(commitment["action_digest"], reveal["salt"], reveal["rationale"]) == commitment["commitment"]
    except Exception:  # noqa: BLE001 - total
        return False


def audit_rationale(commitment: Any, action: Any, reveal: Any, judge: Callable[[str, Any], Any]) -> Dict[str, Any]:
    """After-the-fact audit with an auditor-supplied ``judge(rationale, action)``. Failing to open the commitment, or a rationale
    that opens and is judged false, is slashable; a malformed commitment, the wrong action or a throwing judge is not. Total."""
    ok = isinstance(commitment, dict)
    evidence = {"commitment": commitment["commitment"] if ok and isinstance(commitment.get("commitment"), str) else "",
                "action_digest": commitment["action_digest"] if ok and isinstance(commitment.get("action_digest"), str) else ""}
    try:
        if not _commitment_ok(commitment):
            return {"verdict": "malformed", "slashable": False, "evidence": evidence}
        if hash_canonical(action) != commitment["action_digest"]:
            return {"verdict": "wrong_action", "slashable": False, "evidence": evidence}
        if not _truthy(reveal) or not verify_rationale(commitment, reveal, action):
            return {"verdict": "unopened", "slashable": True, "evidence": evidence}
        try:
            good = judge(reveal["rationale"], action) is True
        except Exception:  # noqa: BLE001 - a throwing judge is not the agent's fault
            return {"verdict": "judge_error", "slashable": False, "evidence": dict(evidence, rationale=reveal["rationale"])}
        return {"verdict": "consistent" if good else "false_rationale", "slashable": not good,
                "evidence": dict(evidence, rationale=reveal["rationale"])}
    except Exception:  # noqa: BLE001 - total
        return {"verdict": "malformed", "slashable": False, "evidence": evidence}


# ---- 3. semantic firewall ------------------------------------------------------------------------------------------------

def _binding_of(tool: str, signature_digest: str, schema: Any) -> str:
    return hash_canonical({"tool": tool, "signature_digest": signature_digest, "schema": schema})


def tool_schema_caveat(tool_signature: Any, arg_schema: Any) -> Dict[str, Any]:
    """Build a ``tool_schema`` caveat: authority for exactly this tool + signature + closed argument schema. Raises when the
    signature has no tool name, the schema is invalid or anything is not canonicalizable. The schema is deep-cloned."""
    if isinstance(tool_signature, str):
        tool = tool_signature
    elif isinstance(tool_signature, dict) and isinstance(tool_signature.get("name"), str):
        tool = tool_signature["name"]
    else:
        tool = ""
    if not tool:
        raise TypeError("tool_schema_caveat: tool name required")
    err = validate_arg_schema(arg_schema)
    if err:
        raise TypeError("tool_schema_caveat: " + err)
    schema = _clone(arg_schema)
    signature_digest = hash_canonical(tool_signature)
    return {"type": "tool_schema", "tool": tool, "signature_digest": signature_digest, "schema": schema,
            "schema_digest": hash_canonical(schema), "binding_digest": _binding_of(tool, signature_digest, schema)}


def evaluate_tool_schema(caveat: Any, call: Any) -> Dict[str, Any]:
    """Evaluate a tool call ``{"tool", "args", "toolSignature"?, "toolSignatureDigest"?}`` against a ``tool_schema`` caveat:
    ``{"ok": True}`` or ``{"ok": False, "reason": ...}``. Fails closed, never raises."""
    ok, reason = _evaluate_tool_schema(caveat, call)
    return {"ok": True} if ok else {"ok": False, "reason": reason}


def tool_schema_evaluator(caveat: Any, ctx: Any) -> bool:
    """The caveat-evaluator hook for ``tool_schema``: ``ctx = {"toolCall": {...}}``; other caveat types are unsatisfied here."""
    if not isinstance(ctx, dict) or not isinstance(ctx.get("toolCall"), dict):
        return False
    return evaluate_tool_schema(caveat, ctx["toolCall"])["ok"]


def predicates_caveat(allow: Any) -> Dict[str, Any]:
    """The delegated-narrowing caveat ``{"type": "predicates", "allow": [...]}`` (deep-cloned canonical form)."""
    return {"type": CAVEAT_PREDICATES, "allow": _clone(allow)}


def action_spend_usd(action: Any) -> Any:
    """The action's spend in USD as ``max_spend`` reads it: the own ``action.action.params.amount`` (finite, >= 0) whose own
    ``currency``, when present, is ``"usd"`` or ``"USD"``. None = no readable spend."""
    if not isinstance(action, dict):
        return None
    act = action.get("action") if "action" in action else None
    if not isinstance(act, dict):
        return None
    params = act.get("params") if "params" in act else None
    if not isinstance(params, dict) or "amount" not in params:
        return None
    amount = params["amount"]
    if _fin(amount) is None or amount < 0:
        return None
    if "currency" in params and params["currency"] not in ("usd", "USD"):
        return None
    return amount


def _max_spend_satisfied(caveat: dict, ctx: dict) -> bool:
    lim = caveat.get("usd") if "usd" in caveat else None
    spend = action_spend_usd(ctx.get("action") if "action" in ctx else None)
    return _fin(lim) is not None and spend is not None and _fin(spend) <= _fin(lim)


def agent_native_caveat_evaluator(caveat: Any, ctx: Any) -> bool:
    """Superset of the stock envelope caveat evaluator: adds ``predicates`` (needs ``ctx["action"]``), ``max_spend`` (needs
    ``ctx["action"]``) and ``tool_schema`` (needs ``ctx["toolCall"]``). ``ctx`` is the reference's: ``now``, ``blastRadius``,
    ``reversibilityClass``, ``delegationDepth``, ``recentActionTimes``, ``action``, ``toolCall``. Anything else defers to the
    stock types and fails closed. Total."""
    try:
        if not isinstance(caveat, dict) or not isinstance(ctx, dict):
            return False
        t = caveat.get("type")
        if t == CAVEAT_TOOL_SCHEMA:
            return tool_schema_evaluator(caveat, ctx)
        if t == CAVEAT_PREDICATES:
            a = ctx.get("action")
            if not isinstance(a, dict) or not isinstance(caveat.get("allow"), list):
                return False
            return any(predicate_matches(p, a) for p in caveat["allow"])
        if t == CAVEAT_MAX_SPEND:
            return _max_spend_satisfied(caveat, ctx)
        stock = {}
        for src, dst in (("now", "now"), ("blastRadius", "blast_radius"), ("reversibilityClass", "reversibility_class"),
                         ("delegationDepth", "delegation_depth"), ("recentActionTimes", "recent_action_times")):
            if src in ctx:
                stock[dst] = ctx[src]
        return _caveat_satisfied(caveat, stock)
    except Exception:  # noqa: BLE001 - total
        return False


# ---- 4. capability introspection -----------------------------------------------------------------------------------------

def _sorted_unique(xs: Any) -> List[str]:
    return sorted(set(xs), key=_utf8_key)


def _intersect_verbs(a: List[str], b: List[str]) -> List[str]:
    if "*" in a:
        return _sorted_unique(b)
    if "*" in b:
        return _sorted_unique(a)
    return _sorted_unique([x for x in a if x in b])


def _inter_res(a: str, b: str) -> Any:
    """Intersect two resource patterns: the pattern, None = empty, _UNDEF = cannot decide symbolically (regex)."""
    if a == b:
        return a
    if a.startswith("re:") or b.startswith("re:"):
        return _UNDEF
    if a == "*":
        return b
    if b == "*":
        return a
    ap, bp = a.endswith("*"), b.endswith("*")
    if ap and bp:
        pa, pb = a[:-1], b[:-1]
        return b if pb.startswith(pa) else a if pa.startswith(pb) else None
    if ap:
        return b if b.startswith(a[:-1]) else None
    if bp:
        return a if a.startswith(b[:-1]) else None
    return None


def _collapse_resources(lst: List[str]) -> Optional[List[str]]:
    lit = None
    res = set()
    for p in lst:
        if p.startswith("re:"):
            res.add(p)
            continue
        if lit is None:
            lit = p
        else:
            r = _inter_res(lit, p)
            if r is None or r is _UNDEF:
                return None
            lit = r
    out = ([lit] if lit is not None and lit != "*" else []) + sorted(res, key=_utf8_key)
    return out if out else ["*"]


def _scope_of_predicate(p: Any) -> Optional[dict]:
    if not isinstance(p, dict):
        return None
    v = p.get("verb") if "verb" in p else None
    if isinstance(v, str):
        verbs = [v]
    elif isinstance(v, list) and all(isinstance(x, str) for x in v):
        verbs = list(v)
    else:
        return None
    if "resource" in p and not isinstance(p["resource"], str):
        return None
    if "where" not in p:
        where: Any = []
    elif isinstance(p["where"], list):
        where = p["where"]
    else:
        return None
    return {"verbs": _sorted_unique(verbs), "resources": [p["resource"] if "resource" in p else "*"], "where": where}


def _intersect_scopes(a: List[dict], b: List[dict]) -> List[dict]:
    out: Dict[str, dict] = {}
    for x in a:
        for y in b:
            verbs = _intersect_verbs(x["verbs"], y["verbs"])
            if not verbs:
                continue
            resources = _collapse_resources(list(x["resources"]) + list(y["resources"]))
            if resources is None:
                continue
            s = {"verbs": verbs, "resources": resources, "where": list(x["where"]) + list(y["where"])}
            out[hash_canonical(s)] = s
    return [out[k] for k in sorted(out)]


def _scope_matches(s: dict, verb: Any, resource: Any, params: Any) -> bool:
    if "*" not in s["verbs"] and verb not in s["verbs"]:
        return False
    action = {"verb": verb, "resource": resource}
    if _truthy(params):
        action["params"] = params
    ctx = {"action": action}
    for r in s["resources"]:
        if not predicate_matches({"verb": "*", "resource": r}, ctx):
            return False
    if params is not None and s["where"]:
        return predicate_matches({"verb": "*", "where": s["where"]}, ctx)
    return True


def _well_formed_caveat(cv: dict) -> bool:
    t = cv.get("type")
    if t in (CAVEAT_EXPIRES, CAVEAT_NOT_BEFORE):
        return _isfin(cv.get("at"))
    if t == CAVEAT_RATE:
        return _isfin(cv.get("max")) and _isfin(cv.get("per_secs")) and cv["per_secs"] > 0
    if t in (CAVEAT_MAX_BLAST_RADIUS, CAVEAT_DELEGATION_DEPTH):
        return _isfin(cv.get("max"))
    if t == CAVEAT_REVERSIBILITY_MAX:
        return isinstance(cv.get("class"), str) and cv["class"] in REVERSIBILITY_ORDER
    if t == CAVEAT_PREDICATES:
        return isinstance(cv.get("allow"), list) and all(_scope_of_predicate(p) is not None for p in cv["allow"])
    if t == CAVEAT_TOOL_SCHEMA:
        return isinstance(cv.get("tool"), str) and cv["tool"] != ""
    if t == "budget_alloc":
        return _isfin(cv.get("limit")) and cv["limit"] >= 0
    if t == CAVEAT_MAX_SPEND:
        return _isfin(cv.get("usd")) and cv["usd"] >= 0
    return False


def _empty_envelope() -> Dict[str, Any]:
    return {"ok": False, "hasEnvelope": False, "scopes": [], "verbs": [], "resources": [], "opaqueResourceConstraints": [],
            "tools": [], "toolSchemas": [], "unsatisfiable": [], "caveats": [], "remainingBudgetHints": {}}


def describe_envelope(chain: Any, now: Any = None, expected_root_issuer: Optional[str] = None, policy: Any = None) -> Dict[str, Any]:
    """What an attenuated chain permits NOW: the conjunction of the root ``envelope`` predicates and every appended caveat, derived
    with the verifier's own vocabulary (never wider than reality). A chain that does not verify, or one carrying a caveat the
    verifier cannot satisfy, permits nothing. Deterministic (``now`` supplied) and total."""
    try:
        pol = policy if isinstance(policy, dict) else {}
        ok, reason = verify_chain(chain, expected_root_issuer, pol.get("allowedSuites"), pol.get("pqPins"), pol.get("trustedRoot"))
        if not ok:
            return dict(_empty_envelope(), reason=reason)
        root, leaf = chain[0], chain[-1]
        env0 = read_envelope(root)
        env = _empty_envelope()
        env.update(ok=True, hasEnvelope=env0 is not None, caveats=leaf["caveats"])
        h = env["remainingBudgetHints"]
        bad = set()
        st = {"scopes": None, "tools": None, "seen": False}
        everything = [{"verbs": ["*"], "resources": ["*"], "where": []}]
        if env0 is not None:
            base = [_scope_of_predicate(p) for p in env0["predicates"]]
            if any(s is None for s in base):
                bad.add("envelope.predicates")
            st["scopes"] = _intersect_scopes([s for s in base if s is not None], everything)

        def fold(cv: Any, in_envelope: bool) -> None:
            if not isinstance(cv, dict) or not isinstance(cv.get("type"), str):
                bad.add("<malformed>")
                return
            t = cv["type"]
            if t == CAVEAT_ENVELOPE:
                if st["seen"] or in_envelope:
                    bad.add(CAVEAT_ENVELOPE)
                st["seen"] = True
                return
            if not _well_formed_caveat(cv):
                bad.add(t)
                return
            if t == CAVEAT_PREDICATES:
                st["scopes"] = _intersect_scopes(st["scopes"] if st["scopes"] is not None else everything,
                                                 [_scope_of_predicate(p) for p in cv["allow"]])
            elif t == CAVEAT_TOOL_SCHEMA:
                env["toolSchemas"].append(cv)
                sig = _js_string(cv["signature_digest"]) if "signature_digest" in cv else "undefined"
                consistent = validate_arg_schema(cv.get("schema")) is None and hash_canonical(cv.get("schema")) == cv.get("schema_digest") \
                    and _binding_of(cv["tool"], sig, cv.get("schema")) == cv.get("binding_digest")
                if not consistent:
                    st["tools"] = []
                    bad.add(CAVEAT_TOOL_SCHEMA)
                else:
                    st["tools"] = [cv["tool"]] if st["tools"] is None else [x for x in st["tools"] if x == cv["tool"]]
            elif t == CAVEAT_EXPIRES:
                h["expiresAt"] = cv["at"] if "expiresAt" not in h else min(h["expiresAt"], cv["at"])
            elif t == CAVEAT_NOT_BEFORE:
                h["notBefore"] = cv["at"] if "notBefore" not in h else max(h["notBefore"], cv["at"])
            elif t == CAVEAT_RATE:
                m, p = float(cv["max"]), float(cv["per_secs"])
                cur = h.get("maxRate")
                if cur is None or m / p < float(cur["max"]) / float(cur["per_secs"]) \
                        or (m / p == float(cur["max"]) / float(cur["per_secs"]) and m < float(cur["max"])):
                    h["maxRate"] = {"max": cv["max"], "per_secs": cv["per_secs"]}
            elif t == CAVEAT_MAX_BLAST_RADIUS:
                h["maxBlastRadius"] = cv["max"] if "maxBlastRadius" not in h else min(h["maxBlastRadius"], cv["max"])
            elif t == CAVEAT_REVERSIBILITY_MAX:
                i = REVERSIBILITY_ORDER.index(cv["class"])
                j = len(REVERSIBILITY_ORDER) if "reversibilityMax" not in h else REVERSIBILITY_ORDER.index(h["reversibilityMax"])
                if i < j:
                    h["reversibilityMax"] = REVERSIBILITY_ORDER[i]
            elif t == CAVEAT_DELEGATION_DEPTH:
                rem = _nz(float(cv["max"]) - (len(chain) - 1))
                h["delegationDepthRemaining"] = rem if "delegationDepthRemaining" not in h else min(h["delegationDepthRemaining"], rem)
            elif t == "budget_alloc":
                h["budgetAlloc"] = cv["limit"] if "budgetAlloc" not in h else min(h["budgetAlloc"], cv["limit"])
            elif t == CAVEAT_MAX_SPEND:
                h["maxSpendUsd"] = cv["usd"] if "maxSpendUsd" not in h else min(h["maxSpendUsd"], cv["usd"])

        if env0 is not None:
            for cv in env0["caveats"]:
                fold(cv, True)
        for cv in leaf["caveats"]:
            fold(cv, False)

        scopes, tools = st["scopes"], st["tools"]
        env["scopes"] = scopes
        opaque = set()
        if scopes is not None:
            vs, rs = set(), set()
            for s in scopes:
                vs.update(s["verbs"])
                for r in s["resources"]:
                    rs.add(r)
                    if r.startswith("re:"):
                        opaque.add(r)
            env["verbs"], env["resources"] = _sorted_unique(vs), _sorted_unique(rs)
        else:
            env["verbs"], env["resources"] = None, None
        env["opaqueResourceConstraints"] = _sorted_unique(opaque)
        env["tools"] = None if tools is None else _sorted_unique(tools)
        env["unsatisfiable"] = _sorted_unique(bad)
        if env["unsatisfiable"]:
            env["scopes"], env["verbs"], env["resources"], env["tools"] = [], [], [], []
            env["reason"] = "unsatisfiable caveat(s): " + ", ".join(env["unsatisfiable"])
        if "expiresAt" in h and _isfin(now):
            h["expiresIn"] = _nz(float(h["expiresAt"]) - float(now))
        return env
    except Exception:  # noqa: BLE001 - total
        return dict(_empty_envelope(), reason="introspection error (fail closed)")


def envelope_permits(env: Any, verb: Any, resource: Any, now: Any = None, params: Any = None) -> bool:
    """Cheap pre-flight an agent can run before attempting. False is DEFINITIVE (the verifier will refuse); True means the
    symbolic envelope allows it. With ``params`` the ``where`` conditions are evaluated too (fail closed); without, a
    conditional scope counts as "may permit". Total."""
    try:
        if not _truthy(env["ok"]) or len(env["unsatisfiable"]) > 0:
            return False
        if env["scopes"] is not None and not any(_scope_matches(s, verb, resource, params) for s in env["scopes"]):
            return False
        h = env["remainingBudgetHints"]
        if "delegationDepthRemaining" in h and not (_isfin(h["delegationDepthRemaining"]) and float(h["delegationDepthRemaining"]) >= 0):
            return False
        if "maxSpendUsd" in h and params is not None:
            spend = action_spend_usd({"action": {"params": params}})
            if spend is None or not (_isfin(spend) and float(spend) <= float(h["maxSpendUsd"])):
                return False
        if now is not None:
            if not _isfin(now):
                return False
            if "expiresAt" in h and not (_isfin(h["expiresAt"]) and float(now) < float(h["expiresAt"])):
                return False
            if "notBefore" in h and not (_isfin(h["notBefore"]) and float(now) >= float(h["notBefore"])):
                return False
        return True
    except Exception:  # noqa: BLE001 - total
        return False


def envelope_permits_tool_call(env: Any, call: Any) -> Dict[str, Any]:
    """Pre-flight for a tool call: the tool must be in ``env["tools"]`` and satisfy EVERY ``tool_schema`` caveat. Total."""
    try:
        ok = _prop(env, "ok")
        if ok is _UNDEF or not _truthy(ok) or len(_prop(env, "unsatisfiable")) > 0:  # an absent `ok` is undefined (falsy)
            reason = env.get("reason") if isinstance(env, dict) else None
            return {"ok": False, "reason": reason if reason is not None else "envelope not usable"}
        if env["tools"] is not None:  # the reference reads call.tool only here (a null call is a TypeError, caught below)
            tool = _prop(call, "tool")
            if tool not in env["tools"]:
                return {"ok": False, "reason": "tool %s not authorized" % _show(_js_string(tool))}
        for tc in env["toolSchemas"]:
            r = evaluate_tool_schema(tc, call)
            if not r["ok"]:
                return r
        return {"ok": True}
    except Exception:  # noqa: BLE001 - total
        return {"ok": False, "reason": "evaluation error (fail closed)"}


# ---- 5. authority lease --------------------------------------------------------------------------------------------------

def grant_lease(args: Any) -> Dict[str, Any]:
    """Issue a lease ``{cap_id, holder, now, ttl_ms, hard_expires_at?, max_renewals?}``. Raises unless the ids are non-empty,
    ``now`` is finite, ``0 < ttl_ms <= MAX_LEASE_TTL_MS``, ``hard_expires_at`` (when present) is finite and after ``now`` and
    ``max_renewals`` (when present) is a non-negative integer."""
    cap, holder = args.get("cap_id"), args.get("holder")
    if not isinstance(cap, str) or not cap or not isinstance(holder, str) or not holder:
        raise TypeError("grant_lease: cap_id and holder required")
    now, ttl = args.get("now"), args.get("ttl_ms")
    if not _isfin(now) or not _isfin(ttl) or ttl <= 0 or ttl > MAX_LEASE_TTL_MS:
        raise ValueError("grant_lease: invalid now/ttl_ms")
    hard = args.get("hard_expires_at") if "hard_expires_at" in args else _ABSENT
    if hard is not _ABSENT and (not _isfin(hard) or float(hard) <= float(now)):
        raise ValueError("grant_lease: hard_expires_at must be finite and in the future")
    mr = args.get("max_renewals") if "max_renewals" in args else _ABSENT
    if mr is not _ABSENT and not (_is_int(mr) and mr >= 0 and not _neg_zero(mr)):
        raise ValueError("grant_lease: invalid max_renewals")
    exp = float(now) + float(ttl)
    if hard is not _ABSENT:
        exp = min(exp, float(hard))
    lease = {"cap_id": cap, "holder": holder, "issued_at": _same_num(now), "renewed_at": _same_num(now), "ttl_ms": _same_num(ttl),
             "renewals": 0, "last_seq": 0, "expires_at": _nz(exp)}
    if hard is not _ABSENT:
        lease["hard_expires_at"] = _same_num(hard)
    if mr is not _ABSENT:
        lease["max_renewals"] = _same_num(mr)
    return lease


def _lease_error(l: Any) -> Optional[str]:
    if not isinstance(l, dict):
        return "malformed lease"
    if not isinstance(l.get("cap_id"), str) or not l["cap_id"] or not isinstance(l.get("holder"), str) or not l["holder"]:
        return "malformed lease"
    if not all(_isfin(l.get(k)) for k in ("issued_at", "renewed_at", "ttl_ms", "expires_at")):
        return "malformed lease"
    ttl = float(l["ttl_ms"])
    if ttl <= 0 or ttl > MAX_LEASE_TTL_MS:
        return "malformed lease"
    for k in ("renewals", "last_seq"):
        if not (_is_int(l.get(k)) and l[k] >= 0) or _neg_zero(l[k]):
            return "malformed lease"
    if "max_renewals" in l and not (_is_int(l["max_renewals"]) and l["max_renewals"] >= 0 and not _neg_zero(l["max_renewals"])):
        return "malformed lease"
    if "hard_expires_at" in l:
        if not _isfin(l["hard_expires_at"]):
            return "malformed lease"
        if float(l["expires_at"]) > float(l["hard_expires_at"]):
            return "lease exceeds hard expiry"
    # a lease can never outlive one ttl past its last renewal: anything else is corruption or tampering
    if float(l["expires_at"]) > float(l["renewed_at"]) + ttl:
        return "malformed lease"
    return None


def lease_state(lease: Any, now: Any) -> Dict[str, Any]:
    """Live iff the record is well-formed, the clock has not run back more than the skew window past the last renewal and
    ``now < expires_at``. Anything else is dead with a ``reason`` and ``expiresIn`` 0 (fail closed)."""
    def dead(reason: str) -> Dict[str, Any]:
        return {"live": False, "expiresIn": 0, "reason": reason}
    if not _isfin(now):
        return dead("invalid clock")
    e = _lease_error(lease)
    if e:
        return dead(e)
    if not (float(now) >= float(lease["renewed_at"]) - HEARTBEAT_SKEW_MS):
        return dead("clock before last renewal")
    expires_in = float(lease["expires_at"]) - float(now)
    if expires_in <= 0:
        return dead("lease lapsed")
    return {"live": True, "expiresIn": _nz(expires_in)}


def renew_capability_lease(lease: Any, hb: Any, now: Any) -> Dict[str, Any]:
    """The reference's pure ``renewLease``: renew on a valid, fresh, in-order heartbeat signed by the lease holder for THIS lease
    grant. A lease that has lapsed (or is malformed or clock-anomalous) is dead for good. Renewal never passes
    ``hard_expires_at``, never shortens the lease and spends the renewal budget. Returns ``{"ok": True, "lease": ...}`` or
    ``{"ok": False, "reason": ...}``; total. (``atlas_pca.lease.renew_lease`` is the grants registry's renewal, not this.)"""
    try:
        st = lease_state(lease, now)
        if not st["live"]:
            return {"ok": False, "reason": "lease lapsed" if st["reason"] == "lease lapsed" else "lease not live: %s" % st["reason"]}
        if not isinstance(hb, dict) or not _only_keys(hb, _HB_KEYS) or not isinstance(hb.get("sig"), str):
            return {"ok": False, "reason": "malformed heartbeat"}
        if not _strict_eq(hb.get("cap_id"), lease["cap_id"]) or not _strict_eq(hb.get("holder"), lease["holder"]) \
                or not _strict_eq(hb.get("lease_issued_at"), lease["issued_at"]):
            return {"ok": False, "reason": "heartbeat not for this lease"}
        seq = _fin(hb.get("seq"))
        if seq is None or not seq.is_integer() or abs(seq) > _SAFE_INT or seq <= float(lease["last_seq"]):
            return {"ok": False, "reason": "stale or replayed heartbeat"}
        at = _fin(hb.get("at"))
        if at is None or _fin(now) is None or not (abs(at - float(now)) <= HEARTBEAT_SKEW_MS):
            return {"ok": False, "reason": "heartbeat outside skew window"}
        body = {k: v for k, v in hb.items() if k != "sig"}
        if not _verify_b64u(lease["holder"], _msg_of("atlas-pca/lease-hb/v2", body), hb["sig"]):
            return {"ok": False, "reason": "bad heartbeat signature"}
        if "max_renewals" in lease and float(lease["renewals"]) >= float(lease["max_renewals"]):
            return {"ok": False, "reason": "renewal budget exhausted"}
        exp = float(now) + float(lease["ttl_ms"])
        if "hard_expires_at" in lease:
            exp = min(exp, float(lease["hard_expires_at"]))
        if not fin(exp):
            return {"ok": False, "reason": "malformed lease"}
        nxt = dict(lease)
        nxt.update(renewals=_nz(float(lease["renewals"]) + 1), last_seq=hb["seq"],
                   renewed_at=_nz(max(float(now), float(lease["renewed_at"]))),
                   expires_at=_nz(max(exp, float(lease["expires_at"]))))
        return {"ok": True, "lease": nxt}
    except Exception:  # noqa: BLE001 - total
        return {"ok": False, "reason": "malformed heartbeat"}
