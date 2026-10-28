"""Consistency tokens (``fresh_at``): a signed high-water mark of the verifier-side state a write produced. A caller attaches
the newest token it holds to later requests; the verifier refuses to DECIDE against state older than the token
(``stale_state`` is an ``escalate``: refresh and retry, never an allow). The token is also a signed PCActn member
(``fresh_at``) read by the verifier's ``fresh_at`` check. Verification only; every function is total.

A token is a dict ``{v, scope, revocation_epoch, ledger_tree_size, budget_version, policy_revision, policy_digest,
issued_at, signer, sig}``; verdicts are ``{decision: ok}``, ``{decision: escalate, code: stale_state, behind: [...]}`` or
``{decision: deny, code}``."""
from typing import Any, Dict, List, Optional

from .pca import _js_keys, decode_b64u_strict, hash_canonical
from .k3 import is_obj, is_one, is_str, is_uint, verify_body, _num

FRESH_AT_DOMAIN = "atlas-pca/fresh-at/v1\0"
FRESH_AT_REF_DOMAIN = "atlas-pca/fresh-at-ref/v1"
FRESH_AT_NUMERIC = ("revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision")
_BODY_KEYS = ("v", "scope", *FRESH_AT_NUMERIC, "policy_digest", "issued_at", "signer")
_WIRE_KEYS = frozenset(_BODY_KEYS + ("sig",))
_SKEW_MS = 60_000

#: "no value" (a PCActn without the member, a policy without ``side_carried``): distinct from JSON ``null``.
ABSENT = object()


def verify_fresh_at(t: Any, signer: Any) -> bool:
    """Well formed and signed by ``signer`` over exactly its content (members beyond the signed ones are not signed and are ignored)."""
    try:
        if not is_obj(t) or not is_one(t.get("v")) or t.get("signer") != signer or not is_str(t.get("scope"), 256) \
                or not is_str(t.get("policy_digest"), 128) or not is_uint(t.get("issued_at")):
            return False
        if not all(is_uint(t.get(k)) for k in FRESH_AT_NUMERIC):
            return False
        return verify_body(FRESH_AT_DOMAIN, {k: t[k] for k in _BODY_KEYS}, signer, t.get("sig"))
    except Exception:
        return False


def fresh_at_digest(t: dict) -> str:
    """The content address a PCActn or request signs to bind the token it carried (raises ``TypeError`` outside the strict profile)."""
    return hash_canonical({"d": FRESH_AT_REF_DOMAIN, "t": t})


def _ge(a: Any, b: Any) -> bool:
    return _num(a) and _num(b) and a >= b


def check_fresh_at(token: Any, local: Any, signer: Any, scope: Any, now: Any, max_token_age_ms: Any = None) -> dict:
    """May the verifier decide against ``local`` (its own four counters + policy digest) for a request carrying ``token``?
    Order, each fail-closed: signature / shape, scope, issued in the future (> 60 s skew), token age, policy fork (same
    revision, different digest), any counter behind the token (escalate ``stale_state``)."""
    try:
        if not verify_fresh_at(token, signer):
            return {"decision": "deny", "code": "bad_token"}
        if token["scope"] != scope:
            return {"decision": "deny", "code": "wrong_scope"}
        if not (_num(now) and token["issued_at"] <= now + _SKEW_MS):
            return {"decision": "deny", "code": "token_from_the_future"}
        if max_token_age_ms is not None and not (_num(max_token_age_ms) and now - token["issued_at"] <= max_token_age_ms):
            return {"decision": "deny", "code": "token_too_old"}
        if _num(local.get("policy_revision")) and local["policy_revision"] == token["policy_revision"] \
                and token["policy_digest"] != local.get("policy_digest"):
            return {"decision": "deny", "code": "policy_fork"}
        behind = [k for k in FRESH_AT_NUMERIC if not _ge(local.get(k), token[k])]
        return {"decision": "ok"} if not behind else {"decision": "escalate", "code": "stale_state", "behind": behind}
    except Exception:
        return {"decision": "deny", "code": "bad_token"}


def validate_fresh_at_wire(v: Any) -> Optional[str]:
    """Wire shape of the PCActn member: the problem, or None. Does NOT check the signature (that is the ``fresh_at`` check)."""
    if not is_obj(v):
        return "'fresh_at' must be an object"
    for k in _js_keys(v):
        if k not in _WIRE_KEYS:
            return "'fresh_at' has an unknown field '%s'" % k
    if not is_one(v.get("v")):
        return "'fresh_at.v' must be 1"
    if not is_str(v.get("scope"), 256) or not is_str(v.get("policy_digest"), 128):
        return "'fresh_at' scope and policy_digest must be non-empty strings"
    for k in (*FRESH_AT_NUMERIC, "issued_at"):
        if not is_uint(v.get(k)):
            return "'fresh_at.%s' must be a non-negative safe integer" % k
    if decode_b64u_strict(v.get("signer"), 32) is None:
        return "'fresh_at.signer' is not canonical base64url (32 bytes)"
    if decode_b64u_strict(v.get("sig"), 64) is None:
        return "'fresh_at.sig' is not canonical base64url (64 bytes)"
    return None


def decide_fresh_at(member: Any, policy: Optional[dict], now: Any) -> Dict[str, Any]:
    """The verifier's ``fresh_at`` check. ``member`` is the PCActn's ``fresh_at`` (``ABSENT`` when it has none); ``policy`` is
    ``{signer, scope, local, max_token_age_ms?, require?, side_carried?}`` (``side_carried`` read only when there is no member;
    the key present, even ``None``, means a token was presented). Result ``{status: none|pass|fail, reason?}``: reported only
    when the PCActn carries the member, a side-carried token is read, or the policy requires one. A stale verifier fails with
    an ``escalate:`` reason (the decision fold turns it into escalate); anything else is a hard failure."""
    if policy is None:
        if member is not ABSENT:
            return {"status": "fail", "reason": "the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)"}
        return {"status": "none"}
    if not (is_obj(policy) and isinstance(policy.get("signer"), str) and isinstance(policy.get("scope"), str) and is_obj(policy.get("local"))):
        return {"status": "fail", "reason": "the fresh_at policy is malformed (fail closed)"}
    token = member if member is not ABSENT else policy.get("side_carried", ABSENT)
    if token is ABSENT:
        require = policy.get("require")
        if require is not None and require is not False:
            return {"status": "fail", "reason": "escalate: a consistency token is required (refresh and retry with the token of your latest write)"}
        return {"status": "none"}
    v = check_fresh_at(token, policy["local"], policy["signer"], policy["scope"], now, policy.get("max_token_age_ms"))
    if v["decision"] == "ok":
        return {"status": "pass"}
    if v["decision"] == "escalate":
        return {"status": "fail", "reason": "escalate: stale_state (verifier state is behind the token on %s)" % ", ".join(v["behind"])}
    return {"status": "fail", "reason": v["code"]}
