"""Lazy elicitation on the wire: the verifier side of the site-signed `pca-intent-required` v1 body (shape check, the signature
against the site's discovery keys, the expiry). Native port of the TypeScript reference (@atlasauth/pca, intent-required.ts); the
signer is `signers_more.sign_intent_required`."""
from __future__ import annotations

from typing import Any, Dict, Optional

from .intent_v2 import (_UNDEF, _js_strict_eq, _pinned_suite_error, _resolve_registered, _unsupported, suite_capability_error)
from .intent_wb import _js_str
from .pca import _b32, canonical_bytes_strict
from .signers_more import _IR_KEYS, _QUESTION_ID, INTENT_REQUIRED_DOMAIN, _cell_coords_error, _is_safe_int

_SIG_MEMBERS = ("alg", "kid", "value", "pq_value")
PROBLEM_BASE = "https://atlasauth.net/pca/problems/"
INTENT_PROBLEM_KINDS = ("intent-required", "intent-denied", "schema-violation", "ceiling")
FRICTIONS = ("tap", "hold", "typed", "device")
_TITLES = {"intent-required": "Principal confirmation required for this action", "intent-denied": "The principal does not intend this action",
           "schema-violation": "The action does not conform to the site action schema",
           "ceiling": "The action is outside a ceiling the principal cannot widen"}
_ERRORS = {"intent-required": "intent_required", "intent-denied": "intent_denied", "schema-violation": "schema_violation", "ceiling": "ceiling"}


def intent_required_shape_error(b: Any, signed: bool = True) -> Optional[str]:
    """Shape of a `pca-intent-required` v1 body (signed unless `signed=False`): None when well formed."""
    if not isinstance(b, dict):
        return "not an object"
    for k in b:
        if k not in _IR_KEYS:
            return "unknown member '%s'" % k
    v = b.get("v")
    if not (isinstance(v, (int, float)) and not isinstance(v, bool) and v == 1) or b.get("kind") != "pca-intent-required":
        return "not a pca-intent-required v1"
    for k in ("session", "map_digest", "schema", "pcactn_digest", "action_digest"):
        if not _b32(b.get(k)):
            return "%s must be canonical base64url (32 bytes)" % k
    cell = b.get("cell")
    if not isinstance(cell, dict) or sorted(cell) != ["coords", "verb"] or not isinstance(cell["verb"], str) or not cell["verb"]:
        return "cell must be {verb, coords}"
    ce = _cell_coords_error(cell["coords"])
    if ce:
        return ce
    if b.get("reason") != "uncertain":
        return "reason must be 'uncertain'"
    if not isinstance(b.get("question_id"), str) or not _QUESTION_ID.fullmatch(b["question_id"]):
        return "question_id must match [A-Za-z0-9_-]{1,64}"
    if b.get("friction") not in ("tap", "hold", "typed", "device"):
        return "unknown friction tier"
    if b.get("delivered_to") not in ("wallet", "agent"):
        return "delivered_to must be 'wallet' or 'agent'"
    if not (_is_safe_int(b.get("expires_at")) and b["expires_at"] >= 0):
        return "expires_at must be a non-negative safe integer"
    if signed:
        s = b.get("sig", _UNDEF)
        if isinstance(s, dict):
            se = suite_capability_error(s.get("alg", _UNDEF))
            if se:
                return "sig.alg: %s" % se
            if "pq_value" in s and not isinstance(s["pq_value"], str):
                return "sig.pq_value must be a string"
        if (not isinstance(s, dict) or any(k not in _SIG_MEMBERS for k in s) or _resolve_registered(s.get("alg", _UNDEF)) is None
                or not isinstance(s.get("kid"), str) or not isinstance(s.get("value"), str)):
            return "sig must be {alg, kid, value, pq_value?}"
    elif "sig" in b:
        return "an unsigned body must not carry sig"
    return None


def _message(b: Dict[str, Any]) -> bytes:
    return INTENT_REQUIRED_DOMAIN.encode("utf-8") + canonical_bytes_strict({k: v for k, v in b.items() if k != "sig"})


def verify_intent_required(b: Any, keys: Any, now: Any) -> Dict[str, Any]:
    """Verify a site-signed body against the site's discovery keys (the action schema's key list). The clock is REQUIRED: a
    `now` that is not a safe integer is refused, never coerced, so expiry can never be skipped. Returns {ok: True} or
    {ok: False, reason}."""
    try:
        if not _is_safe_int(now):
            return {"ok": False, "reason": "the verifier clock is not a safe integer (fail closed)"}
        e = intent_required_shape_error(b)
        if e:
            return {"ok": False, "reason": e}
        if not isinstance(keys, list):
            return {"ok": False, "reason": "the site keys must be an array"}
        kid = b["sig"]["kid"]
        key = next((k for k in keys if isinstance(k, dict) and _js_strict_eq(k.get("kid", _UNDEF), kid)), None)
        if key is None:
            return {"ok": False, "reason": "no site key with kid '%s'" % kid}
        kse = suite_capability_error(key.get("alg", _UNDEF))
        if kse:
            return {"ok": False, "reason": "site key: %s" % kse}
        ka = _resolve_registered(key.get("alg", _UNDEF))
        if ka is None or ka != _resolve_registered(b["sig"].get("alg", _UNDEF)):
            return {"ok": False, "reason": "sig.alg does not match the pinned key suite"}
        pins = {key["pk"]: key["pq_pk"]} if "pq_pk" in key and "pk" in key else None
        err = _pinned_suite_error(ka, key.get("pk"), key.get("pq_pk", _UNDEF), _message(b), b["sig"]["value"], b["sig"].get("pq_value", _UNDEF), pins)
        if err is not None:
            return {"ok": False, "reason": err if _unsupported(err) else "site signature invalid"}
        if not (now <= b["expires_at"]):
            return {"ok": False, "reason": "the question has expired"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001 - total, like the reference
        return {"ok": False, "reason": "malformed intent_required: %s" % e}


def verify_intent_required_at(b: Any, keys: Any, now: Any) -> Dict[str, Any]:
    """:func:`verify_intent_required` with the clock REQUIRED: a missing or non-integer ``now`` is a denial, so expiry can never be skipped."""
    return verify_intent_required(b, keys, now)


def intent_problem(kind: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """The RFC 9457 response for an Intent Layer outcome: status 403, the ``WWW-Authenticate`` challenge and the problem+json body (``opts["body"]``,
    the signed intent_required body, rides in ``pca``; intent-required needs it). An unknown kind keeps the reference's shape: ``error="undefined"``
    and no title."""
    opts = opts or {}
    k = kind if isinstance(kind, str) else None
    params = ['error="%s"' % (_ERRORS[k] if k in _ERRORS else "undefined")]
    body_in = opts.get("body")
    if kind == "intent-required":
        if not body_in:
            raise ValueError("intentProblem: intent-required needs the signed body")
        params += ['session="%s"' % body_in["session"], 'question="%s"' % body_in["question_id"]]
    body: Dict[str, Any] = {"type": PROBLEM_BASE + _js_str(kind), "status": 403}
    if k in _TITLES:
        body["title"] = _TITLES[k]
    if opts.get("detail") is not None:
        body["detail"] = opts["detail"]
    if body_in:
        body["pca"] = body_in
    return {"status": 403, "headers": {"WWW-Authenticate": "PCA " + ", ".join(params), "Content-Type": "application/problem+json"}, "body": body}
