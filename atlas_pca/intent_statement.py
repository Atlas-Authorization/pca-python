"""Intent capture and commitment: the principal's own words plus the structured reading, signed, with a content address
(the intent ref). Native port of the statement artifact of the TypeScript reference (@atlasauth/pca and
@atlasauth/pca-intent): shape, Ed25519 signing, and verification through the verifier-pinned suite dispatch."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from . import ed25519
from .intent_v2 import _UNDEF, _bind_suite_fields, _pinned_suite_error
from .pca import REGISTERED_SUITES, _is_safe_int, b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical

INTENT_SIG_DOMAIN = "atlas-pca/intent/v1\0"
INTENT_REF_DOMAIN = "atlas-pca/intent-ref/v1"
INTENT_SOURCE_KINDS = ("conversation", "ticket", "document", "form", "other")


def _g(o: dict, k: str) -> Any:
    return o.get(k, _UNDEF)


def statement_body(s: dict) -> dict:
    """The signed body: suite fields and signatures excluded (the ref names the content)."""
    b = {k: s[k] for k in ("v", "principal", "text", "slots", "sources", "created_at", "nonce") if k in s and s[k] is not _UNDEF}
    return json.loads(json.dumps(b))


def intent_ref(s: dict) -> str:
    """Content address of an intent statement."""
    return hash_canonical({"d": INTENT_REF_DOMAIN, "s": statement_body(s)})


def _statement_shape_error(s: Any) -> Optional[str]:
    if not isinstance(s, dict):
        return "intent statement is not an object"
    if _g(s, "v") != 1 or isinstance(_g(s, "v"), bool):
        return "unsupported intent statement version"
    if decode_b64u_strict(_g(s, "principal"), 32) is None:
        return "principal is not canonical base64url (32 bytes)"
    text = _g(s, "text")
    if not isinstance(text, str) or len(text) == 0:
        return "text must be a non-empty string"
    if not isinstance(_g(s, "slots"), dict):
        return "slots must be an object"
    sources = _g(s, "sources")
    if not isinstance(sources, list):
        return "sources must be an array"
    for i, src in enumerate(sources):
        if not isinstance(src, dict) or _g(src, "kind") not in INTENT_SOURCE_KINDS or not isinstance(_g(src, "kind"), str):
            return "sources[%d] has an unknown kind" % i
        if _g(src, "uri") is not _UNDEF and not isinstance(src["uri"], str):
            return "sources[%d].uri must be a string" % i
        if decode_b64u_strict(_g(src, "digest"), 32) is None:
            return "sources[%d].digest is not canonical base64url (32 bytes)" % i
    ca = _g(s, "created_at")
    if not _is_safe_int(ca) or ca < 0:
        return "created_at must be a non-negative safe integer (epoch ms)"
    nonce = _g(s, "nonce")
    if not isinstance(nonce, str) or len(nonce) == 0:
        return "nonce must be a non-empty string"
    return None


def _suite_fields_error(a: dict) -> Optional[str]:
    alg = _g(a, "alg")
    if alg is not _UNDEF and (not isinstance(alg, str) or alg not in REGISTERED_SUITES):
        return "unknown signature suite"
    if (alg is _UNDEF or alg == "ed25519") and (_g(a, "pq_pk") is not _UNDEF or _g(a, "pq_sig") is not _UNDEF):
        return "an ed25519 artifact must not carry pq_pk / pq_sig"
    return None


def _message(body: dict) -> bytes:
    return INTENT_SIG_DOMAIN.encode("utf-8") + canonical_bytes_strict(body)


def sign_intent(s: dict, principal_secret: bytes, suite: Any = None) -> dict:
    """Sign a statement as its principal (an Ed25519 seed); `principal` defaults to the key of the seed."""
    if suite is not None and suite.get("alg") not in (None, "ed25519"):
        raise ValueError("signIntentStatement: only Ed25519 signing is supported natively")
    principal = b64u(ed25519.public_key(principal_secret))
    if "principal" in s and s["principal"] != principal:
        raise ValueError("signIntentStatement: principal key mismatch")
    body = statement_body({**s, "principal": principal})
    bad = _statement_shape_error(body)
    if bad:
        raise ValueError("signIntentStatement: %s" % bad)
    return {**body, "sig": b64u(ed25519.sign_secret(principal_secret, _message(body)))}


def verify_intent(s: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Verify a signed statement (shape, signer, suite signature; a PQ key must be pinned via opts["pqPins"]). Never raises."""
    opts = opts or {}
    try:
        bad = _statement_shape_error(s)
        if bad:
            return {"ok": False, "reason": bad}
        if opts.get("expectedSigner") is not None and s["principal"] != opts["expectedSigner"]:
            return {"ok": False, "reason": "principal mismatch"}
        se = _suite_fields_error(s)
        if se:
            return {"ok": False, "reason": se}
        msg = _message(_bind_suite_fields(statement_body(s), _g(s, "alg"), _g(s, "pq_pk")))
        pins = opts.get("pqPins") if isinstance(opts.get("pqPins"), dict) else None
        if _pinned_suite_error(_g(s, "alg"), s["principal"], _g(s, "pq_pk"), msg, _g(s, "sig"), _g(s, "pq_sig"), pins) is not None:
            return {"ok": False, "reason": "bad signature"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "malformed intent statement: %s" % e}
