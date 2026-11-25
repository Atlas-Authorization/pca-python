"""Signed human confirmation, producer side (native port of the signing half of confirmation.ts of the TypeScript reference
@atlasauth/pca-actions). The verifier half (review_message, verb_confirmation_error, verify_attestation) lives in actions.py."""
from typing import Any, Mapping

from .actions import REVIEW_DOMAIN, VERB_FACTS_DOMAIN, KEY_ROLES, _blank_reason, _sort_uniq, _u16key, facts_digest, review_message  # noqa: F401
from .agent import KeyPair
from .pca import b64u


def blank_reason(s: str) -> bool:
    """True iff the dismissal reason is nothing but whitespace and the C0 separators."""
    return _blank_reason(s)


def sign_review(b: Mapping[str, Any], secret: bytes) -> dict:
    """The ReviewRef for body `b` (final_traits sorted and distinct, dismissed sorted by trait), signed with a 32-byte Ed25519 seed."""
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != 32:
        raise ValueError("the reviewer key must be a 32-byte Ed25519 secret")
    norm = dict(b)
    norm["final_traits"] = _sort_uniq(b["final_traits"])
    norm["dismissed"] = sorted(b["dismissed"], key=lambda d: _u16key(d["trait"]))
    return {**norm, "sig": b64u(KeyPair(bytes(secret)).sign(review_message(norm)))}
