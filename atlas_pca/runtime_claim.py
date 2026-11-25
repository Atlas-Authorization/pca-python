"""Runtime-class claims (verification side): a signed statement that an agent's sandbox runs at a class.

Valid only if signed by a pinned attestor over ``domain || canonical(claim without sig)``, about this passport, inside its
validity window, over evidence the caller has already verified (its digest is in ``verified_evidence``). Anything else, and any
claim with a member beyond the eight, is ``none``. Total: never raises.
"""
from typing import Any, Iterable

from .k3 import is_obj, is_str, is_uint, is_one, verify_body

RUNTIME_CLAIM_DOMAIN = "atlas-pca/runtime-class-claim/v1\0"
RUNTIME_CLASSES = ("none", "os_confined", "egress_default_deny", "wasi_no_ambient")
_KEYS = {"v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig"}


def verified_runtime_class(claim: Any, pinned_attestors: Iterable[str], passport_digest: str,
                           verified_evidence: Iterable[str], now: Any) -> str:
    try:
        c = claim
        if not is_obj(c) or set(c.keys()) != _KEYS or not is_one(c.get("v")) or c.get("class") not in RUNTIME_CLASSES:
            return "none"
        if not (is_str(c.get("attestor"), 128) and is_str(c.get("passport_digest"), 128) and is_str(c.get("evidence_digest"), 128)):
            return "none"
        if c["attestor"] not in list(pinned_attestors) or c["passport_digest"] != passport_digest:
            return "none"
        if c["evidence_digest"] not in list(verified_evidence):
            return "none"
        if not (is_uint(c.get("iat")) and is_uint(c.get("exp")) and is_uint(now)) or not (c["iat"] <= now < c["exp"]):
            return "none"
        body = {k: v for k, v in c.items() if k != "sig"}
        return c["class"] if verify_body(RUNTIME_CLAIM_DOMAIN, body, c["attestor"], c.get("sig")) else "none"
    except Exception:
        return "none"
