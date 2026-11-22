"""The one signer of the goal-to-decision flow (the TypeScript reference is @atlasauth/pca-goal `sign`): artifacts (approvals,
test sets, policy pins, precedents) signed with the suite-agile signer under a per-kind domain over STRICT canonical bytes.
Signing needs the optional `cryptography` extra (Ed25519) and, for a PQ suite, the ML-DSA backend; nothing here rolls a primitive."""
from typing import Any, Dict, Optional, Sequence, Union

from .agent import KeyPair, PqKeyPair, sign_artifact
from .intent_wb import artifact_suite_error, verify_artifact_sig

__all__ = ["goal_domain", "signer_id", "sign_goal_artifact", "verify_goal_artifact", "sign_payload", "verify_payload"]


def goal_domain(kind: str) -> str:
    """Domain separation: an artifact of one kind never verifies as another kind."""
    return "atlas-pca/goal/%s/v1\0" % kind


def _kp(secret: Union[bytes, bytearray, KeyPair]) -> KeyPair:
    return secret if isinstance(secret, KeyPair) else KeyPair(bytes(secret))


def signer_id(secret: Union[bytes, KeyPair]) -> str:
    """The pinned public identity (b64u Ed25519) of a signer secret (a 32-byte seed or a KeyPair)."""
    return _kp(secret).public


def sign_goal_artifact(kind: str, body: Dict[str, Any], secret: Union[bytes, KeyPair], alg: Optional[str] = None,
                       pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """Sign a flat artifact body (it must already carry its signer identity member). Raises on a non-canonical body."""
    return sign_artifact(goal_domain(kind), body, _kp(secret), alg, pq)


def verify_goal_artifact(kind: str, artifact: Any, signer_field: str, pins: Sequence[Any]) -> bool:
    """Verify against the caller's PINNED signers: the pin whose `pk` equals the artifact's own signer member must verify. Total."""
    try:
        if not isinstance(artifact, dict):
            return False
        if artifact_suite_error(artifact) is not None:
            return False
        who = artifact.get(signer_field)
        if not isinstance(who, str):
            return False
        pin = None
        for p in pins:
            pk = p if isinstance(p, str) else (p.get("pk") if isinstance(p, dict) else None)
            if p is None:  # a null pin makes the reference throw: refuse
                return False
            if pk == who:
                pin = p
                break
        return pin is not None and verify_artifact_sig(goal_domain(kind), artifact, pin)
    except Exception:  # noqa: BLE001 - total
        return False


def sign_payload(kind: str, payload: Any, secret: Union[bytes, KeyPair], alg: Optional[str] = None,
                 pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents."""
    return sign_goal_artifact(kind, {"v": 1, "kind": kind, "signer": signer_id(secret), "payload": payload}, secret, alg, pq)


def verify_payload(s: Any, kind: str, pins: Sequence[Any]) -> bool:
    if not isinstance(s, dict):
        return False
    v = s.get("v")
    return (isinstance(v, (int, float)) and not isinstance(v, bool) and v == 1 and s.get("kind") == kind
            and verify_goal_artifact(kind, s, "signer", pins))
