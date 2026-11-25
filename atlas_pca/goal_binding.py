"""Decision-to-effect binding and the claimed-fidelity gate (the TypeScript reference is @atlasauth/pca-goal `binding`)."""
import hashlib
import hmac
from typing import Any, Dict, Optional

from .decision import tighten
from .pca import b64u, hash_canonical, utf8

__all__ = ["action_digest", "bind_decision", "guard_execute", "claim_gate", "goal_commit", "open_commit"]


def action_digest(a: Any) -> str:
    """Digest of exactly the action that was decided: verb, resource and every parameter."""
    return hash_canonical({"d": "atlas-pca/goal-action/v1", "act": a})


def bind_decision(a: Any, decision: str) -> Dict[str, Any]:
    return {"decision": decision, "action_digest": action_digest(a)}


def guard_execute(b: Any, executed: Any) -> bool:
    """True only for an `allow` bound to exactly this action (swapped params or verb, escalate, deny all refuse). Total."""
    try:
        if b["decision"] != "allow":
            return False
        x, y = b["action_digest"], action_digest(executed)
        if not isinstance(x, str):
            return False
        return hmac.compare_digest(x.encode("utf-8"), y.encode("utf-8"))
    except Exception:  # noqa: BLE001 - total
        return False


def claim_gate(base: str, min_ppm: Any, _claimed_ppm: Any = None, replayed_ppm: Optional[Any] = None) -> str:
    """An agent-claimed fidelity never moves the outcome; only a replayed fidelity below the minimum can, only downward
    (escalate); a NaN or non-numeric replay is unconfirmed and tightens. `replayed_ppm=None` is the reference's undefined."""
    if replayed_ppm is None:
        return base
    try:
        ok = replayed_ppm >= min_ppm and not isinstance(replayed_ppm, bool)
    except TypeError:
        ok = False
    return tighten(base, "escalate") if not ok else base


def goal_commit(goal_digest: str, policy_digest: str, salt: str) -> str:
    """Hiding goal commitment (goal binding v3): sha256("pca-goal:v3:commit:<goal>:<policy>:<salt>"), base64url."""
    return b64u(hashlib.sha256(utf8("pca-goal:v3:commit:%s:%s:%s" % (goal_digest, policy_digest, salt))).digest())


def open_commit(commit: str, goal_digest: str, policy_digest: str, salt: str) -> bool:
    """Constant-time check that `commit` opens to (goal, policy, salt)."""
    if not isinstance(commit, str):
        raise TypeError("commit must be a string")
    return hmac.compare_digest(utf8(commit), goal_commit(goal_digest, policy_digest, salt).encode("ascii"))
