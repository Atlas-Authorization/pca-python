"""Content digests of the goal-to-decision flow (the TypeScript reference is @atlasauth/pca-goal `digests`): strict canonical JSON,
safe integers only. A float, None-key or cycle raises TypeError."""
from typing import Any, Dict, Sequence

from .analyzer_js import u16key
from .pca import hash_canonical

__all__ = ["goal_digest", "nl_digest", "model_set_digest", "approval_digest"]


def goal_digest(goal: Any) -> str:
    """Digest of the whole signed Goal."""
    return hash_canonical({"d": "atlas-pca/goal-ir/v1", "goal": goal})


def nl_digest(instruction: str) -> str:
    """Digest of the instruction text a goal was interpreted from (what `Goal.nlDigest` must equal)."""
    return hash_canonical({"d": "atlas-pca/goal-nl/v1", "text": instruction})


def model_set_digest(models: Sequence[str]) -> str:
    """Digest of the model set that produced a goal: sorted (UTF-16 order), de-duplicated ids."""
    return hash_canonical({"d": "atlas-pca/goal-model-set/v1", "models": sorted(set(models), key=u16key)})


def approval_digest(body: Dict[str, Any]) -> str:
    """Digest of an approval's covered fields (the digests it pins plus its expiry): any changed member changes it."""
    return hash_canonical({"d": "atlas-pca/goal-approval-body/v1", "body": body})
