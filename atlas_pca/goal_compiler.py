"""Policy canonical bytes and digest (the TypeScript reference is @atlasauth/pca-goal `compiler`). The typed front door of the
proved goal compiler (typecheck / compile / decide / render over the extracted Dafny code) is not native: it needs the verified
core, which only the TypeScript package carries."""
import hashlib
from typing import Any

from .analyzer_js import u16key
from .goal_normalize import jq
from .pca import b64u

__all__ = ["canonical_policy", "policy_digest"]


def canonical_policy(p: Any) -> str:
    """Canonical text of a policy (sorted-key JSON, no floats), the input of the policy digest."""
    if p is None or not isinstance(p, (dict, list, tuple)):
        return jq(p)
    if isinstance(p, (list, tuple)):
        return "[" + ",".join(canonical_policy(x) for x in p) + "]"
    return "{" + ",".join(jq(k) + ":" + canonical_policy(p[k]) for k in sorted(p, key=u16key)) + "}"


def policy_digest(p: Any) -> str:
    return b64u(hashlib.sha256(canonical_policy(p).encode("utf-8")).digest())
