"""Trait selectors and the registry-growth semantics (native port of selector.ts of the TypeScript reference @atlasauth/pca-actions)."""
from typing import Any, Iterable, Optional


def selector_matches(s: dict, closure: Iterable[str]) -> Optional[bool]:
    """Does the selector match an action whose trait closure is `closure`? An unknown selector kind yields None (falsy), as the reference."""
    cl = set(closure)
    k = s.get("k")
    if k == "trait":
        return s["id"] in cl
    if k == "all_of":
        return all(i in cl for i in s["ids"])
    if k == "any_of":
        return any(i in cl for i in s["ids"])
    if k == "not":
        return not selector_matches(s["s"], cl)
    if k == "and":
        return bool(selector_matches(s["a"], cl)) and bool(selector_matches(s["b"], cl))
    return None


def selector_matches_for(s: dict, mode: str, closure: Iterable[str], confirmed: bool) -> Optional[bool]:
    """Unconfirmed = maximally dangerous: every prohibit selector matches it, no allow selector ever does; the closure is not consulted."""
    if not confirmed:
        return mode == "prohibit"
    return selector_matches(s, closure)


def selector_has_not(s: dict) -> bool:
    k = s.get("k")
    if k == "not":
        return True
    if k == "and":
        return selector_has_not(s["a"]) or selector_has_not(s["b"])
    return False


def _any_of(x: dict) -> bool:
    k = x.get("k")
    if k == "any_of":
        return True
    if k == "and":
        return _any_of(x["a"]) or _any_of(x["b"])
    return False


def allow_selector_error(s: dict, pinned: bool) -> Optional[str]:
    """T7 typing rule for an ALLOW selector: no negation, and any_of only in a pinned allow. None = allowed."""
    if selector_has_not(s):
        return "an allow selector must not use negation: the absence of a trait is never a safety claim"
    if not pinned and _any_of(s):
        return "any_of in an allow selector requires the grant to be pinned to a pack digest"
    return None


def policy_decision(p: dict, verb: str, closure: Iterable[str], confirmed: bool) -> str:
    """A matching prohibit denies; a pinned verb with a matching allow is allowed; an unpinned verb is deny/escalate; else deny."""
    cl = set(closure)
    if any(selector_matches_for(s, "prohibit", cl, confirmed) for s in p["prohibit"]):
        return "deny"
    if verb not in p["pinned"]:
        return "escalate" if p.get("on_new_action") == "escalate" else "deny"
    return "allow" if any(selector_matches_for(s, "allow", cl, confirmed) for s in p["allow"]) else "deny"
