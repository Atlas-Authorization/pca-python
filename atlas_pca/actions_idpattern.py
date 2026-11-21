"""Resource id patterns (native port of idpattern.ts of the TypeScript reference @atlasauth/pca-actions): matching and decidable containment."""
import re
from typing import Any, Dict, FrozenSet

from .actions import ID_CLASSES, _id_class_chars, id_pattern_error  # noqa: F401  (id_pattern_error re-exported)

ID_CLASS_CHARS: Dict[str, FrozenSet[str]] = {c: frozenset(_id_class_chars(c)) for c in ID_CLASSES}
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
MAX_ID_LEN = 128


def in_class(s: str, c: str) -> bool:
    chars = ID_CLASS_CHARS[c]
    return all(ch in chars for ch in s)


def id_matches(p: Any, id: Any) -> bool:
    """Does `id` (the id part of a resource, without the type) match the pattern? A non-string id never matches."""
    if not isinstance(id, str):
        return False
    if isinstance(p, str) and p == "*":
        return 0 < len(id) <= MAX_ID_LEN and in_class(id, "any_safe")
    if "exact" in p:
        return id == p["exact"]
    if not id.startswith(p["prefix"]):
        return False
    rest = id[len(p["prefix"]):]
    if len(rest) < p["len"][0] or len(rest) > p["len"][1]:
        return False
    if p["class"] == "uuid":
        return _UUID_RE.fullmatch(rest) is not None
    return in_class(rest, p["class"])


def _class_subset(a: str, b: str) -> bool:
    return ID_CLASS_CHARS[a] <= ID_CLASS_CHARS[b]


def id_pattern_contains(outer: Any, inner: Any) -> bool:
    """Is every id matched by `inner` also matched by `outer`? Sound; an exact id never contains a pattern."""
    if isinstance(outer, str) and outer == "*":
        return True
    if isinstance(inner, str) and inner == "*":
        return False
    if "exact" in outer:
        return not isinstance(inner, str) and "exact" in inner and inner["exact"] == outer["exact"]
    if "exact" in inner:
        return id_matches(outer, inner["exact"])
    if not inner["prefix"].startswith(outer["prefix"]):
        return False
    r = inner["prefix"][len(outer["prefix"]):]
    if not in_class(r, outer["class"]):
        return False
    if outer["class"] == "uuid":
        return inner["class"] == "uuid" and r == ""
    if not _class_subset(inner["class"], outer["class"]):
        return False
    return len(r) + inner["len"][0] >= outer["len"][0] and len(r) + inner["len"][1] <= outer["len"][1]
