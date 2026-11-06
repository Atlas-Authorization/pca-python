"""Policy classes (NIST NGAC idea): a decision is the meet of the answers of every class consulted, and the record names who said
no. Fail-strict: no class is a deny, a malformed list, a duplicate or an unknown class is a deny. Total: nothing raises.
Port of packages/pca/src/policy-classes.ts; replays policy-classes-vectors.json."""
from typing import Any, Dict, Optional

from .decision import meet_all
from .k3 import is_obj, is_str, is_uint

POLICY_CLASSES = ("constitution", "regulatory", "org", "blueprint", "user")
MAX_POLICY_CLASSES = len(POLICY_CLASSES)
_MEMBERS = ("class", "revision", "digest", "decision")


def class_verdicts_error(lst: Any) -> Optional[str]:
    """None = a well-formed list: closed members, known classes, each at most once."""
    if not isinstance(lst, list):
        return "policy classes must be an array"
    if len(lst) > MAX_POLICY_CLASSES:
        return f"more than {MAX_POLICY_CLASSES} policy classes"
    seen = set()
    for i, v in enumerate(lst):
        if not is_obj(v):
            return f"policy_classes[{i}] must be an object"
        for k in v:
            if k not in _MEMBERS:
                return f"policy_classes[{i}] has unknown member '{k}'"
        c = v.get("class")
        if not isinstance(c, str) or c not in POLICY_CLASSES:
            return f"policy_classes[{i}].class is not a known class"
        if c in seen:
            return f"policy class '{c}' appears twice"
        seen.add(c)
        if not is_uint(v.get("revision")):
            return f"policy_classes[{i}].revision must be a non-negative safe integer"
        if not is_str(v.get("digest"), 128):
            return f"policy_classes[{i}].digest invalid"
        if v.get("decision") not in ("allow", "escalate", "deny"):
            return f"policy_classes[{i}].decision must be allow, escalate or deny"
    return None


def _deny(reason: str) -> Dict[str, Any]:
    return {"decision": "deny", "classes": [], "denied_by": [], "escalated_by": [], "reason": reason}


def decide_classes(lst: Any) -> Dict[str, Any]:
    try:
        if isinstance(lst, list) and len(lst) == 0:
            return _deny("no_policy_class")
        e = class_verdicts_error(lst)
        if e:
            return _deny(f"malformed policy classes: {e}")
        classes = [{"class": v["class"], "revision": v["revision"], "digest": v["digest"], "decision": v["decision"]}
                   for v in sorted(lst, key=lambda v: POLICY_CLASSES.index(v["class"]))]
        return {
            "decision": meet_all([c["decision"] for c in classes]),
            "classes": classes,
            "denied_by": [c["class"] for c in classes if c["decision"] == "deny"],
            "escalated_by": [c["class"] for c in classes if c["decision"] == "escalate"],
        }
    except Exception:
        return _deny("evaluation error (fail closed)")
