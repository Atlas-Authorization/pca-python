"""L4 information-flow taint and the ``enforce_taint`` gate: a port of the reference ``taint.ts`` and the proved kernels behind it.

The agent's own label is never read: every declared provenance ref is re-classified from facts the SERVER holds (a trusted-input
registry it populated, or its own committed resource graph); a ref the server cannot vouch for is ``agent`` (the worst case). Pure and
deterministic; malformed or absent provenance and any internal error fail CLOSED to taint 1. Labels are dicts ``{"kind", "id"?}``."""
import math
from typing import Any, Dict, List, Optional

from .predicates import _js_number_string

TAINT_LEVELS = ("trusted", "first_party", "tool", "web", "agent")
_RANK = {k: i for i, k in enumerate(TAINT_LEVELS)}
_MAX_RANK = len(TAINT_LEVELS) - 1


def is_taint_level(kind: Any) -> bool:
    """True only for the five real level names."""
    return isinstance(kind, str) and kind in _RANK


def label_rank(label: Any) -> int:
    """Rank of a label; an unknown or non-string kind is the WORST rank (fail closed)."""
    kind = label.get("kind") if isinstance(label, dict) else None
    return _RANK[kind] if is_taint_level(kind) else _MAX_RANK


def taint_value(label: Any) -> float:
    """Normalized taint of a label: trusted 0, first_party 0.25, tool 0.5, web 0.75, agent 1."""
    return label_rank(label) / _MAX_RANK


def join_label(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Least upper bound: the higher-ranked label; equal ranks keep the id only when both agree, else the generic representative."""
    ra, rb = label_rank(a), label_rank(b)
    if ra > rb:
        return a
    if rb > ra:
        return b
    if a.get("id") == b.get("id"):
        return a
    return {"kind": a["kind"]}


def join_labels(labels: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Join over a list of labels; the EMPTY lineage joins to the worst case ("no verifiable trusted input" is not "trusted")."""
    if not labels:
        return {"kind": "agent"}
    acc = labels[0]
    for lab in labels[1:]:
        acc = join_label(acc, lab)
    return acc


class InMemoryTrustedInputRegistry:
    """The server's trusted-input registry: content digest -> label. Only the server populates it; nothing an agent sends reaches it."""

    def __init__(self) -> None:
        self._m: Dict[str, Dict[str, Any]] = {}

    def record(self, digest: Any, label: Any) -> "InMemoryTrustedInputRegistry":
        if isinstance(digest, str) and digest and isinstance(label, dict) and is_taint_level(label.get("kind")):
            self._m[digest] = dict(label)
        return self

    def record_trusted(self, digest: str) -> "InMemoryTrustedInputRegistry":
        return self.record(digest, {"kind": "trusted"})

    def record_first_party(self, digest: str) -> "InMemoryTrustedInputRegistry":
        return self.record(digest, {"kind": "first_party"})

    def record_tool(self, digest: str, tool_id: str) -> "InMemoryTrustedInputRegistry":
        return self.record(digest, {"kind": "tool", "id": tool_id})

    def record_web(self, digest: str) -> "InMemoryTrustedInputRegistry":
        return self.record(digest, {"kind": "web"})

    def lookup(self, digest: str) -> Optional[Dict[str, Any]]:
        lab = self._m.get(digest)
        return dict(lab) if lab is not None else None

    @property
    def size(self) -> int:
        return len(self._m)


EMPTY_REGISTRY = type("EmptyRegistry", (), {"lookup": staticmethod(lambda digest: None)})()


def classify_ref(ref: Any, registry: Any, resource_graph: Any = None) -> Dict[str, Any]:
    """Independently classify ONE declared provenance ref (never reading the agent's own label): the registry's label, else first_party for a
    node of the resource graph, else agent. A non-string or empty ref is malformed (agent)."""
    if not isinstance(ref, str) or not ref:
        return {"kind": "agent"}
    vouched = registry.lookup(ref)
    if isinstance(vouched, dict) and is_taint_level(vouched.get("kind")):
        return vouched
    try:
        if resource_graph is not None and resource_graph.node(ref):
            return {"kind": "first_party"}
    except Exception:  # noqa: BLE001 - the worst case
        pass
    return {"kind": "agent", "id": ref} if len(ref) <= 128 else {"kind": "agent"}


def _invalid(reason: str) -> Dict[str, Any]:
    return {"taint": 1, "label": {"kind": "agent"}, "refs": [], "valid": False, "reason": reason}


def compute_taint(provenance: Any, registry: Any, resource_graph: Any = None) -> Dict[str, Any]:
    """``{"taint", "label", "refs", "valid", "reason"?}`` for a PCActn's provenance: all-trusted verified lineage is 0, any unverifiable, web or
    agent ref is high, an empty lineage is 1. Absent or malformed provenance, a non-array or non-string ``trusted_refs`` and a missing registry
    return ``{"taint": 1, "valid": False}``. Never raises."""
    try:
        reg_ok = callable(getattr(registry, "lookup", None))
        prov_ok = isinstance(provenance, dict)
        refs: List[Any] = []
        if reg_ok and prov_ok and "trusted_refs" in provenance:
            raw = provenance["trusted_refs"]
            if not isinstance(raw, list):
                return _invalid("taint: trusted_refs must be an array")
            if not all(isinstance(r, str) and r for r in raw):
                return _invalid("taint: trusted_refs must be non-empty strings")
            refs = raw
        if not reg_ok:
            return _invalid("taint: no trusted-input registry")
        if not prov_ok:
            return _invalid("taint: provenance is absent or malformed")
        classified = [{"ref": r, "label": classify_ref(r, registry, resource_graph)} for r in refs]
        label = join_labels([c["label"] for c in classified])
        return {"taint": label_rank(label) / _MAX_RANK, "label": label, "refs": classified, "valid": True}
    except Exception as e:  # noqa: BLE001
        return _invalid("taint: evaluation error (fail closed): %s" % e)


def taint_gate(provenance: Any, registry: Any, resource_graph: Any, max_taint: Any) -> Dict[str, Any]:
    """The ``enforce_taint`` gate: ``{"ok": True}`` or ``{"ok": False, "reason"}``. ``max_taint`` is the largest taint the policy accepts; a
    negative or non-numeric bound is a misconfiguration and never passes."""
    try:
        t = compute_taint(provenance, registry, resource_graph)
        if not t["valid"]:
            return {"ok": False, "reason": t.get("reason") or "provenance lineage is not server-verifiable (fail closed)"}
        if not (isinstance(max_taint, (int, float)) and not isinstance(max_taint, bool) and math.isfinite(max_taint) and max_taint >= 0):
            return {"ok": False, "reason": "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"}
        allowed = max((r for r in range(_MAX_RANK + 1) if r / _MAX_RANK <= max_taint), default=-1)
        if label_rank(t["label"]) <= allowed:
            return {"ok": True}
        return {"ok": False, "reason": "information-flow taint %s exceeds policy max %s" % (_js_number_string(t["taint"]), _js_number_string(max_taint))}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "taint gate error (fail closed): %s" % e}
