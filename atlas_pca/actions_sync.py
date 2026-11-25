"""Keep a platform's action definitions in step with the sources they were imported from (native port of sync.ts of the TypeScript
reference @atlasauth/pca-actions). Pure: the caller fetches the source and stores the lock. A def the lock does not attribute to this
source is never touched; a changed operation is never carried over as confirmed."""
from typing import Any, Callable, Dict, List, Optional

from .actions import CORE_REGISTRY, _u16key, def_digest
from .actions_diff import diff_defs


def _as_imported(d: dict) -> dict:
    return {**d, "review": {"state": "unreviewed"}} if d["review"]["state"] == "confirmed" else d


def sync_source(current: List[dict], imported: List[dict], spec_digest: str, now: Any, lock: Optional[dict] = None,
                registry: Optional[Dict[str, dict]] = None, attestation_verified: Optional[Callable[[dict], Any]] = None) -> dict:
    """Merge a fresh import of one source into the current defs: {defs, entries, deprecated, lock, needsReview}."""
    reg = CORE_REGISTRY if registry is None else registry
    cur = {d["verb"]: d for d in current}
    imp = {d["verb"]: _as_imported(d) for d in imported}
    locked_ops = (lock or {}).get("ops") or {}
    ops: Dict[str, str] = {}
    entries: List[dict] = []
    defs: List[dict] = []
    for verb in sorted(imp, key=_u16key):
        d = imp[verb]
        dg = def_digest(d)
        ops[verb] = dg
        old = cur.get(verb)
        locked = locked_ops.get(verb) if lock is not None else None
        if old is None:
            entries.append({"verb": verb, "change": "added"})
            defs.append(d)
        elif locked == dg or (locked is None and def_digest(old) == dg):
            entries.append({"verb": verb, "change": "unchanged"})
            defs.append(old)
        else:
            try:
                diff = diff_defs(old, d, reg, attestation_verified)
            except Exception as e:  # noqa: BLE001
                diff = {"class": "incomparable", "reasons": [str(e)]}
            entries.append({"verb": verb, "change": "changed", "diff": diff})
            defs.append(d)
    deprecated = sorted((v for v in locked_ops if v not in imp), key=_u16key)
    for v in deprecated:
        entries.append({"verb": v, "change": "removed"})
    return {"defs": defs, "entries": entries, "deprecated": deprecated, "lock": {"spec_digest": spec_digest, "ops": ops, "synced_at": now},
            "needsReview": any(e["change"] in ("added", "changed") for e in entries)}


def sync_text(r: dict) -> str:
    """One line per changed entry, then a summary."""
    lines = []
    for e in r["entries"]:
        if e["change"] == "unchanged":
            continue
        diff = e.get("diff")
        extra = ""
        if diff:
            extra = "  (%s%s)" % (diff["class"], ": " + ", ".join(diff["reasons"]) if diff["reasons"] else "")
        lines.append("%s %s%s" % (e["change"].ljust(9), e["verb"], extra))

    def n(c: str) -> int:
        return sum(1 for e in r["entries"] if e["change"] == c)

    lines.append("%d added, %d changed, %d removed (deprecated), %d unchanged%s" % (
        n("added"), n("changed"), n("removed"), n("unchanged"),
        "; added and changed actions are unreviewed (strict) until a reviewer confirms them" if r["needsReview"] else ""))
    return "\n".join(lines)
