"""Forbid-wins certificate check (security contract C-241). Port of `certificateConsistent` in
packages/pca/src/forbid-certificate.ts (the TypeScript is authoritative).

A certificate lists, per policy clause, whether it matched (`true` / `unknown` / `false`). The decision, the winner and the
shadowed list follow from that table alone: any matched forbid denies (the most authoritative signer is named, ties by id);
otherwise no matched permit denies; otherwise a matched escalate clause escalates; otherwise allow. This function needs no
predicate evaluator, so every verifier can run it. Total: any malformed certificate is not consistent (never raises)."""
from typing import Any, Dict, List, Optional, Sequence

__all__ = ["certificate_consistent"]

_KINDS = ("permit", "forbid", "escalate")
_VALUES = ("true", "false", "unknown")


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def certificate_consistent(cert: Any, precedence: Optional[Sequence[str]] = None) -> bool:
    try:
        if not _is_obj(cert) or cert.get("v") != 1 or cert.get("kind") != "forbid-wins" or not isinstance(cert.get("clauses"), list):
            return False
        rows: List[Dict[str, Any]] = cert["clauses"]
        winner = cert.get("winner")
        shadowed = cert.get("shadowed")
        if not _is_obj(winner) or not isinstance(shadowed, list):
            return False
        if winner.get("kind") == "malformed":
            return len(rows) == 0 and cert.get("decision") == "deny" and winner.get("id") is None and len(shadowed) == 0
        prec = list(precedence or [])
        for r in rows:
            if not _is_obj(r) or r.get("kind") not in _KINDS or r.get("value") not in _VALUES or not isinstance(r.get("id"), str):
                return False

        def rank(r: Dict[str, Any]) -> int:
            s = r.get("signer")
            return prec.index(s) if s in prec else len(prec)  # an unlisted (or absent) signer ranks last

        def hit(kind: str) -> List[Dict[str, Any]]:
            return [r for r in rows if r["kind"] == kind and r["value"] != "false"]

        forbids = sorted(hit("forbid"), key=lambda r: (rank(r), _utf16_key(r["id"])))
        permits = hit("permit")
        escalates = hit("escalate")
        if forbids:
            win, decision, kind = forbids[0], "deny", "forbid"
        elif not permits:
            win, decision, kind = None, "deny", "none"
        elif escalates:
            win, decision, kind = escalates[0], "escalate", "escalate"
        else:
            win, decision, kind = permits[0], "allow", "permit"
        others = [r["id"] for r in forbids + permits + escalates if r is not win]
        return (
            cert.get("decision") == decision
            and winner.get("kind") == kind
            and winner.get("id") == (win["id"] if win is not None else None)
            and shadowed == others
        )
    except Exception:  # fail closed: a certificate that cannot be read is not consistent
        return False


def _utf16_key(s: str) -> bytes:
    # The reference orders ids with JavaScript's `<` (UTF-16 code units).
    return s.encode("utf-16-be", "surrogatepass")
