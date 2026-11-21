"""Forbid-wins certificate check (security contract C-241). Port of `certificateConsistent` in
packages/pca/src/forbid-certificate.ts (the TypeScript is authoritative).

A certificate lists, per policy clause, whether it matched (`true` / `unknown` / `false`). The decision, the winner and the
shadowed list follow from that table alone: any matched forbid denies (the most authoritative signer is named, ties by id);
otherwise no matched permit denies; otherwise a matched escalate clause escalates; otherwise allow. This function needs no
predicate evaluator, so every verifier can run it. Total: any malformed certificate is not consistent (never raises)."""
from typing import Any, Dict, List, Optional, Sequence

from .pca import hash_canonical
from .predicates import predicate_matches
from .prohibitions import when_matches

__all__ = ["certificate_consistent", "clauses_error", "decide_clauses", "certify", "check_forbid_certificate", "MAX_CLAUSES"]

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


MAX_CLAUSES = 512  # most clauses one policy may carry (a bound on the certificate size)


def clauses_error(clauses: Any) -> Optional[str]:
    """None = the clause list is well formed (distinct ids, known kinds, a predicate for each)."""
    if not isinstance(clauses, list):
        return "clauses must be an array"
    if len(clauses) > MAX_CLAUSES:
        return "more than %d clauses" % MAX_CLAUSES
    seen = set()
    for i, c in enumerate(clauses):
        if not _is_obj(c):
            return "clauses[%d] must be an object" % i
        cid = c.get("id")
        if not isinstance(cid, str) or len(cid) == 0 or len(cid) > 128:
            return "clauses[%d].id must be a string of 1..128 characters" % i
        if cid in seen:
            return "clauses[%d].id '%s' is a duplicate" % (i, cid)
        seen.add(cid)
        if not isinstance(c.get("kind"), str) or c["kind"] not in _KINDS:
            return "clauses[%d].kind must be permit, forbid or escalate" % i
        if "signer" in c and (not isinstance(c["signer"], str) or len(c["signer"]) > 256):
            return "clauses[%d].signer must be a string of at most 256 characters" % i
        if not _is_obj(c.get("when")):
            return "clauses[%d].when must be a predicate object" % i
    return None


def _value_of(c: Dict[str, Any], ctx: Any) -> str:
    if c["kind"] == "permit":
        return "true" if predicate_matches(c["when"], ctx) else "false"
    # veto polarity: a clean match is true; cannot-decide-but-the-veto-applies is unknown; a clean miss is false
    if not when_matches(c["when"], ctx):
        return "false"
    return "true" if predicate_matches(c["when"], ctx) else "unknown"


def _rank_of(c: Dict[str, Any], precedence: Sequence[str]) -> int:
    s = c.get("signer")
    return list(precedence).index(s) if s is not None and s in precedence else len(precedence)  # an unlisted signer ranks last


def _malformed() -> Dict[str, Any]:
    return {"decision": "deny", "witness": {"winner": {"kind": "malformed", "id": None}, "shadowed": []}, "values": []}


def decide_clauses(clauses: Any, ctx: Any, precedence: Optional[Sequence[str]] = None, permit_signers: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Decide a clause list against an action: any forbid matched denies, else no permit matched denies, else an escalate matched escalates,
    else allow. Order-independent for the decision; the named winner is deterministic (the most authoritative signer's forbid, ties by id).
    ``permit_signers``, when given, drops permits from any other signer. Total: a malformed policy or action is a deny naming ``malformed``."""
    try:
        if clauses_error(clauses) is not None:
            return _malformed()
        a = ctx.get("action") if isinstance(ctx, dict) else None
        if not isinstance(a, dict) or not isinstance(a.get("verb"), str) or not isinstance(a.get("resource"), str):
            return _malformed()
        prec = list(precedence or [])
        active = [c for c in clauses if c["kind"] != "permit" or permit_signers is None or (c.get("signer") is not None and c["signer"] in permit_signers)]
        values = [{"id": c["id"], "kind": c["kind"], "value": _value_of(c, ctx) if any(c is x for x in active) else "false"} for c in clauses]

        def hit(k: str) -> List[Dict[str, Any]]:
            return [c for c, v in zip(clauses, values) if c["kind"] == k and v["value"] != "false"]

        forbids = sorted(hit("forbid"), key=lambda c: (_rank_of(c, prec), _utf16_key(c["id"])))
        permits, escalates = hit("permit"), hit("escalate")

        def others(win: Any) -> List[str]:
            return [c["id"] for c in forbids + permits + escalates if c is not win]

        if forbids:
            return {"decision": "deny", "witness": {"winner": {"kind": "forbid", "id": forbids[0]["id"]}, "shadowed": others(forbids[0])}, "values": values}
        if not permits:
            return {"decision": "deny", "witness": {"winner": {"kind": "none", "id": None}, "shadowed": others(None)}, "values": values}
        if escalates:
            return {"decision": "escalate", "witness": {"winner": {"kind": "escalate", "id": escalates[0]["id"]}, "shadowed": others(escalates[0])}, "values": values}
        return {"decision": "allow", "witness": {"winner": {"kind": "permit", "id": permits[0]["id"]}, "shadowed": others(permits[0])}, "values": values}
    except Exception:  # noqa: BLE001
        return _malformed()


def certify(clauses: Any, ctx: Any, precedence: Optional[Sequence[str]] = None, permit_signers: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Build the canonical certificate for a decision."""
    d = decide_clauses(clauses, ctx, precedence, permit_signers)
    by_id = {c["id"]: c for c in clauses} if isinstance(clauses, list) else {}
    rows = []
    for v in d["values"]:
        row = {"id": v["id"], "kind": v["kind"]}
        signer = by_id.get(v["id"], {}).get("signer")
        if signer is not None:
            row["signer"] = signer
        row["value"] = v["value"]
        rows.append(row)
    return {"v": 1, "kind": "forbid-wins", "policy": hash_canonical(clauses), "action": hash_canonical(ctx), "decision": d["decision"],
            "winner": d["witness"]["winner"], "shadowed": d["witness"]["shadowed"], "clauses": rows}


def check_forbid_certificate(cert: Any, clauses: Any, ctx: Any, precedence: Optional[Sequence[str]] = None,
                             permit_signers: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Recompute the certificate from the clauses and the action; it must match byte for byte (canonical form)."""
    try:
        if clauses_error(clauses) is not None:
            return {"ok": False, "reason": "malformed clauses"}
        if not certificate_consistent(cert, precedence):
            return {"ok": False, "reason": "certificate table does not entail its decision"}
        again = certify(clauses, ctx, precedence, permit_signers)
        if hash_canonical(again) != hash_canonical(cert):
            return {"ok": False, "reason": "certificate does not match the recomputed decision"}
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "certificate check error (fail closed)"}
