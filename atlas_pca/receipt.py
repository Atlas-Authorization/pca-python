"""Action receipts: a tamper-evident client-side record (the TypeScript ``receipt``). The transparency ledger is the server's witnessed
record; a receipt log is the PRINCIPAL's local, hash-chained copy of what their agents did and how each action was verified. Each receipt
commits to the previous one, so a dropped or altered entry is detectable. Pure (hashing only). A receipt is a dict with the reference's
member names: ``seq``, ``at``, ``actionDigest``, ``verb``, ``resource``, ``outcome``, ``checks`` (optional), ``prev`` and ``hash``."""
from typing import Any, Dict, List, Optional

from .pca import hash_canonical, pcactn_digest

_ABSENT = object()
__all__ = ["receipt_for", "append_receipt", "verify_receipt_chain", "receipt_head"]


def _body(r: Dict[str, Any]) -> Dict[str, Any]:
    return {"d": "atlas-pca/receipt/v1", "seq": r["seq"], "at": r["at"], "actionDigest": r["actionDigest"], "verb": r["verb"],
            "resource": r["resource"], "outcome": r["outcome"], "checks": r.get("checks"), "prev": r["prev"]}


def receipt_for(prev_hash: str, seq: int, p: Dict[str, Any], verify: Any, at: Optional[int] = None) -> Dict[str, Any]:
    """Build the next receipt in a chain for a verified action. `verify` is a verdict (``allow`` and ``checks``), object or dict."""
    allow = verify.get("allow") if isinstance(verify, dict) else getattr(verify, "allow", False)
    checks = verify.get("checks") if isinstance(verify, dict) else getattr(verify, "checks", None)
    body: Dict[str, Any] = {"seq": seq, "at": p["iat"] if at is None else at, "actionDigest": pcactn_digest(p),
                            "verb": p["action"]["verb"], "resource": p["action"]["resource"],
                            "outcome": "allow" if allow else "deny", "prev": prev_hash}
    if checks is not None:  # an empty map is kept (JS truthiness)
        body["checks"] = checks
    return {**body, "hash": hash_canonical(_body(body))}


def append_receipt(log: List[Dict[str, Any]], p: Dict[str, Any], verify: Any, at: Optional[int] = None) -> List[Dict[str, Any]]:
    """Append a verified action to a receipt log, chaining to the last entry. Returns a new list."""
    last = log[-1] if log else None
    return [*log, receipt_for(last["hash"] if last else "", (last["seq"] if last else -1) + 1, p, verify, at)]


def verify_receipt_chain(log: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Verify a receipt log is an intact hash chain: ``{"ok": True}`` or ``{"ok": False, "brokenAt", "reason"}``."""
    prev = ""
    for i, r in enumerate(log):
        if r.get("seq") != i or isinstance(r.get("seq"), bool):
            seq = r.get("seq", _ABSENT)
            out: Dict[str, Any] = {"ok": False} if seq is _ABSENT else {"ok": False, "brokenAt": seq}  # an absent member is no member, as in the reference
            out["reason"] = "seq %s out of order (expected %d)" % ("undefined" if seq is _ABSENT else "null" if seq is None else seq, i)
            return out
        if r.get("prev") != prev:
            return {"ok": False, "brokenAt": r["seq"], "reason": "prev link mismatch at seq %s" % r["seq"]}
        if hash_canonical(_body(r)) != r.get("hash"):
            return {"ok": False, "brokenAt": r["seq"], "reason": "hash mismatch at seq %s (tampered body)" % r["seq"]}
        prev = r["hash"]
    return {"ok": True}


def receipt_head(log: List[Dict[str, Any]]) -> str:
    """The head hash of a log: a single value that commits to the entire history."""
    return log[-1]["hash"] if log else ""
