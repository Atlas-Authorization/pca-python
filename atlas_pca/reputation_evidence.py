"""Reputation from verifiable records: disputes are derived ONLY from guardian-signed settlement records (open / release / slash). A record
whose signature does not verify, or whose bond has no known subject, is counted in ``rejected`` and never becomes a dispute."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Sequence

from .bond_settlement import settlement_record_digest, verify_settlement

__all__ = ["disputes_from_settlements"]


def disputes_from_settlements(records: Sequence[Any], guardian_public: str, subject_of: Callable[[str], Optional[str]],
                              pins: Optional[dict] = None) -> Dict[str, Any]:
    """``{"disputes": [{"id", "subject", "slashed", "at", "amount"?}], "rejected": n}`` from settlement records signed by
    ``guardian_public``. ``subject_of(claim_id)`` maps a bond to the subject it was posted for (None: unknown, the record is rejected).
    An ``open`` record is not an outcome. The dispute id is the record's digest, so a repeated record counts once in a reputation."""
    disputes, rejected = [], 0
    for r in records:
        subject = subject_of(r["claimId"]) if isinstance(r, dict) and isinstance(r.get("claimId"), str) else None
        if subject is None or not verify_settlement(r, guardian_public, pins):
            rejected += 1
            continue
        if r.get("action") == "open":
            continue
        d = {"id": settlement_record_digest(r), "subject": subject, "slashed": r.get("action") == "slash", "at": r.get("at")}
        if "amount" in r:
            d["amount"] = r["amount"]
        disputes.append(d)
    return {"disputes": disputes, "rejected": rejected}
