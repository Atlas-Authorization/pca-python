"""Reputation and coverage pricing over observed outcomes (the accountability layer above bonds and disputes).

Reputation here is a transparent, explainable function of observed behaviour (deny rate, step-up rate, slashed disputes), not an oracle.
It is ADVISORY: nothing in the verifier or ``authorize`` reads it, and it must not be wired into an allow decision. What is guaranteed:
the score is a pure function of validated input (malformed input scores 0 and says why; a dispute counts once per unique ``id``; a
dispute for another subject is invalid), and a coverage quote is signed and re-derivable. Records are dicts with the reference names."""
from __future__ import annotations

from ._fin import fin
from typing import Any, Dict, Optional

from .agent import KeyPair
from .analyzer_js import to_fixed
from .pca import _verify_b64u, b64u, canonical_bytes
from .predicates import _js_number_string, _js_string

__all__ = ["MAX_REPUTATION_RECORDS", "COVERAGE_QUOTE_DOMAIN", "validate_reputation_input", "reputation", "price_coverage",
           "issue_coverage_quote", "verify_coverage_quote"]

MAX_REPUTATION_RECORDS = 100_000
COVERAGE_QUOTE_DOMAIN = "atlas-pca/coverage-quote/v1\0"
_OUTCOMES = ("auto", "step_up", "deny", "executed")
_ABSENT: Any = object()


def _fin(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


def _num(v: Any) -> str:
    return _js_number_string(float(v))


def validate_reputation_input(inp: Any) -> Optional[str]:
    """Why the input (``{"subject", "events"?, "disputes"?}``) is unusable, or None."""
    subject = inp.get("subject") if isinstance(inp, dict) else None
    if not isinstance(subject, str) or subject == "":
        return "subject must be a non-empty string"
    events, disputes = inp.get("events", []), inp.get("disputes", [])
    if not isinstance(events, list) or not isinstance(disputes, list):
        return "events and disputes must be arrays"
    if len(events) > MAX_REPUTATION_RECORDS or len(disputes) > MAX_REPUTATION_RECORDS:
        return "too many records"
    if any(not isinstance(e, dict) or not isinstance(e.get("outcome"), str) or e["outcome"] not in _OUTCOMES for e in events):
        return "event with an unknown outcome"
    for d in disputes:
        if not isinstance(d, dict) or not isinstance(d.get("id"), str) or d["id"] == "":
            return "dispute without an id"
        if not isinstance(d.get("subject"), str) or d["subject"] != subject:
            return "dispute for another subject"
        if not isinstance(d.get("slashed"), bool):
            return "dispute.slashed must be a boolean"
        if not _fin(d.get("at")) or d["at"] < 0:
            return "dispute.at must be finite and >= 0"
        if "amount" in d and (not _fin(d["amount"]) or d["amount"] < 0):
            return "dispute.amount must be finite and >= 0"
    return None


def reputation(inp: Any) -> Dict[str, Any]:
    """The reputation of ``inp["subject"]``: ``{"subject", "actions", "autos", "stepUps", "denies", "slashes", "disputes", "score",
    "factors"}``. Starts at 1 and subtracts explainable penalties (deny rate, a milder step-up rate, and, dominant, slashed disputes);
    no history scores a neutral 0.5; unusable input scores 0 with the reason in ``factors`` (never the neutral score). Never raises."""
    def out(subject: str, actions: int, autos: int, step_ups: int, denies: int, slashes: int, disputes: int, score: Any, factors: list) -> Dict[str, Any]:
        return {"subject": subject, "actions": actions, "autos": autos, "stepUps": step_ups, "denies": denies, "slashes": slashes,
                "disputes": disputes, "score": score, "factors": factors}
    bad = validate_reputation_input(inp)
    if bad:
        subject = inp.get("subject") if isinstance(inp, dict) else None
        return out("" if subject is None else _js_string(subject), 0, 0, 0, 0, 0, 0, 0, ["invalid input: %s" % bad])
    events = inp.get("events", [])
    seen = set()
    disputes = [d for d in inp.get("disputes", []) if d["id"] not in seen and not seen.add(d["id"])]
    actions = len(events)
    autos, step_ups, denies = (sum(1 for e in events if e["outcome"] == o) for o in ("auto", "step_up", "deny"))
    slashes = sum(1 for d in disputes if d["slashed"])
    if actions == 0 and not disputes:
        return out(inp["subject"], actions, autos, step_ups, denies, slashes, 0, 0.5, ["unproven (no history)"])
    factors = []
    score: Any = 1
    if actions > 0:
        deny_rate, step_up_rate = denies / actions, step_ups / actions
        if deny_rate > 0:
            score -= 0.6 * deny_rate
            factors.append("deny rate %s%%" % to_fixed(deny_rate * 100, 0))
        if step_up_rate > 0:
            score -= 0.15 * step_up_rate
            factors.append("step-up rate %s%%" % to_fixed(step_up_rate * 100, 0))
    if slashes > 0:  # slashes dominate: a heavy, saturating penalty
        score -= min(0.8, 0.3 * slashes)
        factors.append("%d slashed dispute%s" % (slashes, "s" if slashes > 1 else ""))
    if not factors:
        factors.append("clean history")
    return out(inp["subject"], actions, autos, step_ups, denies, slashes, len(disputes), max(0, min(1, score)), factors)


# ---- underwriting -------------------------------------------------------------------------------------------------------

def _opt(opts: Any, key: str, default: Any) -> Any:
    v = opts.get(key) if isinstance(opts, dict) else None
    return default if v is None else v


def price_coverage(rep: Dict[str, Any], exposure: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Price coverage of ``exposure`` for a subject of reputation ``rep["score"]``: premium = baseRate * exposure * (1 + riskLoad *
    (1 - score)), declined below ``minScore``. ``opts``: ``{"baseRate"?: 0.01, "riskLoad"?: 4, "minScore"?: 0.25}``. Returns
    ``{"declined", "premium", "coverage", "rationale"}``; an invalid score is declined and a non-finite exposure counts as 0."""
    base, load, floor = _opt(opts, "baseRate", 0.01), _opt(opts, "riskLoad", 4), _opt(opts, "minScore", 0.25)
    score = rep.get("score", _ABSENT) if isinstance(rep, dict) else _ABSENT
    if not _fin(score) or score < 0 or score > 1:
        return {"declined": True, "premium": 0, "coverage": 0, "rationale": "invalid reputation score"}
    exp = max(0, exposure) if _fin(exposure) else 0
    if score < floor:
        return {"declined": True, "premium": 0, "coverage": 0,
                "rationale": "reputation %s below underwriting floor %s" % (to_fixed(score, 2), _num(floor))}
    factor = 1 + load * (1 - score)
    return {"declined": False, "premium": base * exp * factor, "coverage": exp,
            "rationale": "base %s × exposure %s × load %s (score %s)" % (_num(base), _num(exp), to_fixed(factor, 2), to_fixed(score, 2))}


# ---- signed coverage quotes ---------------------------------------------------------------------------------------------

def _quote_message(claim: Dict[str, Any]) -> bytes:
    return COVERAGE_QUOTE_DOMAIN.encode("utf-8") + canonical_bytes(claim)


def issue_coverage_quote(rep: Dict[str, Any], exposure: Any, underwriter: KeyPair, now: Any, ttl_ms: Any,
                         opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Price and sign a quote as ``underwriter`` (an Ed25519 key pair), valid from ``now`` for ``ttl_ms``. Raises ValueError on a bad
    score, validity or exposure: a nonsense quote is never signed."""
    if not _fin(exposure) or exposure < 0:
        raise ValueError("issueCoverageQuote: exposure must be finite and >= 0")
    if not _fin(now) or not _fin(ttl_ms) or not ttl_ms > 0:
        raise ValueError("issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0")
    if "subject" not in rep:  # an absent member is outside the strict canonical profile: the reference refuses to sign it
        raise ValueError("issueCoverageQuote: the reputation has no subject")
    score = rep.get("score")
    if not _fin(score) or score < 0 or score > 1:
        raise ValueError("issueCoverageQuote: invalid reputation score")
    base, load, floor = _opt(opts, "baseRate", 0.01), _opt(opts, "riskLoad", 4), _opt(opts, "minScore", 0.25)
    p = price_coverage(rep, exposure, {"baseRate": base, "riskLoad": load, "minScore": floor})
    claim = {"v": 1, "subject": rep.get("subject"), "score": score, "exposure": exposure, "baseRate": base, "riskLoad": load, "minScore": floor,
             "declined": p["declined"], "premium": p["premium"], "coverage": p["coverage"], "issued_at": now, "expires_at": now + ttl_ms,
             "underwriter": underwriter.public}
    return dict(claim, sig=b64u(underwriter.sign(_quote_message(claim))))


def verify_coverage_quote(q: Any, underwriter: Any, now: Any) -> Dict[str, Any]:
    """Verify a quote against the pinned ``underwriter`` key at ``now``: the signature, the validity window and the premium RECOMPUTED
    from the stated inputs. ``{"ok": True}`` or ``{"ok": False, "reason"}`` with reason ``malformed`` | ``underwriter`` | ``signature`` |
    ``expired`` | ``not-yet-valid`` | ``price-mismatch``. Never raises."""
    def no(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}
    try:
        if not isinstance(q, dict) or isinstance(q.get("v"), bool) or q.get("v") != 1 or not isinstance(q.get("sig"), str):
            return no("malformed")
        nums = [q.get(k) for k in ("score", "exposure", "baseRate", "riskLoad", "minScore", "premium", "coverage", "issued_at", "expires_at")]
        if any(not _fin(n) for n in nums) or not isinstance(q.get("declined"), bool) or not isinstance(q.get("subject"), str):
            return no("malformed")
        if not isinstance(underwriter, str) or underwriter != q.get("underwriter"):
            return no("underwriter")
        claim = {k: v for k, v in q.items() if k != "sig"}
        if not _verify_b64u(q["underwriter"], _quote_message(claim), q["sig"]):
            return no("signature")
        if not _fin(now) or now < q["issued_at"]:
            return no("not-yet-valid")
        if now >= q["expires_at"]:
            return no("expired")
        p = price_coverage({"score": q["score"]}, q["exposure"], {"baseRate": q["baseRate"], "riskLoad": q["riskLoad"], "minScore": q["minScore"]})
        if p["declined"] != q["declined"] or p["premium"] != q["premium"] or p["coverage"] != q["coverage"]:
            return no("price-mismatch")
        return {"ok": True}
    except Exception:  # noqa: BLE001 - total
        return no("malformed")
