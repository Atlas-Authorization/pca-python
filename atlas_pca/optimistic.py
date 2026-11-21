"""Optimistic-path wire verification: bonded claims, the challenge window, fraud proofs (wire level) and settlement
records. Matches the shared extension-layer vectors. A fraud proof passing `fraud_proof_wire_check` is well-formed and
self-consistent only; recomputing the policy decision it asserts is the settlement layer's job."""
from ._fin import fin
import time
from typing import Any, Dict, Optional

from .intent_v2 import _UNDEF, _pinned_suite_error, suite_capability_error
from .pca import _is_safe_int, _verify_b64u, b64u, canonical_bytes, hash_canonical

DEFAULT_WINDOW_POLICY = {"minWindowMs": 1000, "maxWindowMs": 86_400_000, "defaultWindowMs": 300_000, "maxSkewMs": 5000}
DEFAULT_MIN_CHALLENGE_WINDOW_MS = 30_000
IRREVERSIBLE_CLASS = "irreversible"
_CLAIM_DOMAIN = "atlas-pca/optimistic/v1\0"
_SETTLEMENT_DOMAIN = "atlas-pca/bond-settlement/v1\0"
_FRAUD_KINDS = ("policy-denied", "risk-understated", "optimistic-not-allowed", "irreversible")
_DEFAULT_R_MARGIN = 1e-9
_MISSING = object()


def _num(x: Any) -> bool:
    """A finite JSON number (JS Number.isFinite on a value that is not coerced)."""
    return not isinstance(x, bool) and isinstance(x, (int, float)) and fin(x)


def _same(a: Any, b: Any) -> bool:
    """JS strict equality for JSON values."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def _validate_window(issued_at: Any, window_ms: Any, server_now: Any, policy: dict) -> Optional[str]:
    if not _num(server_now):
        return "server time is not finite"
    if not _num(issued_at) or not _num(window_ms):
        return "malformed challenge window"
    if not (abs(issued_at - server_now) <= policy["maxSkewMs"]):
        return "issued_at is outside the allowed skew of server time"
    if not (window_ms >= policy["minWindowMs"]):
        return "challenge window is below the minimum"
    if not (window_ms <= policy["maxWindowMs"]):
        return "challenge window exceeds the maximum"
    return None


def resolve_window(policy: dict, server_now: Any, requested_ms: Any = None) -> Dict[str, Any]:
    """Server-authoritative window for a new claim: issued_at = server_now, the window = the request (or the policy default) clamped
    up to the realistic 30s floor and down to the policy maximum."""
    if not _num(server_now):
        raise ValueError("resolveWindow: serverNow must be finite")
    want = requested_ms if _num(requested_ms) else policy["defaultWindowMs"]
    floor = max(policy["minWindowMs"], DEFAULT_MIN_CHALLENGE_WINDOW_MS)
    return {"issued_at": server_now, "challenge_window_ms": min(policy["maxWindowMs"], max(floor, want))}


def _claim_message(body: dict) -> bytes:
    return _CLAIM_DOMAIN.encode() + canonical_bytes(body)


def open_optimistic(pcactn: Any, opts: dict, signer_secret: bytes, allow_insecure_signer: bool = False) -> dict:
    """Open an optimistic claim for `pcactn`, signed by the agent-leaf `signer_secret` (a 32-byte Ed25519 seed). Raises (ValueError) when the action is
    irreversible or the window is out of policy. `opts`: bondRef, claimedR, challengeWindowMs?, issuedAt?, serverNow? (default: the wall clock), windowPolicy?."""
    action = pcactn.get("action") if isinstance(pcactn, dict) else None
    rc = action.get("reversibility_class") if isinstance(action, dict) else None
    if rc == IRREVERSIBLE_CLASS:
        raise ValueError("openOptimistic: irreversible actions cannot use the optimistic fast-path (\u00a79A)")
    if not _num(opts.get("claimedR")):
        raise ValueError("openOptimistic: claimedR must be finite")
    policy = DEFAULT_WINDOW_POLICY if opts.get("windowPolicy") is None else opts["windowPolicy"]
    server_now = opts["serverNow"] if _num(opts.get("serverNow")) else int(time.time() * 1000)
    issued_at = opts["issuedAt"] if _num(opts.get("issuedAt")) else server_now
    window_ms = policy["defaultWindowMs"] if "challengeWindowMs" not in opts else opts["challengeWindowMs"]
    bad = _validate_window(issued_at, window_ms, server_now, policy)
    if bad:
        raise ValueError("openOptimistic: %s" % bad)
    body = {"pcactn_digest": hash_canonical(pcactn), "bond_ref": opts.get("bondRef"), "claimed_r": opts["claimedR"],
            "reversibility_class": rc if isinstance(rc, str) else "unknown", "issued_at": issued_at, "challenge_window_ms": window_ms}
    from .agent import KeyPair  # deferred: agent imports the core verifier
    return dict(body, sig=b64u(KeyPair(signer_secret, allow_insecure_signer).sign(_claim_message(body))))


def claim_check(claim: Any, expected_pcactn_digest: str, signer_public: str, server_now: Any, window_policy: Optional[dict] = None) -> str:
    """First failing check of a bonded claim: malformed, irreversible, digest, claimed_r, window, signature; else 'ok'."""
    try:
        if not isinstance(claim, dict):
            return "malformed"
        if claim.get("reversibility_class") == IRREVERSIBLE_CLASS:
            return "irreversible"
        if not _same(claim.get("pcactn_digest", _MISSING), expected_pcactn_digest):
            return "digest"
        if not _num(claim.get("claimed_r")):
            return "claimed_r"
        if _validate_window(claim.get("issued_at"), claim.get("challenge_window_ms"), server_now, window_policy or DEFAULT_WINDOW_POLICY):
            return "window"
        sig = claim.get("sig")
        body = {k: v for k, v in claim.items() if k != "sig"}
        if not isinstance(sig, str) or not _verify_b64u(signer_public, _CLAIM_DOMAIN.encode() + canonical_bytes(body), sig):
            return "signature"
        return "ok"
    except Exception:
        return "malformed"


def challenge_window_end(claim: dict) -> Any:
    """Last instant (epoch ms) a challenge is accepted: issued_at + challenge_window_ms."""
    return claim["issued_at"] + claim["challenge_window_ms"]


def within_challenge_window(claim: dict, now: Any) -> bool:
    """True while challenges are accepted (inclusive end)."""
    return _num(now) and now <= challenge_window_end(claim)


def claim_status(claim: dict, now: Any) -> str:
    """'open' while challenges are accepted, else 'finalized'. A non-finite clock or window end raises: it must never read as finalized."""
    if not _num(now) or not _num(challenge_window_end(claim)):
        raise ValueError("claim_status: the clock and the challenge window must be finite times")
    return "open" if within_challenge_window(claim, now) else "finalized"


def fraud_proof_wire_check(claim: Any, proof: Any) -> str:
    """First failing wire check of a fraud proof: malformed, digest, bond, claimed_r, kind, consistency; else 'ok'."""
    try:
        if not isinstance(proof, dict) or not isinstance(claim, dict):
            return "malformed"
        d = proof.get("decision")
        if not isinstance(d, dict) or not isinstance(d.get("releaseGuardianShare"), bool) or not isinstance(d.get("optimisticAllowed"), bool) or not _num(d.get("r")):
            return "malformed"
        if not all(isinstance(proof.get(k), str) for k in ("pcactn_digest", "bond_ref", "reason")):
            return "malformed"
        if not _same(proof["pcactn_digest"], claim.get("pcactn_digest", _MISSING)):
            return "digest"
        if not _same(proof["bond_ref"], claim.get("bond_ref", _MISSING)):
            return "bond"
        if not _same(proof.get("claimed_r", _MISSING), claim.get("claimed_r", _MISSING)):
            return "claimed_r"
        kind = proof.get("kind")
        if not isinstance(kind, str) or kind not in _FRAUD_KINDS:
            return "kind"
        m = proof.get("r_margin")
        margin = max(0, m) if _num(m) else _DEFAULT_R_MARGIN
        ev = proof.get("evidence")
        ev = ev.get("action") if isinstance(ev, dict) else None
        ev = ev.get("action") if isinstance(ev, dict) else None
        ev_class = ev.get("reversibility_class") if isinstance(ev, dict) else None
        rel, allowed = d["releaseGuardianShare"], d["optimisticAllowed"]
        if kind == "irreversible":
            holds = claim.get("reversibility_class") == IRREVERSIBLE_CLASS or ev_class == IRREVERSIBLE_CLASS
        elif kind == "policy-denied":
            holds = not rel
        elif kind == "optimistic-not-allowed":
            holds = rel and not allowed
        else:
            holds = rel and allowed and d["r"] > claim["claimed_r"] + margin
        return "ok" if holds else "consistency"
    except Exception:
        return "malformed"


def _nonempty(x: Any) -> bool:
    return isinstance(x, str) and len(x) > 0


def _nonneg(x: Any) -> bool:
    return _num(x) and x >= 0


def settlement_wire_check(record: Any, guardian_public: str, pins: Optional[dict] = None) -> str:
    """First failing check of a settlement record: malformed, suite, shape, split, signature; else 'ok'. A suite this
    runtime lacks is `suite`; a PQ / hybrid record verifies only under `pins[guardian_public]` (see atlas_pca.ledger)."""
    try:
        if not isinstance(record, dict):
            return "malformed"
        if suite_capability_error(record.get("alg", _UNDEF)) is not None:
            return "suite"
        r = record
        slash = r.get("action") == "slash"
        ev = r.get("evidenceDigest")
        if (
            not _nonempty(r.get("claimId")) or r.get("action") not in ("open", "release", "slash")
            or not _num(r.get("amount")) or r["amount"] <= 0
            or not _nonempty(r.get("from")) or not _nonempty(r.get("to")) or not _num(r.get("at"))
            or not isinstance(ev, str) or (ev == "" if slash else ev != "")
            or (not isinstance(r.get("split"), dict) if slash else "split" in r)
            or not isinstance(r.get("sig"), str)
            or ("guardian_epoch" in r and not (_is_safe_int(r["guardian_epoch"]) and r["guardian_epoch"] >= 0))
        ):
            return "shape"
        if slash:
            sp = r["split"]
            ca = sp.get("challengerAccount", _MISSING)
            c, v, t = sp.get("challengerReward"), sp.get("victimCompensation"), sp.get("treasuryRemainder")
            ok = (
                _same(sp.get("amount"), r["amount"]) and _nonneg(c) and _nonneg(v) and _nonneg(t)
                and (c + v) + t == r["amount"] and _nonempty(sp.get("victimAccount")) and _same(sp.get("treasuryAccount"), r["to"])
                and ((c == 0 and v == 0 and t == r["amount"]) if ca is None else _nonempty(ca))
            )
            if not ok:
                return "split"
        body = {k: v for k, v in r.items() if k not in ("sig", "pq_sig")}
        msg = _SETTLEMENT_DOMAIN.encode() + canonical_bytes(body)
        bad = _pinned_suite_error(r.get("alg", _UNDEF), guardian_public, r.get("pq_pk", _UNDEF), msg, r["sig"], r.get("pq_sig", _UNDEF), pins)
        return "ok" if bad is None else "signature"
    except Exception:
        return "malformed"
