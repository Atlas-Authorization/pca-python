"""Risk-priced escalation of the wallet: ask a human iff pBadUpper * loss > interruptionCost, in integer arithmetic (probabilities
in ppm, money in minor units; no floats, no randomness, no clock). Every input is explicit and comes from a principal-SIGNED
configuration; anything missing, out of range or unsigned means ASK. The only learned component is a per-principal multiplier that
scales P(bad) UP, so it can only add asks; asking less needs a principal-signed autonomy raise. A port of the TypeScript
reference (@atlasauth/pca-wallet, escalation-pricing). Signing needs the principal's 32-byte Ed25519 seed."""
from typing import Any, Dict, Mapping, Optional, Sequence

from .ed25519 import sign_secret
from .ed25519 import verify as _ed_verify
from .pca import b64u, hash_canonical, unb64u
from .predicates import _UNDEF
from .wallet_omega import is_number, is_safe_int, u16len

__all__ = [
    "PPM", "MAX_MULTIPLIER_PPM", "sign_pricing_config", "pricing_config_error", "fresh_calibration", "decide_escalation",
    "sign_answer", "update_calibration", "sign_autonomy_raise", "apply_autonomy_raise",
]

PPM = 1_000_000
MAX_MULTIPLIER_PPM = 100 * PPM


def _is_minor(n: Any) -> bool:
    return is_safe_int(n) and n >= 0


def _neg_zero(n: Any) -> bool:
    return isinstance(n, float) and n == 0 and str(n).startswith("-")


def _is_one(v: Any) -> bool:
    return is_number(v) and v == 1


def _msg(kind: str, body: Any) -> bytes:
    return hash_canonical({"kind": kind, "body": body}).encode("utf-8")


def _sig(secret: bytes, kind: str, body: Any) -> str:
    return b64u(sign_secret(secret, _msg(kind, body)))


def _verify(principal: str, kind: str, body: Any, sig: str) -> bool:
    return _ed_verify(unb64u(principal), _msg(kind, body), unb64u(sig))


def sign_pricing_config(body: Dict[str, Any], principal_secret: bytes) -> Dict[str, Any]:
    out = dict(body)
    out["sig"] = _sig(principal_secret, "pca.escalation_pricing", body)
    return out


def pricing_config_error(c: Any) -> Optional[str]:
    """Why a signed pricing configuration is refused, or None (a pure function of its content)."""
    try:
        if not isinstance(c, dict):
            return "config_malformed"
        x = c
        if not _is_one(x.get("v")) or not isinstance(x.get("principal"), str) or not isinstance(x.get("currency"), str) or not isinstance(x.get("sig"), str):
            return "config_malformed"
        if not (_is_minor(x.get("interruptionCost")) and _is_minor(x.get("maxInterruptionCost")) and _is_minor(x.get("hardCeilingLoss")) and _is_minor(x.get("epoch"))):
            return "config_amounts_invalid"
        if x["interruptionCost"] > x["maxInterruptionCost"]:
            return "config_cost_above_max"
        step = x.get("tightenStepPpm")
        if not is_safe_int(step) or step < 0 or step > MAX_MULTIPLIER_PPM:
            return "config_step_invalid"
        body = {k: v for k, v in x.items() if k != "sig"}
        return None if _verify(x["principal"], "pca.escalation_pricing", body, x["sig"]) else "config_signature_invalid"
    except Exception:  # noqa: BLE001 - any decoding or hashing failure is a malformed configuration
        return "config_malformed"


def fresh_calibration() -> Dict[str, Any]:
    return {"multiplierPpm": PPM, "seen": []}


def decide_escalation(config: Dict[str, Any], cal: Any, a: Any) -> Dict[str, Any]:
    """Pure and total: {ask, reason}. Anything unverifiable or out of range asks."""
    e = pricing_config_error(config)
    if e is not None:
        return {"ask": True, "reason": e}
    if not isinstance(a, dict) or a.get("currency") != config["currency"]:
        return {"ask": True, "reason": "currency_mismatch"}
    loss, p = a.get("loss"), a.get("pBadUpperPpm")
    if not _is_minor(loss) or _neg_zero(loss) or not is_safe_int(p) or p < 0 or _neg_zero(p) or p > PPM:
        return {"ask": True, "reason": "risk_input_invalid"}
    mult = cal.get("multiplierPpm") if isinstance(cal, dict) else None
    if not (is_safe_int(mult) and mult >= PPM and mult <= MAX_MULTIPLIER_PPM):
        return {"ask": True, "reason": "calibration_invalid"}
    if loss > config["hardCeilingLoss"]:
        return {"ask": True, "reason": "above_hard_ceiling"}
    pe = int(p) * int(mult)
    capped = PPM * PPM if pe > PPM * PPM else pe
    lhs = capped * int(loss)
    rhs = int(config["interruptionCost"]) * PPM * PPM
    if lhs > rhs:
        return {"ask": True, "reason": "expected_loss_exceeds_interruption_cost"}
    return {"ask": False, "reason": "expected_loss_within_interruption_cost"}


def sign_answer(body: Dict[str, Any], principal_secret: bytes) -> Dict[str, Any]:
    out = dict(body)
    out["sig"] = _sig(principal_secret, "pca.escalation_answer", body)
    return out


def _answer_ok(a: Any, principal: str) -> bool:
    try:
        if not isinstance(a, dict) or not _is_one(a.get("v")) or a.get("principal") != principal:
            return False
        nonce, ad = a.get("nonce"), a.get("action_digest")
        if not isinstance(nonce, str) or u16len(nonce) < 8 or not isinstance(ad, str) or a.get("answer") not in ("approve", "deny"):
            return False
        body = {k: v for k, v in a.items() if k != "sig"}
        return _verify(principal, "pca.escalation_answer", body, a["sig"])
    except Exception:  # noqa: BLE001
        return False


def update_calibration(config: Dict[str, Any], cal: Dict[str, Any], answers: Sequence[Any], risks: Mapping[str, Any]) -> Dict[str, Any]:
    """Fold signed answers into the calibration. A DENY the principal gave to an action that the CURRENT pricing would have
    auto-approved is a miss and adds `tightenStepPpm` (capped); anything else changes nothing. The multiplier never decreases."""
    if pricing_config_error(config) is not None:
        return cal
    mult = cal["multiplierPpm"]
    seen = set(cal["seen"])
    order = list(cal["seen"])
    for a in answers:
        if not _answer_ok(a, config["principal"]) or a["nonce"] in seen:
            continue
        seen.add(a["nonce"])
        order.append(a["nonce"])
        risk = risks.get(a["action_digest"], _UNDEF)
        if a["answer"] != "deny" or risk is _UNDEF:
            continue
        if not decide_escalation(config, {"multiplierPpm": mult, "seen": []}, risk)["ask"]:
            mult = min(MAX_MULTIPLIER_PPM, mult + config["tightenStepPpm"])
    return {"multiplierPpm": max(mult, cal["multiplierPpm"]), "seen": order}


def sign_autonomy_raise(b: Dict[str, Any], secret: bytes) -> Dict[str, Any]:
    out = dict(b)
    out["sig"] = _sig(secret, "pca.autonomy_raise", b)
    return out


def apply_autonomy_raise(config: Dict[str, Any], raise_: Dict[str, Any], principal_secret: bytes) -> Dict[str, Any]:
    """A higher interruption cost means fewer asks. Needs the principal's signature, a strictly newer epoch and a cost within
    `maxInterruptionCost`; raises ValueError otherwise."""
    ok = False
    try:
        b = {k: v for k, v in raise_.items() if k != "sig"}
        ok = _is_one(raise_.get("v")) and raise_.get("principal") == config["principal"] and _verify(config["principal"], "pca.autonomy_raise", b, raise_["sig"])
    except Exception:  # noqa: BLE001 - ok stays False
        ok = False
    if not ok:
        raise ValueError("applyAutonomyRaise: signature or principal invalid")
    if not (raise_["epoch"] > config["epoch"]):
        raise ValueError("applyAutonomyRaise: epoch must advance")
    cost = raise_.get("newInterruptionCost")
    if not _is_minor(cost) or cost > config["maxInterruptionCost"]:
        raise ValueError("applyAutonomyRaise: above the configured maximum")
    body = {k: v for k, v in config.items() if k != "sig"}
    body["interruptionCost"] = cost
    body["epoch"] = raise_["epoch"]
    return sign_pricing_config(body, principal_secret)
