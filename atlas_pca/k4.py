"""Money and approvals (K4), verification side: risk-priced escalation (pricing config, decision, calibration from signed answers),
the network-token binding, and the ERC-7715 granted-permission check. Replays packages/pca/conformance/k4-vectors.json.

Signatures are Ed25519 (STRICT) over the UTF-8 bytes of ``hash_canonical({"kind": kind, "body": body})`` (the digest string), where
``body`` is the signed object without its ``sig``. Every function is total: malformed input returns the failure value, never raises.
Escalation is integer-only; probabilities in ppm, money in minor units."""
import re
from typing import Any, Callable, Dict, List, Optional

from .pca import _is_safe_int, decode_b64u_strict, hash_canonical
from . import ed25519

PPM = 1_000_000
MAX_MULTIPLIER_PPM = 100 * PPM
NETWORK_TOKEN_BINDING_KIND = "pca.network_token_binding"

_REF_RE = re.compile(r"[A-Za-z0-9_.:\-]{8,128}")
_HEX_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_HEX_QTY = re.compile(r"0x(0|[1-9a-fA-F][0-9a-fA-F]*)")
_HEX_CTX = re.compile(r"0x[0-9a-fA-F]+")


def _is_minor(n: Any) -> bool:
    return _is_safe_int(n) and n >= 0


def _msg(kind: str, body: dict) -> bytes:
    return hash_canonical({"kind": kind, "body": body}).encode("utf-8")


def _sig_ok(pub: Any, kind: str, obj: dict) -> Optional[bool]:
    """None when the key or signature does not decode; else the strict verification result."""
    body = {k: v for k, v in obj.items() if k != "sig"}
    pk = decode_b64u_strict(pub)
    sg = decode_b64u_strict(obj.get("sig"))
    if pk is None or sg is None:
        return None
    if len(pk) != 32 or len(sg) != 64:
        return False
    return ed25519.verify(pk, _msg(kind, body), sg)


# ---- network-token binding -----------------------------------------------------------------------------------------------

def _luhn(d: str) -> bool:
    total, dbl = 0, False
    for ch in reversed(d):
        n = ord(ch) - 48
        if dbl:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        dbl = not dbl
    return total % 10 == 0


def looks_like_pan(s: str) -> bool:
    runs = re.findall(r"[0-9]+", re.sub(r"[\s\-]", "", s))
    return any(13 <= len(r) <= 19 and _luhn(r) for r in runs)


def token_ref_error(ref: Any) -> Optional[str]:
    if not isinstance(ref, str) or _REF_RE.fullmatch(ref) is None:
        return "token_ref_malformed"
    return "token_ref_looks_like_pan" if looks_like_pan(ref) else None


def verify_network_token_binding(b: Any, grant: Any, holder: str, issuer_nonce: str, provider: Optional[str] = None) -> Optional[str]:
    try:
        if not isinstance(b, dict) or b.get("kind") != NETWORK_TOKEN_BINDING_KIND:
            return "binding_malformed"
        e = token_ref_error(b.get("token_ref"))
        if e is not None:
            return e
        p = b.get("provider")
        if not isinstance(p, str) or p == "" or (provider is not None and p != provider):
            return "provider_mismatch"
        if b.get("grant_digest") != hash_canonical(grant):
            return "grant_digest_mismatch"
        if b.get("holder") != holder:
            return "holder_mismatch"
        if b.get("issuer_nonce") != issuer_nonce:
            return "issuer_nonce_mismatch"
        body = {"kind": NETWORK_TOKEN_BINDING_KIND, "v": 1, "provider": p, "token_ref": b["token_ref"], "grant_digest": b["grant_digest"],
                "issuer_nonce": b["issuer_nonce"], "holder": b["holder"]}
        pk, sg = decode_b64u_strict(b["holder"]), decode_b64u_strict(b.get("binding_proof"))
        if pk is None or sg is None:
            return "binding_malformed"
        ok = len(pk) == 32 and len(sg) == 64 and ed25519.verify(pk, hash_canonical(body).encode("utf-8"), sg)
        return None if ok else "binding_proof_invalid"
    except Exception:
        return "binding_malformed"


# ---- risk-priced escalation ----------------------------------------------------------------------------------------------

def pricing_config_error(c: Any) -> Optional[str]:
    try:
        if not isinstance(c, dict) or c.get("v") != 1 or isinstance(c.get("v"), bool) or not isinstance(c.get("principal"), str) \
                or not isinstance(c.get("currency"), str) or not isinstance(c.get("sig"), str):
            return "config_malformed"
        if not all(_is_minor(c.get(k)) for k in ("interruptionCost", "maxInterruptionCost", "hardCeilingLoss", "epoch")):
            return "config_amounts_invalid"
        if c["interruptionCost"] > c["maxInterruptionCost"]:
            return "config_cost_above_max"
        st = c.get("tightenStepPpm")
        if not _is_safe_int(st) or st < 0 or st > MAX_MULTIPLIER_PPM:
            return "config_step_invalid"
        r = _sig_ok(c["principal"], "pca.escalation_pricing", c)
        return None if r else ("config_malformed" if r is None else "config_signature_invalid")
    except Exception:
        return "config_malformed"


def decide_escalation(config: Any, cal: Any, a: Any) -> Dict[str, Any]:
    e = pricing_config_error(config)
    if e is not None:
        return {"ask": True, "reason": e}
    if not isinstance(a, dict) or a.get("currency") != config["currency"]:
        return {"ask": True, "reason": "currency_mismatch"}
    loss, p = a.get("loss"), a.get("pBadUpperPpm")
    if not _is_minor(loss) or not _is_safe_int(p) or p < 0 or p > PPM:
        return {"ask": True, "reason": "risk_input_invalid"}
    m = cal.get("multiplierPpm") if isinstance(cal, dict) else None
    if not (_is_safe_int(m) and PPM <= m <= MAX_MULTIPLIER_PPM):
        return {"ask": True, "reason": "calibration_invalid"}
    if loss > config["hardCeilingLoss"]:
        return {"ask": True, "reason": "above_hard_ceiling"}
    capped = min(p * m, PPM * PPM)
    if capped * loss > config["interruptionCost"] * PPM * PPM:
        return {"ask": True, "reason": "expected_loss_exceeds_interruption_cost"}
    return {"ask": False, "reason": "expected_loss_within_interruption_cost"}


def _answer_ok(a: Any, principal: str) -> bool:
    try:
        if not isinstance(a, dict) or a.get("v") != 1 or a.get("principal") != principal:
            return False
        n = a.get("nonce")
        if not isinstance(n, str) or len(n) < 8 or not isinstance(a.get("action_digest"), str) or a.get("answer") not in ("approve", "deny"):
            return False
        return _sig_ok(principal, "pca.escalation_answer", a) is True
    except Exception:
        return False


def update_calibration(config: Any, cal: Dict[str, Any], answers: List[Any], risks: Dict[str, Any]) -> Dict[str, Any]:
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
        risk = risks.get(a["action_digest"])
        if a["answer"] != "deny" or risk is None:
            continue
        if not decide_escalation(config, {"multiplierPpm": mult, "seen": []}, risk)["ask"]:
            mult = min(MAX_MULTIPLIER_PPM, mult + config["tightenStepPpm"])
    return {"multiplierPpm": max(mult, cal["multiplierPpm"]), "seen": order}


# ---- ERC-7715 granted-permission check -------------------------------------------------------------------------------------

def _lower(x: Any) -> str:
    return x.lower() if isinstance(x, str) else "\0"


def verify_granted_permission(g: Dict[str, Any], sent: Dict[str, Any], got: Any, allowed_managers: List[str],
                              context_owner: Optional[Callable[[str], Optional[str]]] = None) -> Optional[str]:
    try:
        r = got
        if not isinstance(r, dict) or not isinstance(r.get("permission"), dict):
            return "response_malformed"
        ctx = r.get("context")
        if not isinstance(ctx, str) or _HEX_CTX.fullmatch(ctx) is None:
            return "context_malformed"
        owner = context_owner(ctx) if context_owner else None
        if owner is not None and owner != g["grantDigest"]:
            return "context_bound_to_other_grant"
        m = r.get("delegationManager")
        if not isinstance(m, str) or _HEX_ADDR.fullmatch(m) is None or m.lower() not in [x.lower() for x in allowed_managers]:
            return "delegation_manager_not_allowed"
        if _lower(r.get("chainId")) != _lower(sent["chainId"]):
            return "chain_mismatch"
        if _lower(r.get("to")) != _lower(sent["to"]):
            return "recipient_mismatch"
        if sent.get("from") is not None and _lower(r.get("from")) != _lower(sent["from"]):
            return "from_mismatch"
        perm, sperm = r["permission"], sent["permission"]
        if perm.get("type") != sperm["type"] or perm.get("type") not in ("native-token-allowance", "erc20-token-allowance"):
            return "permission_type_mismatch"
        d, sd = perm["data"], sperm["data"]
        if not isinstance(d, dict):
            return "response_malformed"
        if _lower(d.get("tokenAddress", "")) != _lower(sd.get("tokenAddress", "")):
            return "token_mismatch"
        al = d.get("allowance")
        if not isinstance(al, str) or _HEX_QTY.fullmatch(al) is None:
            return "amount_malformed"
        if int(al, 16) > int(sd["allowance"], 16):
            return "amount_widened"
        if perm.get("isAdjustmentAllowed") != sperm["isAdjustmentAllowed"] and perm.get("isAdjustmentAllowed") is True:
            return "adjustment_widened"
        rules = r.get("rules")
        if not isinstance(rules, list):
            return "expiry_missing"
        expiry = None
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("type") != "expiry":
                return "unknown_rule_type"
            if expiry is not None:
                return "duplicate_expiry"
            ts = rule.get("data", {}).get("timestamp") if isinstance(rule.get("data"), dict) else None
            if not _is_safe_int(ts):
                return "expiry_malformed"
            expiry = ts
        if expiry is None:
            return "expiry_missing"
        if expiry > g["expiresAtSec"]:
            return "expiry_extended"
        return None
    except Exception:
        return "response_malformed"
