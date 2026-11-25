"""Signed agent passport verification (wire level), the native counterpart of `verifyPassport` in @atlasauth/pca.

Same reason codes and check order; the reason text is not part of the contract. Every signature suite this verifier can
verify for PCActns in this runtime (`supported_suites()`) is accepted, the post-quantum ones only under a PQ key pinned for
the issuer (`pq_pins`); a suite it cannot verify is refused with `unsupported_suite`.
Hardware evidence: the age rule, the binding handed to the verifier and the identity comparison are enforced here. The vendor
attestation verification comes from `attest(document, expected)` returning `{"ok", "bound", "measured"}` (an integrator's own
verifier; it wins when given) or from `default_verifier`, a verifier built by `atlas_pca.attest.verifier_from_config(vendor,
config)` from the vendor configuration (AMD SEV-SNP, Intel TDX DCAP, Azure MAA, GCP Confidential Space, NVIDIA GPU SPDM; needs the
`cryptography` package). With neither, a hardware_rooted passport that passes every other check is refused with
`hardware_verifier_missing` (fail closed, never a software pass).
"""
from typing import Any, Callable, Dict, Optional, Sequence

from .pca import _resolve_pq_key, _resolve_suite, _verify_suite, canonical_bytes_strict, hash_canonical

PASSPORT_SIG_DOMAIN = b"atlas-pca/passport-sig/v1\x00"
DEFAULT_EVIDENCE_AGE_MS = 24 * 3_600_000
MAX_SKEW_MS = 60_000
_MAX_SAFE = 9007199254740991


def _int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if abs(v) <= _MAX_SAFE else None
    if isinstance(v, float) and v.is_integer() and abs(v) <= _MAX_SAFE:
        return int(v)
    return None


def _str(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and v else None


def verify_passport(
    sp: Any,
    trusted_issuers: Sequence[str],
    now_ms: int,
    clock_skew_ms: Optional[int] = None,
    max_evidence_age_ms: Optional[int] = None,
    subject: Optional[str] = None,
    revoked: Optional[Callable[[str, str, str], bool]] = None,
    pq_pins: Optional[Dict[str, str]] = None,
    attest: Optional[Callable[[Any, Dict[str, Any]], Any]] = None,
    default_verifier: Optional[Any] = None,
) -> Optional[str]:
    """None when the passport verifies, else the reason code. `revoked` None, or raising, is `revocation_unavailable`.
    `default_verifier` (an object with `verify(document, expected, now_ms)`, see `atlas_pca.attest`) verifies hardware evidence
    when no `attest` callable is given; `attest` wins."""
    if not isinstance(sp, dict):
        return "malformed"
    p = sp.get("passport")
    if sp.get("typ") != "atlas-pca/passport" or not isinstance(p, dict):
        return "malformed"
    if _int(sp.get("ver")) != 1:
        return "unsupported_version"
    if _resolve_suite(sp)[0] is None:
        return "unsupported_suite"
    iss, sub, sig, pid = _str(sp.get("iss")), _str(sp.get("sub")), _str(sp.get("sig")), _str(p.get("id"))
    hw = p.get("hardware_rooted")
    if not (iss and sub and sig and pid and _str(p.get("model_id")) and _str(p.get("operator")) and isinstance(hw, bool)):
        return "malformed"
    nbf, exp, iat = _int(sp.get("nbf")), _int(sp.get("exp")), _int(sp.get("iat"))
    if nbf is None or exp is None or iat is None or exp <= nbf or abs(now_ms) > _MAX_SAFE:
        return "malformed"
    if iss not in trusted_issuers:
        return "unknown_issuer"
    try:
        canon = canonical_bytes_strict({k: v for k, v in sp.items() if k not in ("sig", "pq_sig")})
    except (TypeError, ValueError, RecursionError):
        return "malformed"
    pq = _resolve_pq_key(iss, sp.get("pq_pk"), pq_pins=pq_pins)
    if not _verify_suite(sp, iss, PASSPORT_SIG_DOMAIN + canon, pq):
        return "bad_signature"
    fp = {"d": "atlas-pca/passport/v1", "hardware_rooted": hw, "operator": p.get("operator")}
    for k in ("model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"):
        fp[k] = p.get(k)
    try:
        if hash_canonical(fp) != pid:
            return "id_mismatch"
    except (TypeError, ValueError):
        return "id_mismatch"
    skew = 0 if clock_skew_ms is None else min(max(clock_skew_ms, 0), MAX_SKEW_MS)
    if now_ms + skew < nbf:
        return "not_yet_valid"
    if now_ms - skew >= exp:
        return "expired"
    if subject is not None and subject != sub:
        return "subject_mismatch"
    if revoked is None:
        return "revocation_unavailable"
    try:
        is_revoked = revoked(pid, iss, sub)
    except Exception:
        return "revocation_unavailable"
    if is_revoked is True:
        return "revoked"
    if hw:
        ev = sp.get("evidence")
        doc = ev.get("document") if isinstance(ev, dict) else None
        at = _int(ev.get("at")) if isinstance(ev, dict) else None
        if not isinstance(doc, dict) or not _str(doc.get("nonce")) or at is None:
            return "hardware_evidence_missing"
        max_age = DEFAULT_EVIDENCE_AGE_MS if max_evidence_age_ms is None else max_evidence_age_ms
        if max_age < 0 or now_ms - at > max_age or at - now_ms > skew:
            return "hardware_evidence_stale"
        if attest is None and default_verifier is not None:
            attest = lambda d, expected: default_verifier.verify(d, expected, now_ms)  # noqa: E731 - the default verifier at the verifier clock
        if attest is None:
            return "hardware_verifier_missing"
        try:
            r = attest(doc, {"holder_pub": sub, "grant_ref": "passport:" + pid, "epoch": 0, "nonce": doc["nonce"]})
        except Exception:
            return "hardware_attestation_failed"
        if not isinstance(r, dict) or r.get("ok") is not True or r.get("bound") is not True:
            return "hardware_attestation_failed"
        if not _identity_matches(p, r.get("measured")):
            return "hardware_identity_mismatch"
    return None


def _identity_matches(p: dict, m: Any) -> bool:
    """The hardware-measured identity equals the claims (model and operator always; the optional digests and the runtime
    measurement when the passport states them; measured weights when it claims them)."""
    if not isinstance(m, dict):
        return False

    def eq(k: str) -> bool:
        return isinstance(p.get(k), str) and p.get(k) == m.get(k)

    if not (eq("model_id") and eq("operator")):
        return False
    for k in ("weights_digest", "runtime_measurement", "system_prompt_digest", "tool_manifest_digest"):
        if k in p and not eq(k):
            return False
    return not (p.get("weights_measured") is True and m.get("weights_measured") is not True)
