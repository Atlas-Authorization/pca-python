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
from ._fin import fin
import math
from typing import Any, Callable, Dict, Optional, Sequence

from .intent_v2 import _UNDEF, _js_string
from .intent_wb import _js_str
from .pca import _resolve_pq_key, _resolve_suite, _verify_suite, canonical_bytes_strict, hash_canonical

PASSPORT_SIG_DOMAIN = b"atlas-pca/passport-sig/v1\x00"
DEFAULT_EVIDENCE_AGE_MS = DEFAULT_PASSPORT_EVIDENCE_AGE_MS = 24 * 3_600_000
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


def _skew_of(v: Any) -> float:
    """``Math.min(Math.max(v ?? 0, 0), 60000)`` with the reference's number coercion (a numeric string counts, anything else is NaN: no tolerance)."""
    if v is None:
        v = 0
    if isinstance(v, str):
        try:
            v = float(v.strip() or 0)
        except ValueError:
            v = math.nan
    elif not isinstance(v, (int, float)):
        v = math.nan
    r = min(max(v, 0), MAX_SKEW_MS)
    return 0 if r != r else r  # a NaN skew falls back to none


def verify_passport_verdict(sp: Any, o: dict) -> Dict[str, Any]:
    """Verify a signed passport: ``{"ok": True, passport, iss, sub, exp, hardware_verified}`` or ``{"ok": False, reason, detail?}``; never raises.
    Options ``o``: ``trustedIssuers`` (list of issuer keys), ``now`` (epoch ms), ``clockSkewMs`` (capped at 60 s), ``subject``, ``maxEvidenceAgeMs``
    (default 24 h), ``pqPins`` ({issuer: pq key}), ``revocation`` (``f({"id", "iss", "sub"}) -> bool``; absent or raising is refused) and
    ``attestationVerifier`` (an object with ``verify(document, expected, now_ms)``, or a callable ``f(document, expected)``; without one a hardware
    passport is refused). Same reason codes and check order as the reference."""
    def bad(reason: str, detail: Optional[str] = None) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": False, "reason": reason}
        if detail:
            out["detail"] = detail
        return out
    try:
        p = sp.get("passport") if isinstance(sp, dict) else None
        if not isinstance(sp, dict) or sp.get("typ") != "atlas-pca/passport" or p is None:
            return bad("malformed")
        if _int(sp.get("ver")) != 1:
            return bad("unsupported_version", _js_string(sp.get("ver", _UNDEF)))
        if _resolve_suite(sp)[0] is None:
            return bad("unsupported_suite", _js_str(sp.get("alg")))
        pd = p if isinstance(p, dict) else {}
        iss, sub, sig, pid = _str(sp.get("iss")), _str(sp.get("sub")), _str(sp.get("sig")), _str(pd.get("id"))
        hw = pd.get("hardware_rooted")
        if not (iss and sub and sig and pid and _str(pd.get("model_id")) and _str(pd.get("operator")) and isinstance(hw, bool)):
            return bad("malformed")
        now_ms = o.get("now")
        nbf, exp, iat, now = _int(sp.get("nbf")), _int(sp.get("exp")), _int(sp.get("iat")), _int(now_ms)
        if nbf is None or exp is None or iat is None or now is None or exp <= nbf:
            return bad("malformed", "times")
        trusted = o.get("trustedIssuers")
        if not isinstance(trusted, (list, tuple, set, frozenset)) or iss not in trusted:
            return bad("unknown_issuer")
        try:
            canon = canonical_bytes_strict({k: v for k, v in sp.items() if k not in ("sig", "pq_sig")})
        except (TypeError, ValueError, RecursionError) as e:
            return bad("malformed", str(e) or "error")
        pq = _resolve_pq_key(iss, sp.get("pq_pk"), pq_pins=o.get("pqPins"))
        if not _verify_suite(sp, iss, PASSPORT_SIG_DOMAIN + canon, pq):
            return bad("bad_signature")
        fp = {"d": "atlas-pca/passport/v1", "hardware_rooted": hw, "operator": pd.get("operator")}
        for k in ("model_id", "weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"):
            fp[k] = pd.get(k)
        try:
            if hash_canonical(fp) != pid:
                return bad("id_mismatch")
        except (TypeError, ValueError):
            return bad("id_mismatch")
        skew = _skew_of(o.get("clockSkewMs"))
        if now + skew < nbf:
            return bad("not_yet_valid")
        if now - skew >= exp:
            return bad("expired")
        subject = o.get("subject")
        if subject is not None and subject != sub:
            return bad("subject_mismatch")
        revocation = o.get("revocation")
        if not callable(revocation):
            return bad("revocation_unavailable", "no revocation source")
        try:
            revoked = revocation({"id": pid, "iss": iss, "sub": sub}) is True
        except Exception:  # noqa: BLE001
            return bad("revocation_unavailable")
        if revoked:
            return bad("revoked")
        if hw:
            ev = sp.get("evidence")
            ev = ev if isinstance(ev, dict) else {}
            doc = ev.get("document")
            if not isinstance(doc, dict) or not _str(doc.get("nonce")):
                return bad("hardware_evidence_missing")
            at = _int(ev.get("at"))
            if at is None:
                return bad("hardware_evidence_missing", "evidence.at")
            mx = o.get("maxEvidenceAgeMs")
            max_age = DEFAULT_EVIDENCE_AGE_MS if mx is None else mx
            if isinstance(max_age, bool) or not isinstance(max_age, (int, float)) or not fin(max_age) or max_age < 0 \
                    or now - at > max_age or at - now > skew:
                return bad("hardware_evidence_stale")
            verifier = o.get("attestationVerifier")
            if verifier is None:
                return bad("hardware_verifier_missing")
            try:
                expected = {"holder_pub": sub, "grant_ref": "passport:" + pid, "epoch": 0, "nonce": doc["nonce"]}
                r = verifier(doc, expected) if callable(verifier) else verifier.verify(doc, expected, now)
            except Exception as e:  # noqa: BLE001
                return bad("hardware_attestation_failed", str(e) or "error")
            if not isinstance(r, dict) or r.get("ok") is not True or r.get("bound") is not True:
                reason = r.get("reason") if isinstance(r, dict) else None
                return bad("hardware_attestation_failed", reason if isinstance(reason, str) else None)
            if not _identity_matches(pd, r.get("measured")):
                return bad("hardware_identity_mismatch")
        return {"ok": True, "passport": p, "iss": iss, "sub": sub, "exp": exp, "hardware_verified": hw}
    except Exception as e:  # noqa: BLE001
        return bad("malformed", str(e) or "error")


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
    """None when the passport verifies, else the reason code (see :func:`verify_passport_verdict`). `revoked` None, or raising, is
    `revocation_unavailable`. `default_verifier` (an object with `verify(document, expected, now_ms)`, see `atlas_pca.attest`) verifies hardware
    evidence when no `attest` callable is given; `attest` wins."""
    verifier = attest if attest is not None else default_verifier
    v = verify_passport_verdict(sp, {
        "trustedIssuers": trusted_issuers, "now": now_ms, "clockSkewMs": clock_skew_ms, "maxEvidenceAgeMs": max_evidence_age_ms, "subject": subject,
        "pqPins": pq_pins, "revocation": None if revoked is None else (lambda d: revoked(d["id"], d["iss"], d["sub"])),
        "attestationVerifier": verifier})
    return None if v["ok"] else v["reason"]


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


# ---- extras (passport.ts matchesBinding / trustScore / passportEvidenceBinding / passportAssurance) --------------------------

PASSPORT_VERSION = 1


def passport_evidence_binding(passport_id: str, subject: str, nonce: str) -> Dict[str, Any]:
    """The binding a hardware quote must carry: holder = subject key, grant = passport id, epoch 0, nonce = the evidence nonce."""
    return {"holderPub": subject, "grantRef": "passport:%s" % passport_id, "epoch": 0, "nonce": nonce}


def matches_binding(p: dict, b: dict) -> Dict[str, Any]:
    """Does the passport satisfy a grant's agent binding? ``{"ok", "reasons"}``; a required-but-absent field or an unmet hardware demand fails closed."""
    import re
    reasons = []

    def need(lst: Any, value: Any, label: str) -> None:
        if not lst:
            return
        if value is None:
            reasons.append("%s required by binding but absent from passport" % label)
        elif value not in lst:
            reasons.append("%s '%s' not in allowlist" % (label, value))

    if b.get("model_allowlist") and p.get("model_id") not in b["model_allowlist"]:
        reasons.append("model_id '%s' not in allowlist" % p.get("model_id"))
    need(b.get("weights_allowlist"), p.get("weights_digest"), "weights_digest")
    need(b.get("system_prompt_allowlist"), p.get("system_prompt_digest"), "system_prompt_digest")
    need(b.get("tool_manifest_allowlist"), p.get("tool_manifest_digest"), "tool_manifest_digest")
    if b.get("operator") is not None and p.get("operator") != b["operator"]:
        reasons.append("operator '%s' != required '%s'" % (p.get("operator"), b["operator"]))
    if b.get("require_hardware") and not p.get("hardware_rooted"):
        reasons.append("binding requires a hardware-rooted attestation")
    if b.get("require_measured_weights") and not p.get("weights_measured"):
        reasons.append("binding requires hardware-measured weights")
    if "min_measurement" in b:
        mm = b["min_measurement"]
        if isinstance(mm, str):
            if p.get("runtime_measurement") != mm:
                reasons.append("runtime_measurement does not equal the pinned measurement")
        else:
            bound = mm.get("svn") if isinstance(mm, dict) and len(mm) == 1 else None
            if (isinstance(bound, bool) or not isinstance(bound, (int, float)) or _int(bound) is None or bound < 0
                    or (isinstance(bound, float) and bound == 0 and str(bound)[0] == "-")):  # Object.is(bound, -0)
                reasons.append("min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)")
            else:
                rm = p.get("runtime_measurement", _UNDEF)
                svn = int(rm) if isinstance(rm, str) and re.fullmatch(r"(?:0|[1-9][0-9]*)", rm) and int(rm) <= _MAX_SAFE else None
                if svn is None or svn < bound:
                    reasons.append("runtime SVN %s < required %s" % (_js_string(rm), int(bound)))
    return {"ok": not reasons, "reasons": reasons}


def trust_score(p: dict, known_operators: Optional[Sequence[str]] = None) -> float:
    """A coarse identity-assurance score in [0, 1] from the passport's own completeness (not behavioural reputation)."""
    s = 0.0
    if p.get("hardware_rooted"):
        s += 0.4
    if p.get("weights_digest"):
        s += 0.2 if p.get("weights_measured") else 0.1
    if p.get("system_prompt_digest"):
        s += 0.1
    if p.get("tool_manifest_digest"):
        s += 0.1
    if known_operators and p.get("operator") in known_operators:
        s += 0.2
    return max(0.0, min(1.0, s))


class _PassportRegistry:
    def __init__(self, passports: Any) -> None:
        self._by_id: Dict[Any, Any] = {}
        for p in passports:
            self._by_id[p["id"]] = p  # a later duplicate id replaces the earlier in place

    def get(self, passport_id: Any) -> Any:
        return self._by_id.get(passport_id)

    def has(self, passport_id: Any) -> bool:
        return passport_id in self._by_id

    def all(self) -> list:
        return list(self._by_id.values())


def build_registry(passports: Any) -> _PassportRegistry:
    """A passport registry keyed by id (``get``, ``has``, ``all``; first-appearance order, a later duplicate replaces the earlier)."""
    return _PassportRegistry(passports)


def passport_assurance(verdict: dict, verifier: Any = None) -> Dict[str, Any]:
    """Assurance label for a verified passport: hardware only when the evidence verified through `verifier`."""
    from .authorize import assurance_label_of
    if not verdict.get("hardware_verified"):
        return {"level": "software"}
    label = assurance_label_of(verifier)
    out = {"level": (label or {}).get("level", "unknown")}
    if label and label.get("vendor"):
        out["vendor"] = label["vendor"]
    return out
