"""Post-quantum co-signature of a verified attestation verdict: a port of the TypeScript reference (@atlasauth/pca-attest-eat).

After the classical AMD SEV-SNP hardware root has been verified, the verdict's security-relevant fields (tier, trustworthy bit,
measured identity, nonce and iat freshness anchor, issuer, co-sign time) are bound under an ML-DSA-65 signature by default (or a
hybrid / nested-hybrid / category-5 suite). This does NOT make AMD's root post-quantum: it makes the recorded verdict
forward-secure against a later break of the classical root. A classical-only suite is refused.

The signed bytes are ``utf8(JSON(obj))`` over a fixed field order with a domain-separating ``typ`` and every optional field
emitted explicitly (its value or null). Secret keys are a dict with the reference's slots: ``edSecret`` (32-byte Ed25519 seed)
and one of ``mlDsa`` / ``mlDsa87`` / ``slhDsa`` / ``slhDsa256s`` (a ``generate_pq_keypair`` key pair for that family).
"""
from typing import Any, Dict, Optional

from .attest_eat_common import G, U, ct_eq, has, is_finite, js_json, js_string, msg_of, now_ms, utf8
from .pca import b64u

__all__ = [
    "PQCOSIGN_DOMAIN", "DEFAULT_PQ_COSIGN_SUITE", "PQ_COSIGN_SUITES", "is_pq_co_sign_suite", "canonical_verdict_bytes",
    "verdict_from_appraisal", "co_sign_attestation", "verify_co_signed_attestation",
]

PQCOSIGN_DOMAIN = "atlas-pca/attest-cosign/v1"
DEFAULT_PQ_COSIGN_SUITE = "ml-dsa-65"
PQ_COSIGN_SUITES = (
    "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-ml-dsa-65",
    "hybrid-nested-ed25519-ml-dsa-65", "hybrid-ed25519-ml-dsa-87", "hybrid-ed25519-slh-dsa-sha2-128f",
    "hybrid-ed25519-slh-dsa-sha2-256s",
)


def is_pq_co_sign_suite(x: Any) -> bool:
    """One of the accepted post-quantum suites (rejects ed25519, unknown names and non-strings)."""
    return isinstance(x, str) and x in PQ_COSIGN_SUITES


def _is_record(v: Any) -> bool:
    return isinstance(v, dict)


def _put(out: Dict[str, Any], k: str, v: Any) -> None:
    if v is not U:  # a JavaScript `undefined` member is absent from JSON.stringify
        out[k] = v


def _canonical_measured(m: Any) -> Any:
    if m is U:
        return None
    out: Dict[str, Any] = {}
    _put(out, "model_id", G(m, "model_id"))
    _put(out, "weights_digest", G(m, "weights_digest"))
    wm = G(m, "weights_measured")
    out["weights_measured"] = wm if isinstance(wm, bool) else None
    _put(out, "runtime_measurement", G(m, "runtime_measurement"))
    _put(out, "operator", G(m, "operator"))
    sp, tm = G(m, "system_prompt_digest"), G(m, "tool_manifest_digest")
    out["system_prompt_digest"] = sp if isinstance(sp, str) else None
    out["tool_manifest_digest"] = tm if isinstance(tm, str) else None
    return out


def canonical_verdict_bytes(verdict: Any, cosigned_at: Any) -> bytes:
    """The CANONICAL, DETERMINISTIC bytes the co-signature is computed over (fixed field order, null for every absent optional)."""
    c: Dict[str, Any] = {"typ": PQCOSIGN_DOMAIN}
    _put(c, "tier", G(verdict, "tier"))
    c["trustworthy"] = G(verdict, "trustworthy") is True
    measurement, nonce, iat, issuer = G(verdict, "measurement"), G(verdict, "nonce"), G(verdict, "iat"), G(verdict, "issuer")
    c["measurement"] = measurement if isinstance(measurement, str) else None
    c["measured"] = _canonical_measured(G(verdict, "measured"))
    c["nonce"] = nonce if isinstance(nonce, str) else None
    c["iat"] = iat if is_finite(iat) else None
    c["issuer"] = issuer if isinstance(issuer, str) else None
    c["cosignedAt"] = cosigned_at
    return utf8(js_json(c))


def verdict_from_appraisal(result: Any, claims: Any) -> Dict[str, Any]:
    """An attestation verdict from an ``appraise`` result plus the EAT claims (tier, trustworthy, measured identity / launch
    measurement, nonce, iat, issuer)."""
    verdict: Dict[str, Any] = {}
    _put(verdict, "tier", G(result, "tier"))
    _put(verdict, "trustworthy", G(result, "trustworthy"))
    measured = G(claims, "measured")
    if measured is not U:
        verdict["measured"] = measured
    rm = G(measured, "runtime_measurement") if measured not in (None, U) else U
    if isinstance(rm, (str, list)) and len(rm) > 0:
        measurement = rm
    else:
        sevsnp = G(claims, "sevsnp")
        measurement = G(sevsnp, "measurement") if sevsnp not in (None, U) else U
    if isinstance(measurement, str) and len(measurement) > 0:
        verdict["measurement"] = measurement
    nonce, iat, iss = G(claims, "eat_nonce"), G(claims, "iat"), G(claims, "iss")
    if isinstance(nonce, str):
        verdict["nonce"] = nonce
    if is_finite(iat):
        verdict["iat"] = iat
    if isinstance(iss, str):
        verdict["issuer"] = iss
    return verdict


# ---------------------------------------------------------------------------------------------------------------- co-sign


def _pq_slot(suite: str) -> str:
    if "ml-dsa-87" in suite:
        return "mlDsa87"
    if "ml-dsa-65" in suite:
        return "mlDsa"
    if "slh-dsa-sha2-128f" in suite:
        return "slhDsa"
    return "slhDsa256s"


def co_sign_attestation(verdict: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """Co-sign a verified verdict under a post-quantum suite (default ml-dsa-65). Call this AFTER the classical hardware check passed.
    FAIL CLOSED on misconfiguration: a classical-only or unknown suite, or missing key material for the suite, raises."""
    from .agent import KeyPair, sign_with_suite
    from .pca import _SIG_SUITES

    suite = G(opts, "suite")
    suite = DEFAULT_PQ_COSIGN_SUITE if suite is U or suite is None else suite
    if not is_pq_co_sign_suite(suite):
        raise ValueError("coSignAttestation: '%s' is not an accepted post-quantum co-sign suite" % js_string(suite))
    keys = G(opts, "secretKey")
    if not _is_record(keys):
        raise TypeError("coSignAttestation: secretKey material is required")
    now = G(opts, "now")
    cosigned_at = now if is_finite(now) else now_ms()
    msg = canonical_verdict_bytes(verdict, cosigned_at)

    slot = _pq_slot(suite)
    pq_key = keys.get(slot)
    if pq_key is None or not hasattr(pq_key, "public_bytes") or not hasattr(pq_key, "sign"):
        raise TypeError("coSignAttestation: suite '%s' requires %s key material" % (suite, slot))
    signer_pub: Dict[str, Any] = {"pq": b64u(pq_key.public_bytes)}
    hybrid = suite.startswith("hybrid")
    ed: Optional[Any] = None
    if hybrid:
        seed = keys.get("edSecret")
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("coSignAttestation: hybrid suite '%s' requires edSecret" % suite)
        ed = KeyPair(bytes(seed))
        signer_pub["ed"] = ed.public
    if pq_key.family != _SIG_SUITES[suite][3]:
        raise TypeError("coSignAttestation: suite '%s' requires %s key material" % (suite, slot))
    parts = sign_with_suite(suite, ed, pq_key, msg)
    cosig: Dict[str, Any] = {"cosignedAt": cosigned_at, "sig": parts["sig"]}
    if "pq_sig" in parts:
        cosig["pq_sig"] = parts["pq_sig"]
    return {"verdict": verdict, "cosig": cosig, "suite": suite, "signer_pub": signer_pub}


# ---------------------------------------------------------------------------------------------------------------- verify


def _parse_signer_pub(v: Any) -> Optional[Dict[str, str]]:
    if not _is_record(v) or not isinstance(v.get("pq"), str) or len(v["pq"]) == 0:
        return None
    out = {"pq": v["pq"]}
    if isinstance(v.get("ed"), str) and len(v["ed"]) > 0:
        out["ed"] = v["ed"]
    return out


def _signer_matches(expected: Any, got: Dict[str, str]) -> bool:
    exp_pq = expected if isinstance(expected, str) else G(expected, "pq")
    if not isinstance(exp_pq, str) or not ct_eq(exp_pq, got["pq"]):
        return False
    if not isinstance(expected, str):
        exp_ed = G(expected, "ed")
        if isinstance(exp_ed, str):
            if not isinstance(got.get("ed"), str) or not ct_eq(exp_ed, got["ed"]):
                return False
    return True


def verify_co_signed_attestation(cosigned: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Verify a co-signed attestation: recompute the canonical bytes from the artifact's OWN verdict and co-sign time and check the
    post-quantum signature under the embedded signer key. FAIL CLOSED (a result with a reason, never a raise) on a malformed
    artifact, a classical-only / unknown suite, a tampered verdict field, a wrong key, an ``expectedSigner`` mismatch, a
    co-signature older than ``maxAgeMs``, or a suite this runtime cannot verify. Without ``expectedSigner`` it proves only that
    the signature matches the key EMBEDDED in the artifact."""
    from .pca import _SIG_SUITES, suite_available, verify_leaf_suite

    try:
        opts = {} if opts is None else opts
        if not _is_record(cosigned):
            return {"ok": False, "reason": "co-signed attestation is not an object"}
        verdict = cosigned.get("verdict")
        if not _is_record(verdict) or not isinstance(verdict.get("tier"), str) or not isinstance(verdict.get("trustworthy"), bool):
            return {"ok": False, "reason": "verdict is missing or has a non-string tier / non-boolean trustworthy"}
        cosig = cosigned.get("cosig")
        if not _is_record(cosig) or not is_finite(cosig.get("cosignedAt")) or not isinstance(cosig.get("sig"), str):
            return {"ok": False, "reason": "cosig is missing or has a non-numeric cosignedAt / non-string sig"}
        suite = cosigned.get("suite")
        if not is_pq_co_sign_suite(suite):
            return {"ok": False, "reason": "suite '%s' is not an accepted post-quantum co-sign suite" % js_string(suite if "suite" in cosigned else U)}
        signer_pub = _parse_signer_pub(cosigned.get("signer_pub"))
        if signer_pub is None:
            return {"ok": False, "reason": "signer_pub is missing or has no post-quantum public key"}

        now = G(opts, "now")
        now = now if is_finite(now) else now_ms()
        age_ms = now - cosig["cosignedAt"]
        partial: Dict[str, Any] = {"ok": False, "suite": suite, "verdict": verdict, "signer_pub": signer_pub,
                                   "cosignedAt": cosig["cosignedAt"], "ageMs": age_ms}

        if has(opts, "expectedSigner") and not _signer_matches(opts["expectedSigner"], signer_pub):
            return dict(partial, reason="co-signer public key does not match the expected signer")

        if has(opts, "maxAgeMs"):
            max_age = opts["maxAgeMs"]
            if not is_finite(max_age) or max_age <= 0:
                return dict(partial, reason="invalid maxAgeMs")
            if not (cosig["cosignedAt"] <= now):
                return dict(partial, reason="co-sign timestamp is in the future")
            if not (age_ms <= max_age):
                return dict(partial, reason="co-signature is stale (older than maxAgeMs)")

        msg = canonical_verdict_bytes(verdict, cosig["cosignedAt"])
        if not suite_available(suite):
            return dict(partial, reason="unsupported_suite: %s" % suite)
        p: Dict[str, Any] = {"alg": suite, "sig": cosig["sig"], "pq_pk": signer_pub["pq"]}
        if "pq_sig" in cosig:
            p["pq_sig"] = cosig["pq_sig"]
        needs_ed = _SIG_SUITES[suite][2]  # hybrid: the Ed25519 half verifies under signer_pub.ed
        if not verify_leaf_suite(p, signer_pub.get("ed") if needs_ed else None, msg):
            return dict(partial, reason="post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)")
        return dict(partial, ok=True)
    except Exception as e:  # noqa: BLE001 - fail closed
        return {"ok": False, "reason": "co-signature verification error (fail closed): %s" % msg_of(e)}
