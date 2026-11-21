"""A signed, machine-readable statement of the risk-budget bound of a grant.

From a risk policy ``{bMax, kappa, ...}`` the guardian derives the bound ``bMax / kappa`` (the total risk of autonomous actions between two
consecutive human co-signs), a fixed human statement and optional evidence rows (``checks``), and signs it (Ed25519, ML-DSA-65 or a
hybrid). ``verify_safety_certificate`` recomputes the bound from the certificate's own parameters and refuses any mismatch. This is an
arithmetic consequence of the signed parameters: it is not a claim that the agent or the system is safe.

Certificates are dicts with the reference member names. The verifier is total and fails closed with the reference's reason strings; a
post-quantum or hybrid certificate verifies only under a verifier-side pin (``pq_pins``): there is no option to trust the key the
certificate carries."""
from __future__ import annotations

from ._fin import fin
import json
import math
import re
import time
from typing import Any, Dict, List, Optional

from .agent import KeyPair, _bind_suite, sign_with_suite
from .pca import MAX_JSON_BYTES, _SIG_SUITES, _resolve_pq_key, _verify_suite, canonical_bytes, canonicalize
from .risk import safety_bound, validate_risk_policy
from .sdjwt_jws import js_num

SAFETY_CERT_DOMAIN = "atlas-pca/safety-cert/v1\0"
SAFETY_CERT_VERSION = 1
SAFETY_CERT_SCOPE = "risk-budget-bound"
MAX_SAFETY_CHECKS = 64
_MAX_CHECK_ID = 64
_MAX_EVIDENCE_URL = 2048
_SAFE = 9007199254740991
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_STATUSES = ("passed", "failed", "not_run")


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v: Any) -> bool:
    return _num(v) and (isinstance(v, int) or fin(v))


def _units(s: str) -> int:
    """Length in UTF-16 code units (how the reference counts)."""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _is(v: Any, text: str) -> bool:
    return isinstance(v, str) and v == text


def _plain_https(ref: str) -> bool:
    if _units(ref) > _MAX_EVIDENCE_URL:
        return False
    import ada_url  # the WHATWG URL parser (a core dependency)
    try:
        u = ada_url.URL(ref)
    except ValueError:
        return False
    return u.protocol == "https:" and u.username == "" and u.password == ""


def validate_safety_checks(checks: Any) -> Optional[str]:
    """The first problem with a list of check rows ``{"id", "status": "passed" | "failed" | "not_run", "evidence": {"kind": "url" |
    "sha256", "ref"}, "at"}``, or None: at most 64 rows, distinct ids of 1..64 characters, a non-negative integer time, and an evidence
    link that is a plain https URL (no credentials, at most 2048 characters) or 64 lowercase hex digits."""
    if not isinstance(checks, list):
        return "checks must be an array"
    if len(checks) > MAX_SAFETY_CHECKS:
        return "more than %d checks" % MAX_SAFETY_CHECKS
    seen = set()
    for c in checks:
        if not isinstance(c, (dict, list)):
            return "check is not an object"
        k = c if isinstance(c, dict) else {}
        cid = k.get("id")
        if not isinstance(cid, str) or not 1 <= _units(cid) <= _MAX_CHECK_ID:
            return "check id must be a 1..64 char string"
        if cid in seen:
            return "duplicate check id '%s'" % cid
        seen.add(cid)
        if not isinstance(k.get("status"), str) or k["status"] not in _STATUSES:
            return "check '%s' has an invalid status" % cid
        at = k.get("at")
        if not (_num(at) and at == at and abs(at) <= _SAFE and float(at).is_integer() and at >= 0 and str(at)[0] != "-"):
            return "check '%s' has an invalid time" % cid
        e = k.get("evidence")
        if not isinstance(e, dict) or not isinstance(e.get("ref"), str):
            return "check '%s' has no evidence link" % cid
        if _is(e.get("kind"), "sha256"):
            if _SHA256_HEX.fullmatch(e["ref"]) is None:
                return "check '%s' evidence digest is not 64 lowercase hex" % cid
        elif _is(e.get("kind"), "url"):
            if not _plain_https(e["ref"]):
                return "check '%s' evidence URL must be a plain https URL" % cid
        else:
            return "check '%s' has an invalid evidence kind" % cid
    return None


def safety_certificate_bound(p: Dict[str, Any]) -> float:
    """``bMax / kappa`` (0 when kappa is not positive): the bound a certificate states."""
    return safety_bound(p)


def _number_text(v: Any) -> str:
    if isinstance(v, float) and v != v:
        return "NaN"
    if isinstance(v, float) and v in (math.inf, -math.inf):
        return "Infinity" if v > 0 else "-Infinity"
    return js_num(v) if _num(v) else str(v)


def safety_certificate_statement(bound: Any) -> str:
    return ("Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions "
            "Σ r(Aᵢ) ≤ %s (= B_max / κ). This is not a claim that the agent or the system is safe." % _number_text(bound))


def safety_certificate_message(cert: Dict[str, Any]) -> bytes:
    """The bytes the guardian signs: the domain prefix and the canonical claim (the certificate without ``sig`` / ``pq_sig``)."""
    return SAFETY_CERT_DOMAIN.encode("utf-8") + canonical_bytes({k: v for k, v in cert.items() if k not in ("sig", "pq_sig")})


def issue_safety_certificate(policy: Any, guardian: KeyPair, *, grant_ref: Optional[str] = None, instance: Optional[str] = None,
                             checks: Optional[List[dict]] = None, issued_at: Any = None, alg: Optional[str] = None, pq: Any = None) -> Dict[str, Any]:
    """A certificate for `policy` signed by the guardian's ``KeyPair`` (and, for a post-quantum or hybrid `alg`, the PQ key pair `pq`).
    `issued_at` is epoch ms (default: now). Raises ValueError on a malformed policy, checks or alg."""
    bad = validate_risk_policy(policy)
    if bad:
        raise ValueError("issueSafetyCertificate: %s" % bad)
    if alg is not None and alg not in _SIG_SUITES:
        raise ValueError("issueSafetyCertificate: unknown signature alg '%s'" % (alg,))
    if checks is not None:
        bad = validate_safety_checks(checks)
        if bad:
            raise ValueError("issueSafetyCertificate: %s" % bad)
    bound = safety_certificate_bound(policy)
    base: Dict[str, Any] = {"v": SAFETY_CERT_VERSION, "statement": safety_certificate_statement(bound), "scope": SAFETY_CERT_SCOPE}
    if checks is not None:
        base["checks"] = [{"id": c["id"], "status": c["status"], "evidence": {"kind": c["evidence"]["kind"], "ref": c["evidence"]["ref"]}, "at": c["at"]}
                          for c in checks]
    base["params"] = {**{k: policy[k] for k in ("bMax", "kappa", "theta1", "theta2", "lambda", "rho")}, "weights": dict(policy["weights"])}
    base["bound"] = base["blastRadiusPerCheckpoint"] = bound
    if grant_ref is not None:
        base["grant_ref"] = grant_ref
    if instance is not None:
        base["instance"] = instance
    base["issued_at"] = int(time.time() * 1000) if issued_at is None else issued_at
    base["guardian"] = guardian.public
    claim = _bind_suite(base, alg, pq)
    return {**claim, **sign_with_suite(alg, guardian, pq, safety_certificate_message(claim))}


def _alg_of(cert: dict) -> Optional[str]:
    """The suite a certificate names (absent: ed25519), or None for anything that is not a registered suite name."""
    if "alg" not in cert:
        return "ed25519"
    return cert["alg"] if isinstance(cert["alg"], str) and cert["alg"] in _SIG_SUITES else None


def verify_safety_certificate(cert: Any, *, guardian: Optional[str] = None, require_checks: Optional[List[str]] = None, max_age_ms: Any = None,
                              now: Any = None, pq_pins: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """``{"ok": True, "recomputedBound"}`` or ``{"ok": False, "reason", "recomputedBound"?}``. Total. Checks, in order: shape, scope,
    check rows, the risk parameters, the stated bound and blast radius against ``bMax / kappa`` RECOMPUTED here, the pinned `guardian`
    key, the signature (a post-quantum half only under ``pq_pins[guardian]``), the age (`max_age_ms` against `now`, default the wall
    clock) and that every id in `require_checks` is present and passed."""
    try:
        if not isinstance(cert, dict) or not (_num(cert.get("v")) and cert["v"] == SAFETY_CERT_VERSION):
            return {"ok": False, "reason": "malformed certificate"}
        if not isinstance(cert.get("sig"), str) or not isinstance(cert.get("guardian"), str):
            return {"ok": False, "reason": "missing guardian/signature"}
        if not _is(cert.get("scope"), SAFETY_CERT_SCOPE):
            return {"ok": False, "reason": "unknown scope"}
        if "checks" in cert:
            bad = validate_safety_checks(cert["checks"])
            if bad:
                return {"ok": False, "reason": "invalid checks: %s" % bad}
        params = cert.get("params")
        bad = validate_risk_policy(dict(params) if isinstance(params, dict) else {})
        if bad:
            return {"ok": False, "reason": "invalid parameters: %s" % bad}
        recomputed = safety_certificate_bound(params)

        def fail(reason: str) -> Dict[str, Any]:
            return {"ok": False, "reason": reason, "recomputedBound": recomputed}

        if not _finite(cert.get("bound")) or cert["bound"] != recomputed:
            return fail("stated bound does not equal B_max/κ recomputed from the parameters")
        if not _num(cert.get("blastRadiusPerCheckpoint")) or cert["blastRadiusPerCheckpoint"] != recomputed:
            return fail("blastRadiusPerCheckpoint does not equal the recomputed bound")
        if guardian is not None and guardian != cert["guardian"]:
            return fail("guardian key is not the pinned key")
        alg = _alg_of(cert)
        if alg is None:
            return fail("unknown signature alg")
        key = None if alg == "ed25519" else _resolve_pq_key(cert["guardian"], cert.get("pq_pk"), pq_pins=pq_pins)
        share = {"sig": cert["sig"], **({"alg": alg} if alg != "ed25519" else {}), **({"pq_sig": cert["pq_sig"]} if "pq_sig" in cert else {})}
        msg = safety_certificate_message(cert)  # first: a claim that cannot be canonicalised is malformed, whatever its key
        if (alg != "ed25519" and key is None) or not _verify_suite(share, cert["guardian"], msg, key):
            return fail("guardian signature does not verify")
        if max_age_ms is not None:
            at = time.time() * 1000 if now is None else now
            if not _finite(max_age_ms) or not _finite(at) or not _finite(cert.get("issued_at")):
                return fail("invalid age policy or issue time")
            if cert["issued_at"] > at:
                return fail("certificate is issued in the future")
            if at - cert["issued_at"] > max_age_ms:
                return fail("certificate is older than maxAgeMs")
        rows = cert.get("checks") or []
        for cid in require_checks or []:
            c = next((k for k in rows if _is(k.get("id"), cid)), None) if isinstance(cid, str) else None
            if c is None:
                return fail("required check '%s' is not present" % (cid,))
            if c["status"] != "passed":
                return fail("required check '%s' is %s" % (cid, c["status"]))
        return {"ok": True, "recomputedBound": recomputed}
    except Exception as e:  # noqa: BLE001 - fail closed
        return {"ok": False, "reason": "malformed certificate: %s" % (str(e) or "unknown")}


def encode_safety_certificate(cert: Dict[str, Any]) -> str:
    """The canonical JSON text of a certificate."""
    return canonicalize(cert)


def _no_constant(name: str) -> Any:
    raise ValueError("not JSON: %s" % name)


def decode_safety_certificate(text: Any) -> Optional[Dict[str, Any]]:
    """Parse a certificate from JSON text, or None. Shape only (version, signature and guardian strings, a params object): the result
    must still go through ``verify_safety_certificate``."""
    try:
        if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > MAX_JSON_BYTES:
            return None
        v = json.loads(text, parse_constant=_no_constant)
        if not isinstance(v, dict) or isinstance(v.get("v"), bool) or v.get("v") != SAFETY_CERT_VERSION:
            return None
        if not isinstance(v.get("sig"), str) or not isinstance(v.get("guardian"), str) or not isinstance(v.get("params"), (dict, list)):
            return None
        return v
    except Exception:  # noqa: BLE001
        return None


def safety_certificate_for_compliance(cert: Any, **verify_options: Any) -> Optional[Dict[str, Any]]:
    """The evidence row of a VERIFIED certificate for a compliance report (None when it does not verify). Takes the keywords of
    ``verify_safety_certificate``."""
    if not verify_safety_certificate(cert, **verify_options)["ok"]:
        return None
    return {"control": SAFETY_CERT_SCOPE, "guardian": cert["guardian"], "issued_at": cert["issued_at"], "bound": cert["bound"],
            "checks": [{"id": c["id"], "status": c["status"],
                        "evidence": "sha256:%s" % c["evidence"]["ref"] if c["evidence"]["kind"] == "sha256" else c["evidence"]["ref"]}
                       for c in cert.get("checks") or []]}


__all__ = ["SAFETY_CERT_DOMAIN", "SAFETY_CERT_VERSION", "SAFETY_CERT_SCOPE", "MAX_SAFETY_CHECKS", "validate_safety_checks",
           "safety_certificate_bound", "safety_certificate_statement", "safety_certificate_message", "issue_safety_certificate",
           "verify_safety_certificate", "encode_safety_certificate", "decode_safety_certificate", "safety_certificate_for_compliance"]
