"""Google Cloud Confidential Space attestation-token verifier (native counterpart of `createGcpConfidentialSpaceVerifier`).

The token's signing key must be anchored to a CONFIGURED anchor (a pinned JWKS, an SPKI SHA-256 pin or an `x5c` chain to a
root); the JWS (RS256 / ES256) is verified under it, then `iss` / time window, `submods.confidential_space`, `swname` /
`swversion`, `hwmodel`, `dbgstat`, the `eat_nonce` binding and the NON-EMPTY `image_digest` allowlist. Fails closed with the
reference's reason strings.
"""
import math
from typing import Any, Dict, List, Optional, Set

from .attest_amd import AttestConstructError
from .attest_cert import Cert
from .attest_common import (
    as_str,
    as_str_list,
    attestation_binding,
    crypto,
    decode_claim_bytes,
    ecdsa_verify_raw,
    first_string,
    is_num,
    jwk_curve,
    key_type,
    node_b64decode,
    parse_jws,
    rsa_pkcs1_verify,
    spki_sha,
    transform_binding,
)
from .attest_der import x509_valid_at

GCP_CS_SUITE = "gcp-confidential-space-jwt"
GCP_CS_DEFAULT_ISSUER = "https://confidentialcomputing.googleapis.com"

_SEVSNP_HWMODELS = ("GCP_AMD_SEV", "GCP_AMD_SEV_SNP", "GCP_AMD_SEV_ES")
_TDX_HWMODELS = ("GCP_INTEL_TDX",)
_DBGSTAT_DISABLED = "disabled-since-boot"


def tee_type_of_hwmodel(hwmodel: str) -> Optional[str]:
    if hwmodel in _SEVSNP_HWMODELS:
        return "sev-snp"
    if hwmodel in _TDX_HWMODELS:
        return "tdx"
    up = hwmodel.upper()
    if up.startswith("GCP_AMD_SEV"):
        return "sev-snp"
    if up.startswith("GCP_INTEL_TDX"):
        return "tdx"
    return None


def _kty_name(key: Any) -> str:
    t = key_type(key)
    return {"ec": "EC", "rsa": "RSA"}.get(t, t)


def _jwk_key(jwk: Dict[str, Any]) -> Any:
    """A public key from a JWK (RSA n/e, EC x/y, or the leaf of an x5c chain); raises on anything unusable."""
    if isinstance(jwk.get("n"), str) and isinstance(jwk.get("e"), str):
        c = crypto()
        n = int.from_bytes(node_b64decode(jwk["n"]), "big")
        e = int.from_bytes(node_b64decode(jwk["e"]), "big")
        return c.rsa.RSAPublicNumbers(e, n).public_key()
    if jwk.get("kty") == "EC" and isinstance(jwk.get("crv"), str) and isinstance(jwk.get("x"), str) and isinstance(jwk.get("y"), str):
        c = crypto()
        curves = {"P-256": c.ec.SECP256R1, "P-384": c.ec.SECP384R1, "P-521": c.ec.SECP521R1}
        if jwk["crv"] not in curves:
            raise ValueError("unsupported curve %s" % jwk["crv"])
        x = int.from_bytes(node_b64decode(jwk["x"]), "big")
        y = int.from_bytes(node_b64decode(jwk["y"]), "big")
        return c.ec.EllipticCurvePublicNumbers(x, y, curves[jwk["crv"]]()).public_key()
    x5c = jwk.get("x5c")
    if isinstance(x5c, list) and len(x5c) > 0 and isinstance(x5c[0], str):
        return Cert(node_b64decode(x5c[0])).public_key
    return None


def _key_from_jwk(jwk: Dict[str, Any]) -> Dict[str, Any]:
    try:
        key = _jwk_key(jwk)
    except Exception as e:
        return {"reason": "JWKS key is not a usable public key: %s" % e}
    if key is None:
        return {"reason": "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate"}
    return {"key": key}


def verify_jwk_x5c_chain(x5c: Any, anchors: Dict[str, Any], now_ms: float, skew_ms: float) -> Optional[str]:
    """A JWK's `x5c` chain to a configured root PEM / SPKI anchor; a failure reason or None."""
    if not isinstance(x5c, list) or len(x5c) == 0:
        return "empty x5c certificate chain"
    certs: List[Cert] = []
    for i, b64 in enumerate(x5c):
        if not isinstance(b64, str) or len(b64) == 0:
            return "empty x5c entry at index %d" % i
        try:
            cert = Cert(node_b64decode(b64))
        except Exception as e:
            return "malformed x5c certificate at index %d: %s" % (i, e)
        if not x509_valid_at(cert.raw, now_ms, skew_ms):
            return "x5c certificate at index %d is outside its validity window" % i
        certs.append(cert)
    for i in range(len(certs) - 1):
        if not certs[i].verify(certs[i + 1].public_key):
            return "x5c link %d is not signed by the certificate above it" % i
    pins = set(s.lower() for s in (anchors.get("trustedKeySpki") or []))
    for c in certs:
        if c.spki_hash("sha256") in pins:
            return None
    top = certs[-1]
    for pem in anchors.get("rootCertsPem") or []:
        try:
            root_key = Cert.from_pem(pem).public_key
        except Exception:
            try:
                root_key = crypto().serialization.load_pem_public_key(pem.encode("utf-8"))
            except Exception:
                continue
        if top.verify(root_key):
            return None
    return "x5c chain does not anchor in a configured GCP trust root"


def _keys_of(jwks: Any) -> List[Dict[str, Any]]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        return []
    return [k if isinstance(k, dict) else {} for k in keys]


def _resolve_trusted_signing_key(header: Dict[str, Any], evidence_jwks: Any, anchors: Dict[str, Any], now_ms: float, skew_ms: float) -> Dict[str, Any]:
    trusted_keys = _keys_of(anchors.get("trustedJwks"))
    evidence_keys = _keys_of(evidence_jwks)
    kid = header.get("kid")
    has_kid = isinstance(kid, str) and len(kid) > 0

    def pick_from(keys: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if has_kid:
            return next((k for k in keys if k.get("kid") == kid), None)
        return keys[0] if len(keys) == 1 else None

    jwk = pick_from(evidence_keys)
    from_trusted = False
    if jwk is None:
        jwk = pick_from(trusted_keys)
        from_trusted = jwk is not None
    hx = header.get("x5c")
    if jwk is None and has_kid and hx and len(hx) > 0:
        jwk = {"x5c": hx, "kid": kid}
    elif jwk is None and not has_kid and hx and len(hx) > 0:
        jwk = {"x5c": hx}
    if jwk is None:
        if has_kid:
            return {"reason": "no JWKS key matches the token kid '%s' (untrusted signer)" % kid}
        return {"reason": "no kid on the token and no unambiguous single signing key available"}

    built = _key_from_jwk(jwk)
    if "reason" in built:
        return built
    key = built["key"]
    spki = spki_sha(key, "sha256")
    if from_trusted:
        return {"key": key}

    pins = set(s.lower() for s in (anchors.get("trustedKeySpki") or []))
    if spki in pins:
        return {"key": key}
    for tk in trusted_keys:
        tb = _key_from_jwk(tk)
        if "reason" in tb:
            continue
        if spki_sha(tb["key"], "sha256") == spki:
            return {"key": key}
    x5c = jwk.get("x5c")
    if isinstance(x5c, list) and len(x5c) > 0 and (len(anchors.get("rootCertsPem") or []) > 0 or len(pins) > 0):
        chain_err = verify_jwk_x5c_chain(x5c, anchors, now_ms, skew_ms)
        if chain_err is None:
            return {"key": key}
        return {"reason": "signing key not trusted: %s" % chain_err}
    return {"reason": "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)"}


def _verify_jws_signature(parsed: Dict[str, Any], key: Any) -> Optional[str]:
    alg = parsed["header"]["alg"]
    if alg == "RS256":
        if key_type(key) != "rsa":
            return "RS256 token but signing key is %s (not RSA)" % _kty_name(key)
        ok = rsa_pkcs1_verify(key, parsed["signature"], parsed["signingInput"], "sha256")
        return None if ok else "JWS RS256 signature does not verify under the Confidential Space signing key"
    if alg == "ES256":
        if key_type(key) != "ec" or jwk_curve(key) != "P-256":
            return "ES256 token but signing key is %s/%s (not EC P-256)" % (_kty_name(key), jwk_curve(key) or "undefined")
        if len(parsed["signature"]) != 64:
            return "ES256 signature is %d bytes (expected 64: r‖s)" % len(parsed["signature"])
        ok = ecdsa_verify_raw(key, parsed["signature"], parsed["signingInput"], "sha256")
        return None if ok else "JWS ES256 signature does not verify under the Confidential Space signing key"
    return "unsupported JWS alg '%s' (Confidential Space uses RS256)" % alg


def _nonce_candidates(v: Any) -> List[str]:
    if isinstance(v, str):
        return [v] if len(v) > 0 else []
    arr = as_str_list(v)
    if arr is None:
        return []
    return [s for s in arr if len(s) > 0]


class GcpConfidentialSpaceVerifier:
    """`verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}."""

    def __init__(self, opts: Dict[str, Any]) -> None:
        ti = opts.get("trustedIssuers")
        if not isinstance(ti, list) or len(ti) == 0:
            raise AttestConstructError("createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs")
        for iss in ti:
            if not isinstance(iss, str) or len(iss) == 0:
                raise AttestConstructError("createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string")
        anchors = opts.get("trustAnchors")
        a = anchors if isinstance(anchors, dict) else {}
        tj = a.get("trustedJwks")
        count = (len(tj["keys"]) if isinstance(tj, dict) and isinstance(tj.get("keys"), list) else 0) + len(a.get("trustedKeySpki") or []) + len(a.get("rootCertsPem") or [])
        if count == 0:
            raise AttestConstructError(
                "createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted"
            )
        policy = opts.get("policy")
        if not isinstance(policy, dict) or not isinstance(policy.get("imageDigests"), list) or len(policy["imageDigests"]) == 0:
            raise AttestConstructError("createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)")
        att = policy.get("allowedTeeTypes")
        if isinstance(att, list) and len(att) == 0:
            raise AttestConstructError("createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty")
        self._anchors = a
        self._policy = policy
        self._issuers = set(ti)
        skew = opts.get("clockSkewMs")
        self._skew = max(0, skew) if is_num(skew) else 0
        self._images: Set[str] = set(x.lower() for x in policy["imageDigests"])
        self._tee_types: Optional[Set[str]] = set(att) if isinstance(att, list) else None
        sw = policy.get("expectedSwName")
        self._sw_name = sw if isinstance(sw, str) else "CONFIDENTIAL_SPACE"
        asv = policy.get("allowedSwVersions")
        self._sw_versions: Optional[Set[str]] = set(asv) if isinstance(asv, list) else None
        self._resolve = opts.get("resolve_evidence")

    def verify(self, document: Any, expected: Any, now_ms: Any) -> Dict[str, Any]:
        def fail(reason: str) -> Dict[str, Any]:
            return {"ok": False, "reason": reason}

        policy = self._policy
        try:
            if self._resolve is None:
                return fail("no GCP Confidential Space evidence resolver configured (fail closed)")
            evidence = self._resolve(document)
            if not isinstance(evidence, dict) or not isinstance(evidence.get("token"), str) or len(evidence["token"]) == 0:
                return fail("no GCP Confidential Space token for this action")
            try:
                parsed = parse_jws(evidence["token"], "parseGcpCsJwt")
            except TypeError as e:
                return fail("Confidential Space token parse failed: %s" % e)
            alg = parsed["header"]["alg"]
            if alg != "RS256" and alg != "ES256":
                return fail("unsupported JWS alg '%s' (Confidential Space uses RS256)" % alg)

            resolved = _resolve_trusted_signing_key(parsed["header"], evidence.get("jwks"), self._anchors, now_ms, self._skew)
            if "key" not in resolved:
                return fail("Confidential Space signing key invalid: %s" % resolved["reason"])
            sig_err = _verify_jws_signature(parsed, resolved["key"])
            if sig_err:
                return fail(sig_err)

            payload = parsed["payload"]
            iss = as_str(payload.get("iss"))
            if not iss or iss not in self._issuers:
                return fail("token iss '%s' is not a configured trusted Google attestation issuer" % ("undefined" if iss is None else iss))
            now_sec = math.floor(now_ms / 1000)
            skew_sec = math.ceil(self._skew / 1000)
            exp = payload.get("exp") if is_num(payload.get("exp")) else None
            iat = payload.get("iat") if is_num(payload.get("iat")) else None
            nbf = payload.get("nbf") if is_num(payload.get("nbf")) else None
            if exp is None:
                return fail("token has no exp (cannot bound validity — fail closed)")
            if now_sec - skew_sec > exp:
                return fail("Confidential Space token expired")
            if nbf is not None and now_sec + skew_sec < nbf:
                return fail("Confidential Space token not yet valid (nbf)")
            if iat is not None and now_sec + skew_sec < iat:
                return fail("Confidential Space token issued in the future (iat)")

            submods = payload.get("submods") if isinstance(payload.get("submods"), dict) else None
            cs = submods.get("confidential_space") if submods is not None and isinstance(submods.get("confidential_space"), dict) else None
            if cs is None:
                return fail("token carries no submods.confidential_space (not a Confidential Space token)")
            swname = as_str(payload.get("swname"))
            if swname != self._sw_name:
                return fail("unexpected swname '%s' (expected '%s')" % ("undefined" if swname is None else swname, self._sw_name))
            if self._sw_versions is not None:
                v = payload.get("swversion")
                versions = as_str_list(v)
                if versions is None:
                    versions = [v] if as_str(v) else []
                if not any(x in self._sw_versions for x in versions):
                    return fail("swversion not in policy allowlist")

            hwmodel = as_str(payload.get("hwmodel"))
            if not hwmodel:
                return fail("token carries no hwmodel claim")
            tee_type = tee_type_of_hwmodel(hwmodel)
            if tee_type is None:
                return fail("unrecognized hwmodel '%s' (not a known AMD SEV-SNP / Intel TDX model)" % hwmodel)
            if self._tee_types is not None and tee_type not in self._tee_types:
                return fail("attestation type '%s' (hwmodel '%s') is not in the policy allowlist" % (tee_type, hwmodel))

            dbgstat = as_str(payload.get("dbgstat"))
            if policy.get("allowDebug") is not True and dbgstat != _DBGSTAT_DISABLED:
                return fail("token dbgstat '%s' is not '%s' (debug build — no confidentiality)" % ("undefined" if dbgstat is None else dbgstat, _DBGSTAT_DISABLED))

            if expected is None:
                return fail("no expected attestation binding supplied")
            try:
                binding_bytes = transform_binding(attestation_binding(expected), policy.get("nonceHash"))
            except TypeError as e:
                return fail("binding not constructible: %s" % e)
            candidates = _nonce_candidates(payload.get("eat_nonce"))
            if len(candidates) == 0:
                return fail("token carries no eat_nonce claim to bind the PCA challenge")
            bound = False
            for cand in candidates:
                b = decode_claim_bytes(cand)
                if b is not None and b == binding_bytes:
                    bound = True
                    break
            if not bound:
                return fail("eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)")

            container = submods.get("container") if isinstance(submods.get("container"), dict) else {}
            image_digest = first_string(container, ["image_digest"])
            if not image_digest:
                return fail("token carries no submods.container.image_digest to measure the workload")
            if image_digest.lower() not in self._images:
                return fail("workload image_digest not in policy allowlist")

            measured = {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": image_digest, "operator": ""}
            host: Dict[str, str] = {"attestation_type": tee_type, "hwmodel": hwmodel, "image_digest": image_digest}
            image_ref = first_string(container, ["image_reference"])
            if image_ref:
                host["image_reference"] = image_ref
            return {"ok": True, "bound": True, "measured": measured, "hostAsserted": host}
        except Exception as e:
            return fail("gcp-confidential-space verification error (fail closed): %s" % e)
