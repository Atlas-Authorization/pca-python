"""A post-quantum software / HSM attestation root: a statement signed under a PQ or hybrid suite (domain ``atlas-pca/attest-pq/v1\\0``) and its
verifier (trusted PQ keys, optional Ed25519 keys, requirePq / requireHybrid, allowed suites, measurement policy). A port of the reference
``attest-pq-software`` module. Honest scope: the measurement is software- or HSM-attested, NOT silicon-measured (``weights_measured`` is always
False), so the root can satisfy a post-quantum requirement but never ``require_hardware``. Synchronous; the verifier is a hardware-verifier object
(``verify(input) -> dict``) usable as a root of :func:`atlas_pca.attestation_soft.create_multi_root_verifier`."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from .agent import KeyPair, sign_with_suite
from .attestation_soft import _member, _need, _truthy, attestation_binding_b64u
from .attest_common import attestation_binding
from .intent_v2 import _UNDEF
from .intent_wb import _js_str
from .pca import _SIG_SUITES, b64u, canonical_bytes_strict, verify_leaf_suite

__all__ = ["PQ_ATTEST_DOMAIN", "create_pq_software_attestor", "create_pq_software_verifier"]

PQ_ATTEST_DOMAIN = "atlas-pca/attest-pq/v1\0"
_PQ_KEY_MEMBER = {"ML-DSA-65": "mlDsa", "ML-DSA-87": "mlDsa87", "SLH-DSA-SHA2-128f": "slhDsa", "SLH-DSA-SHA2-256s": "slhDsa256s"}


def _statement_message(body: dict) -> bytes:
    return PQ_ATTEST_DOMAIN.encode("utf-8") + canonical_bytes_strict(body)


def _suite(alg: Any) -> Optional[tuple]:
    return _SIG_SUITES.get(alg) if isinstance(alg, str) else None


def _has_pq(suite: tuple) -> bool:
    """The suites the reference counts as post-quantum here (ML-DSA and SLH-DSA families; the FN-DSA and LESS suites are not)."""
    return suite[3] in _PQ_KEY_MEMBER


def create_pq_software_attestor(keys: dict) -> Any:
    """An attestor over PQ key material: ``keys`` = ``{"alg", "mlDsa"?, "slhDsa"?, "mlDsa87"?, "slhDsa256s"? (PqKeyPair), "edSecret"? (32 bytes)}``.
    Raises for an unknown or classical alg, missing PQ key material of the suite's family, or a hybrid suite without ``edSecret``. Returns an object
    with ``pq_public_key``, ``ed25519_public_key`` (None without an Ed25519 key) and ``attest(claims)``."""
    alg = keys.get("alg")
    alg = "ed25519" if alg is None else alg  # an absent alg is the default suite
    suite = _suite(alg)
    if suite is None:
        raise ValueError("createPqSoftwareAttestor: unknown signature alg '%s'" % _js_str(alg))
    _, needs_pk, hybrid, key_type, _nested = suite
    if not _has_pq(suite):
        raise ValueError("createPqSoftwareAttestor: '%s' is classical; the PQ root requires a post-quantum suite" % alg)
    pq = keys.get(_PQ_KEY_MEMBER.get(key_type, ""))
    if pq is None:
        raise TypeError("createPqSoftwareAttestor: '%s' requires the matching PQ key material" % alg)
    ed_secret = keys.get("edSecret")
    if hybrid and not isinstance(ed_secret, (bytes, bytearray)):
        raise TypeError("createPqSoftwareAttestor: hybrid suite '%s' requires edSecret" % alg)
    ed = KeyPair(bytes(ed_secret), allow_insecure_signer=True) if isinstance(ed_secret, (bytes, bytearray)) else None

    class _Attestor:
        pq_public_key = pq.public
        ed25519_public_key = ed.public if ed is not None else None

        @staticmethod
        def attest(claims: dict) -> Dict[str, Any]:
            binding = attestation_binding_b64u({"holderPub": claims.get("holder_pub"), "grantRef": claims.get("grant_ref"), "epoch": claims.get("epoch"),
                                                "nonce": claims.get("nonce")})
            body: Dict[str, Any] = {"measurement": _need(claims, "measurement"), "binding": binding, "alg": alg, "pq_pk": pq.public}
            if ed is not None:
                body["attestor_ed25519"] = ed.public
            for k in ("weights_digest", "system_prompt_digest", "tool_manifest_digest", "model_id", "operator"):
                if k in claims:
                    body[k] = claims[k]
            return dict(body, **sign_with_suite(alg, ed, pq, _statement_message(body)))

    return _Attestor()


def _default_identity(st: dict) -> Dict[str, Any]:
    out = {"model_id": st["model_id"] if isinstance(st.get("model_id"), str) else "",
           "weights_digest": st["weights_digest"] if isinstance(st.get("weights_digest"), str) else "", "weights_measured": False,
           "runtime_measurement": st.get("measurement"), "operator": st["operator"] if isinstance(st.get("operator"), str) else ""}
    for k in ("system_prompt_digest", "tool_manifest_digest"):
        if isinstance(st.get(k), str):
            out[k] = st[k]
    return out


def create_pq_software_verifier(opts: dict) -> Any:
    """A hardware-verifier root over PQ-signed statements. Options: ``trustedPqPublicKeys`` (at least one), ``trustedEd25519PublicKeys``, ``requirePq``
    (default True), ``requireHybrid``, ``allowedSuites``, ``policy`` ({"measurements" (non-empty), "weightsMeasurements"?, "deriveIdentity"?}) and
    ``resolveEvidence(document, ctx) -> statement | None``. Construction refusals raise TypeError."""
    policy = opts.get("policy") if isinstance(opts, dict) else None
    if not isinstance(policy, dict) or not isinstance(policy.get("measurements"), list) or len(policy["measurements"]) == 0:
        raise TypeError("createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
    measurements = list(policy["measurements"])
    wm = policy.get("weightsMeasurements")
    weights_measurements = list(wm) if isinstance(wm, list) else None
    trusted_pq = set(opts["trustedPqPublicKeys"]) if isinstance(opts.get("trustedPqPublicKeys"), list) else set()
    if not trusted_pq:
        raise TypeError("createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)")
    trusted_ed = set(opts["trustedEd25519PublicKeys"]) if isinstance(opts.get("trustedEd25519PublicKeys"), list) else set()
    require_pq = opts.get("requirePq") is not False
    require_hybrid = opts.get("requireHybrid") is True
    allowed = None if "allowedSuites" not in opts else set(opts["allowedSuites"]) if isinstance(opts["allowedSuites"], list) else set()
    derive: Callable[[dict], dict] = policy.get("deriveIdentity") or _default_identity
    resolve = opts.get("resolveEvidence")

    class _Verifier:
        @staticmethod
        def verify(inp: dict) -> Dict[str, Any]:
            def fail(reason: str) -> Dict[str, Any]:
                return {"ok": False, "reason": reason}
            try:
                if not resolve:
                    return fail("no PQ-software evidence resolver configured (fail closed)")
                st = resolve(inp.get("document"), inp.get("ctx"))
                if not isinstance(st, dict) or not isinstance(st.get("alg"), str):
                    return fail("no PQ-software attestation statement for this action")
                alg = st["alg"]
                suite = _suite(alg)
                if suite is None:
                    return fail("PQ statement declares an unknown signature alg '%s'" % _js_str(st["alg"]))
                _, needs_pk, hybrid, _kt, _n = suite
                if require_pq and not _has_pq(suite):
                    return fail("PQ required: a classical-only suite '%s' is not accepted by the post-quantum root" % alg)
                if require_hybrid and not (hybrid and _has_pq(suite)):
                    return fail("hybrid required: suite '%s' is not a classical+PQ hybrid" % alg)
                if allowed is not None and alg not in allowed:
                    return fail("suite '%s' is not in the allowed-suites list" % alg)
                if needs_pk and (not isinstance(st.get("pq_pk"), str) or st["pq_pk"] not in trusted_pq):
                    return fail("PQ attestor key is not trusted")
                if (alg == "ed25519" or hybrid) and (not isinstance(st.get("attestor_ed25519"), str) or st["attestor_ed25519"] not in trusted_ed):  # suite.hasEd25519
                    return fail("hybrid Ed25519 attestor key is not trusted")
                body = {k: v for k, v in st.items() if k not in ("sig", "pq_sig")}
                message = _statement_message(body)
                p: Dict[str, Any] = {"alg": alg, "sig": st.get("sig")}
                if needs_pk:
                    p["pq_pk"] = st["pq_pk"]
                if "pq_sig" in st:
                    p["pq_sig"] = st["pq_sig"]
                if not isinstance(st.get("sig"), str) or not verify_leaf_suite(p, st.get("attestor_ed25519"), message):
                    return fail("PQ attestation signature does not verify")
                expected = inp.get("expected")
                if not _truthy(expected):
                    return fail("no expected attestation binding supplied")
                try:
                    expected_b64u = b64u(attestation_binding(expected))
                except Exception as e:  # noqa: BLE001
                    return fail("binding not constructible: %s" % (str(e) or "invalid"))
                if not isinstance(st.get("binding"), str) or len(st["binding"]) == 0:
                    return fail("PQ statement is not bound (binding absent)")
                if st["binding"] != expected_b64u:
                    return fail("PQ statement binding mismatch (holder/grant/epoch/nonce)")
                if not _member(measurements, st.get("measurement", _UNDEF)):
                    return fail("measurement not in policy allowlist")
                if weights_measurements:
                    if not isinstance(st.get("weights_digest"), str) or not _member(weights_measurements, st["weights_digest"]):
                        return fail("measured weights digest not in policy allowlist")
                return {"ok": True, "bound": True, "measured": derive(st), "hostAsserted": {"suite": alg}}
            except Exception as e:  # noqa: BLE001
                return fail("pq-software verification error (fail closed): %s" % (str(e) or "unknown"))

    return _Verifier()
