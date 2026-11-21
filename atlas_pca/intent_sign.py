"""The signing and digest half of the intent modules that the verifier side (``intent_v2``, ``intent_wb``) does not carry: a generic signed artifact, a
classifier verdict and the check of its judge's hardware attestation, an accumulator receipt (and its core digest), and a sequencer key set. Each signer
takes the identity secret as 32 bytes (``KeyPair``'s seed) and an optional suite (``alg`` plus the ``PqKeyPair`` of that suite), refuses a body the shape
check refuses, and is deterministic (Ed25519 and ML-DSA sign deterministically). Ports of the reference ``intent-artifacts`` / ``intent-classifier`` /
``intent-acc`` signers."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .agent import KeyPair, PqKeyPair, sign_with_suite
from .intent_v2 import (ACC_RECEIPT_CORE_DOMAIN, ACC_RECEIPT_DOMAIN, SEQUENCER_KEYS_DOMAIN, _UNDEF, _bind_suite_fields, _receipt_body,
                        acc_receipt_shape_error, sequencer_key_set_shape_error)
from .intent_wb import INTENT_CLASSIFIER_DOMAIN, artifact_message
from .pca import _SIG_SUITES, canonical_bytes_strict, hash_canonical

__all__ = ["public_key_b64u", "sign_artifact", "sign_classifier_verdict", "verify_classifier_attestation", "sign_acc_receipt", "acc_receipt_core_digest",
           "ACC_RECEIPT_CORE_DOMAIN", "sign_sequencer_key_set"]


def public_key_b64u(secret: bytes) -> str:
    """The base64url Ed25519 public key of a 32-byte secret."""
    return KeyPair(bytes(secret), allow_insecure_signer=True).public


def _suite_fields(alg: Optional[str], ed: KeyPair, pq: Optional[PqKeyPair], msg: bytes) -> Dict[str, str]:
    """``signSuiteArtifact``: the signature parts plus, for a non-Ed25519 suite, the ``alg`` and ``pq_pk`` the artifact must carry."""
    parts = sign_with_suite(alg, ed, pq, msg)
    out: Dict[str, str] = {"sig": parts["sig"]}
    if alg and alg != "ed25519":
        out["alg"] = alg
        if pq is not None:
            out["pq_pk"] = pq.public
        if "pq_sig" in parts:
            out["pq_sig"] = parts["pq_sig"]
    return out


def sign_artifact(domain: str, body: dict, secret: bytes, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """``body`` + ``sig`` over utf8(domain) || canonical(body, any ``sig`` / ``pq_sig`` of the body dropped); a non-Ed25519 suite binds ``alg`` and
    ``pq_pk`` into the signed body. Raises for an unknown suite or a non-canonical body."""
    if alg is not None and alg not in _SIG_SUITES:
        raise ValueError("signArtifact: unknown signature alg '%s'" % alg)
    full = dict(body)
    if alg and alg != "ed25519":
        if pq is None:
            raise TypeError("'%s' needs a PQ key pair" % alg)
        full["alg"], full["pq_pk"] = alg, pq.public
    f = _suite_fields(alg, KeyPair(bytes(secret), allow_insecure_signer=True), pq, artifact_message(domain, full))
    return dict(full, **f)


def sign_classifier_verdict(body: dict, secret: bytes, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """A classifier's signed verdict (``judge`` is derived from the secret key): {v, kind, classifier, session, content_digest, label, measurement, judge,
    sig, ...}."""
    return sign_artifact(INTENT_CLASSIFIER_DOMAIN, dict({"v": 1, "kind": "pca-intent-classification"}, **body, judge=public_key_b64u(secret)), secret, alg, pq)


def verify_classifier_attestation(v: Any, attestation: Any, approved: Any = None) -> Dict[str, Any]:
    """The judge-attestation gate for a verdict: its ``measurement`` must be the attested enclave measurement and the attested identity must satisfy the
    approved binding. ``{"ok": True, "measured"}`` or ``{"ok": False, "reason"}``; never raises."""
    from .semantic_threshold import verify_judge_attestation
    if not isinstance(v, dict):
        return {"ok": False, "reason": "verdict must be an object"}
    try:
        return verify_judge_attestation(v.get("measurement"), attestation, approved)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "attestation check error (fail closed): %s" % (str(e) or "unknown")}


def sign_acc_receipt(body: dict, secret: bytes, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """A sequencer's signed accumulator receipt (``signer`` is derived from the secret). Raises when the signed receipt fails its shape check (the
    arithmetic is not checked here)."""
    ed = KeyPair(bytes(secret), allow_insecure_signer=True)
    base = _receipt_body(dict(body, signer=ed.public))
    bound = _bind_suite_fields(base, alg or _UNDEF, pq.public if pq is not None else _UNDEF)
    out = dict(base, **_suite_fields(alg, ed, pq, ACC_RECEIPT_DOMAIN.encode("utf-8") + canonical_bytes_strict(bound)))
    bad = acc_receipt_shape_error(out)
    if bad:
        raise ValueError("signAccReceipt: %s" % bad)
    return out


def acc_receipt_core_digest(r: dict) -> str:
    """The digest of a receipt's core (the members the PCActn reservation binds, without ``ledger`` and ``kid``)."""
    return hash_canonical({"d": ACC_RECEIPT_CORE_DOMAIN, "r": {k: r[k] for k in ("v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest",
                                                                                 "aud", "issued_at", "expires_at")}})


def sign_sequencer_key_set(body: dict, root_secret: bytes, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> dict:
    """A sequencer key set signed by its root (``sequencer`` is derived from the secret). Raises when the signed key set fails its shape check."""
    ed = KeyPair(bytes(root_secret), allow_insecure_signer=True)
    base = {"v": body["v"], "kind": body["kind"], "sequencer": ed.public, "version": body["version"], "issued_at": body["issued_at"], "keys": body["keys"]}
    clone = json.loads(canonical_bytes_strict(base).decode("utf-8"))
    bound = _bind_suite_fields(clone, alg or _UNDEF, pq.public if pq is not None else _UNDEF)
    out = dict(clone, **_suite_fields(alg, ed, pq, SEQUENCER_KEYS_DOMAIN.encode("utf-8") + canonical_bytes_strict(bound)))
    bad = sequencer_key_set_shape_error(out)
    if bad:
        raise ValueError("signSequencerKeySet: %s" % bad)
    return out
