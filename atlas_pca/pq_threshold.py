"""Post-quantum threshold step-up verification (the TypeScript reference, @atlasauth/pca-pq-threshold): a signed FROST group
descriptor that pins the threshold to the group key, an ML-DSA-65 pqT-of-m co-signer quorum, and the hybrid verdict that needs BOTH.

The FROST aggregate is checked as the plain Ed25519 signature it is, and the quorum runs on the existing ML-DSA-65 backend of
atlas_pca.pq_backends (OpenSSL 3.5+ or the `pq` extra). Signing (hybrid_threshold_sign) runs the in-process FROST quorum of
atlas_pca.frost (libsodium via pysodium, the `ristretto` extra) and signs the ML-DSA co-signatures with any object that has `public` and `sign(msg)`
(atlas_pca.pq_backends.OpensslKey). fold_hybrid_step_up / create_hybrid_threshold_verifier / verify_hybrid_step_up fold the aggregate
into a PCActn and enforce it through the core verifier's threshold hook. Issuing a descriptor signs with an Ed25519 authority key, so
it needs `cryptography` or the explicit allow_insecure_signer opt-in of atlas_pca.ed25519.
"""
from __future__ import annotations
from ._fin import fin

import copy
import hashlib
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from . import ed25519 as _ed
from .pca import _pq_verify_b64u, _verify_b64u, b64u, canonical_bytes_strict, decode_b64u_strict, threshold_message

GROUP_DESCRIPTOR_VERSION = 1
GROUP_SUITE = "frost-ed25519"
MAX_GROUP_SIZE = 1024
HYBRID_ARTIFACT_VERSION = 2
HYBRID_CLASSICAL_ALG = "frost-ed25519"
PQ_QUORUM_VERSION = 2
PQ_QUORUM_ALG = "ml-dsa-65"
HYBRID_PQ_ALG = PQ_QUORUM_ALG
MAX_PQ_QUORUM_ENTRIES = 256
ML_DSA_65_PUBLIC_KEY_BYTES = 1952

_DESCRIPTOR_DOMAIN = b"atlas-pca-pq-threshold/group-descriptor/v1\x00"
_SIGNER_SET_DOMAIN = b"atlas-pca-pq-threshold/signer-set/v1\x00"
_PQ_QUORUM_DOMAIN = b"atlas-pca/pq-quorum/v2\x00"
_ABSENT = object()  # a JS `undefined`: an absent field, distinct from null


def _get(o: Any, key: str) -> Any:
    """Field read with JS semantics: arrays and scalars have no such field."""
    return o.get(key, _ABSENT) if isinstance(o, dict) else _ABSENT


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_integer(v: Any) -> bool:
    return _num(v) and fin(v) and v == int(v)


def _is_safe_integer(v: Any) -> bool:
    return _is_integer(v) and abs(v) <= 2 ** 53 - 1


def _is_num(v: Any, n: int) -> bool:
    return _num(v) and v == n


def _as_b64u(k: Any) -> Any:
    return b64u(bytes(k)) if isinstance(k, (bytes, bytearray)) else k


def _js_str(v: Any) -> str:
    if v is _ABSENT:
        return "undefined"
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v == int(v) and abs(v) < 1e21:
        return str(int(v))
    return str(v)


def _utf8(s: str) -> bytes:
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


# ---- signed group descriptor

def signer_set_commitment(participants: Any) -> str:
    """base64url(sha256(domain || canonical([{id, pk}] sorted by id))) over the FROST verification shares."""
    if not isinstance(participants, list) or len(participants) == 0 or len(participants) > MAX_GROUP_SIZE:
        raise ValueError("signerSetCommitment: need 1..%d participants" % MAX_GROUP_SIZE)
    rows = []
    for p in participants:
        if not isinstance(p, dict):
            raise TypeError("signerSetCommitment: participant must be an object")
        pk = _as_b64u(p.get("publicKey"))
        ident = p.get("identifier")
        if not _is_safe_integer(ident) or ident <= 0:
            raise ValueError("signerSetCommitment: participant identifiers must be positive safe integers")
        if decode_b64u_strict(pk, 32) is None:
            raise ValueError("signerSetCommitment: verification share is not a canonical b64u(32) value")
        rows.append({"id": ident, "pk": pk})
    rows.sort(key=lambda r: r["id"])
    for i in range(1, len(rows)):
        if rows[i]["id"] == rows[i - 1]["id"]:
            raise ValueError("signerSetCommitment: duplicate participant identifier")
    return b64u(hashlib.sha256(_SIGNER_SET_DOMAIN + canonical_bytes_strict(rows)).digest())


def _descriptor_bytes(d: Dict[str, Any]) -> bytes:
    body = canonical_bytes_strict({
        "v": d.get("v"), "suite": d.get("suite"), "group_pk": d.get("groupPublicKey"), "t": d.get("t"), "n": d.get("n"),
        "signer_set": d.get("signerSetCommitment"),
    })
    return _DESCRIPTOR_DOMAIN + body


def _ed_public_key(seed: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except ImportError:
        _ed.sign_secret(seed, b"")  # raises unless the caller opted in to the built-in (variable time) signer
        return _ed.public_key(seed)


def issue_group_descriptor(authority_secret_key: Any, group_public_key: Any, t: Any, participants: Any) -> Dict[str, Any]:
    n = len(participants)
    if not _is_integer(t) or t < 1 or t > n:
        raise ValueError("issueGroupDescriptor: need 1 <= t <= n (t=%s, n=%d)" % (_js_str(t), n))
    gpk = _as_b64u(group_public_key)
    if decode_b64u_strict(gpk, 32) is None:
        raise ValueError("issueGroupDescriptor: group public key is not canonical b64u(32)")
    if not isinstance(authority_secret_key, (bytes, bytearray)) or len(authority_secret_key) != 32:
        raise ValueError("issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key")
    seed = bytes(authority_secret_key)
    descriptor = {
        "v": GROUP_DESCRIPTOR_VERSION, "suite": GROUP_SUITE, "groupPublicKey": gpk, "t": int(t), "n": n,
        "signerSetCommitment": signer_set_commitment(participants),
    }
    return {
        "descriptor": descriptor,
        "authority": b64u(_ed_public_key(seed)),
        "sig": b64u(_ed.sign_secret(seed, _descriptor_bytes(descriptor))),
    }


def verify_group_descriptor(s: Any, exp: Any) -> Dict[str, Any]:
    """{"ok": True, "descriptor"} or {"ok": False, "reason"}. Pins t to the group key: a FROST aggregate is a plain Ed25519
    signature, so the threshold cannot be read off the key and must be attested by a trusted setup authority."""

    def fail(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}

    try:
        if s is None or not isinstance(s, (dict, list)):
            return fail("no signed group descriptor: the threshold is unattested")
        d, authority, sig = _get(s, "descriptor"), _get(s, "authority"), _get(s, "sig")
        if not isinstance(d, (dict, list)) or not isinstance(authority, str) or not isinstance(sig, str):
            return fail("malformed group descriptor")
        if not _is_num(_get(d, "v"), GROUP_DESCRIPTOR_VERSION) or _get(d, "suite") != GROUP_SUITE:
            return fail("unsupported group descriptor version or suite")
        dg, dssc = _get(d, "groupPublicKey"), _get(d, "signerSetCommitment")
        if not isinstance(dg, str) or not isinstance(dssc, str):
            return fail("malformed group descriptor")
        dt, dn = _get(d, "t"), _get(d, "n")
        if not _is_integer(dt) or not _is_integer(dn) or dt < 1 or dn < dt or dn > MAX_GROUP_SIZE:
            return fail("malformed group descriptor: need 1 <= t <= n")
        authorities = _get(exp, "trustedAuthorities")
        if not isinstance(authorities, (list, tuple)):
            raise TypeError("trustedAuthorities must be an array")
        trusted = set()
        for a in authorities:
            try:
                trusted.add(_as_b64u(a))
            except TypeError:
                pass  # an unhashable entry can never equal a string authority
        if authority not in trusted:
            return fail("group descriptor authority is not trusted")
        authority_key = decode_b64u_strict(authority, 32)
        raw_sig = decode_b64u_strict(sig, 64)
        if authority_key is None or raw_sig is None:
            return fail("malformed authority key or signature")
        if not _ed.verify(authority_key, _descriptor_bytes(d), raw_sig):
            return fail("group descriptor signature does not verify")
        if dg != _as_b64u(_get(exp, "groupKey")):
            return fail("group descriptor is for a different group key")
        et = _get(exp, "t")
        if not _is_integer(et) or et < 1:
            return fail("required t must be a positive integer")
        if dt != et:
            return fail("group was set up as %s-of-%s but %s is required: the threshold is not bound to this key" % (_js_str(dt), _js_str(dn), _js_str(et)))
        pin = _get(exp, "signerSetCommitment")
        if pin is not _ABSENT and dssc != pin:
            return fail("group descriptor is for a different signer set")
        return {"ok": True, "descriptor": d}
    except Exception:  # noqa: BLE001 - total: malformed input is a refusal
        return fail("group descriptor could not be verified (malformed)")


# ---- ML-DSA-65 co-signer quorum (a pqT-of-m multi-signature of single-party keys, not a threshold scheme)

def pq_quorum_representative(message: bytes) -> bytes:
    """The bytes every co-signature covers: domain || sha256(message)."""
    return _PQ_QUORUM_DOMAIN + hashlib.sha256(bytes(message)).digest()


def normalize_pq_quorum_pool(pks: Any) -> Set[str]:
    """The trusted pool as canonical base64url strings; entries that are not a well-formed ML-DSA-65 public key are ignored."""
    if not isinstance(pks, (list, tuple, set, frozenset)):
        raise TypeError("normalizePqQuorumPool: expected an array of public keys")
    pool: Set[str] = set()
    for p in pks:
        s = _as_b64u(p)
        if isinstance(s, str) and decode_b64u_strict(s, ML_DSA_65_PUBLIC_KEY_BYTES) is not None:
            pool.add(s)
    return pool


def verify_pq_quorum(block: Any, message: bytes, trusted_pool: Any, pq_t: Any) -> Dict[str, Any]:
    """Count DISTINCT trusted keys whose co-signature verifies over `message`; ok iff the count reaches pq_t. Total (never raises
    on a malformed block); a missing, v1 or unknown version is refused before any verification."""

    def no(reason: str) -> Dict[str, Any]:
        return {"ok": False, "count": 0, "need": pq_t, "reason": reason}

    if not _is_integer(pq_t) or pq_t < 1:
        return no("pqT must be a positive integer")
    if not isinstance(block, (dict, list)):
        return no("malformed pq block")
    v, alg, signers = _get(block, "v"), _get(block, "alg"), _get(block, "signers")
    if v is _ABSENT:
        return no("pq quorum version missing (pre-0.5 format is refused)")
    if _is_num(v, 1):
        return no("pq quorum version 1 is no longer accepted (pre-0.5 format)")
    if not _is_num(v, PQ_QUORUM_VERSION):
        return no("unsupported pq quorum version")
    if alg != PQ_QUORUM_ALG or not isinstance(signers, list):
        return no("malformed pq block")
    rep = pq_quorum_representative(message)
    counted: Set[str] = set()
    for entry in signers[:MAX_PQ_QUORUM_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        pk, sig = entry.get("pk"), entry.get("sig")
        if not isinstance(pk, str) or not isinstance(sig, str):
            continue
        if pk not in trusted_pool or pk in counted:
            continue
        if not _pq_verify_b64u("ML-DSA-65", pk, rep, sig):
            continue
        counted.add(pk)
    count = len(counted)
    if count >= pq_t:
        return {"ok": True, "count": count, "need": pq_t}
    return {"ok": False, "count": count, "need": pq_t,
            "reason": "post-quantum quorum short: %d of %s required ML-DSA co-signatures" % (count, _js_str(pq_t))}


# ---- hybrid verification: the FROST aggregate AND the ML-DSA quorum, both over the same action message

def _normalize_group_key(k: Any) -> Optional[str]:
    s = _as_b64u(k)
    return s if decode_b64u_strict(s, 32) is not None else None


def _verify_frost_aggregate(sig: Any, message: bytes, trusted_group_key: str) -> bool:
    # a FROST aggregate is an ordinary Ed25519 signature under the group key
    return isinstance(sig, str) and bool(_verify_b64u(trusted_group_key, message, sig))


def _check_descriptor(opts: Any) -> Optional[str]:
    exp = {"trustedAuthorities": _get(opts, "trustedAuthorities"), "groupKey": _get(opts, "groupKey"), "t": _get(opts, "t")}
    pin = _get(opts, "signerSetCommitment")
    if pin is not _ABSENT:
        exp["signerSetCommitment"] = pin
    r = verify_group_descriptor(_get(opts, "groupDescriptor"), exp)
    return None if r["ok"] else r["reason"]


def _strip(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in d.items() if v is not _ABSENT}
    if isinstance(out.get("pq"), dict):
        out["pq"] = _strip(out["pq"])
    return out


def verify_hybrid_threshold(action: Any, artifact: Any, opts: Any) -> Dict[str, Any]:
    """{"ok", "frost", "pq", "reason"?}: fail closed unless the FROST aggregate verifies under the trusted group key (whose
    threshold the signed descriptor pins) AND at least pqT distinct trusted ML-DSA-65 keys co-signed."""
    try:
        return _verify_hybrid_inner(action, artifact, opts)
    except Exception:  # noqa: BLE001
        reason = "malformed action or verifier options"
        return {"ok": False, "frost": False, "pq": {"ok": False, "count": 0, "need": 0, "reason": reason}, "reason": reason}


def _verify_hybrid_inner(action: Any, artifact: Any, opts: Any) -> Dict[str, Any]:
    version = _get(artifact, "v")
    pq_t = _get(opts, "pqT")
    if not _is_num(version, HYBRID_ARTIFACT_VERSION):
        if version is _ABSENT:
            reason = "artifact version missing (pre-0.5 format is refused)"
        elif _is_num(version, 1):
            reason = "artifact version 1 is no longer accepted (pre-0.5 format)"
        else:
            reason = "unsupported artifact version"
        return _strip({"ok": False, "frost": False, "pq": {"ok": False, "count": 0, "need": pq_t, "reason": reason}, "reason": reason})
    message = threshold_message(action)
    trusted_group_key = _normalize_group_key(_get(opts, "groupKey"))
    pool = normalize_pq_quorum_pool(_get(opts, "pqPublicKeys") if _get(opts, "pqPublicKeys") is not _ABSENT else None)

    frost_ok = False
    frost_reason: Optional[str] = None
    descriptor_reason = _check_descriptor(opts)
    t = _get(opts, "t")
    frost = _get(artifact, "frost")
    ft = _get(frost, "t")
    if not _is_integer(t) or t < 1:
        frost_reason = "t must be a positive integer"
    elif trusted_group_key is None:
        frost_reason = "trusted FROST group key is not a canonical b64u(32) point"
    elif not isinstance(frost, (dict, list)) or _get(frost, "alg") != HYBRID_CLASSICAL_ALG:
        frost_reason = "malformed or missing FROST part"
    elif descriptor_reason is not None:
        frost_reason = descriptor_reason
    elif not _is_integer(ft) or ft < t:
        frost_reason = "FROST declared threshold %s is below the required t=%s (downgrade)" % (_js_str(ft), _js_str(t))
    elif not _verify_frost_aggregate(_get(frost, "sig"), message, trusted_group_key):
        frost_reason = "FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)"
    else:
        frost_ok = True

    pq_block = _get(artifact, "pq")
    pq = verify_pq_quorum(None if pq_block is _ABSENT else pq_block, message, pool, pq_t)
    ok = frost_ok and pq["ok"]
    if ok:
        return _strip({"ok": ok, "frost": frost_ok, "pq": pq})
    return _strip({"ok": ok, "frost": frost_ok, "pq": pq, "reason": pq.get("reason") if frost_ok else frost_reason})


# ---- signing, folding into a PCActn, and the core threshold hook

def sign_pq_quorum(message: bytes, key_pairs: Iterable[Any], pq_t: Optional[int] = None) -> Dict[str, Any]:
    """One ML-DSA-65 co-signature per key pair (an object with `public` bytes and `sign(msg)`) over the quorum representative."""
    rep = pq_quorum_representative(message)
    signers = [{"pk": b64u(k.public), "sig": b64u(k.sign(rep))} for k in key_pairs]
    return {"v": PQ_QUORUM_VERSION, "alg": PQ_QUORUM_ALG, "pqT": pq_t if pq_t is not None else len(signers), "signers": signers}


def hybrid_threshold_sign(action: Dict[str, Any], frost: Dict[str, Any], pq_signers: List[Any], pq_t: Optional[int] = None) -> Dict[str, Any]:
    """The hybrid artifact for `action`: a FROST t-of-n aggregate (frost: {groupPublicKey, quorum: [participant shares], t}) plus one
    ML-DSA-65 co-signature per pq signer, both over the same message. Fails closed on a short quorum or an invalid share."""
    from . import frost as _fr
    t = frost["t"]
    if not _is_integer(t) or t < 1:
        raise ValueError("hybridThresholdSign: frost.t must be a positive integer (got %s)" % _js_str(t))
    if len(frost["quorum"]) < t:
        raise ValueError("hybridThresholdSign: FROST quorum of %d is below the threshold t=%d" % (len(frost["quorum"]), t))
    if len(pq_signers) == 0:
        raise ValueError("hybridThresholdSign: at least one ML-DSA co-signer is required")
    message = threshold_message(action)
    gk = frost["groupPublicKey"]
    if isinstance(gk, str):
        gk = decode_b64u_strict(gk, 32)
        if gk is None:
            raise ValueError("hybridThresholdSign: FROST group public key is not canonical b64u(32)")
    elif not isinstance(gk, (bytes, bytearray)) or len(gk) != 32:
        raise ValueError("hybridThresholdSign: FROST group public key must be 32 bytes")
    gk = bytes(gk)
    agg = _fr.cosign(gk, list(frost["quorum"]), message, threshold=t)
    return {"v": HYBRID_ARTIFACT_VERSION, "digest": b64u(hashlib.sha256(message).digest()),
            "frost": {"alg": HYBRID_CLASSICAL_ALG, "group_pk": b64u(gk), "sig": b64u(agg), "t": t, "quorum": len(frost["quorum"])},
            "pq": sign_pq_quorum(message, pq_signers, pq_t)}


def fold_hybrid_step_up(action: Dict[str, Any], artifact: Dict[str, Any]) -> Dict[str, Any]:
    """{pcactn, pq}: the FROST aggregate becomes a `guardian` share of the PCActn's threshold container (the signed body is unchanged:
    thresholdMessage excludes `threshold`); the PQ block travels beside it."""
    frost = artifact["frost"] if isinstance(artifact, dict) and isinstance(artifact.get("frost"), dict) else None
    if frost is None or not isinstance(action, dict):
        raise TypeError("foldHybridStepUp: malformed action or artifact")
    share = {"role": "guardian", **{k: frost[m] for k, m in (("publicKey", "group_pk"), ("sig", "sig")) if m in frost}}
    th = action.get("threshold")
    existing = th["shares"] if isinstance(th, dict) and isinstance(th.get("shares"), list) else []
    out = {"pcactn": {**action, "threshold": {"shares": [*existing, share]}}}
    if "pq" in artifact:
        out["pq"] = artifact["pq"]
    return out


def create_hybrid_threshold_verifier(opts: Dict[str, Any]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """The core `threshold` hook enforcing the hybrid step-up: the FROST aggregate folded into `pcactn.threshold` (an Ed25519
    signature under the TRUSTED group key) AND the pqT-of-m quorum over this action. Pass the result as
    verify_pcactn_core(..., threshold_hook=...). The configuration is snapshotted at creation."""
    opts = copy.deepcopy(opts)
    trusted = _normalize_group_key(_get(opts, "groupKey"))
    pool = normalize_pq_quorum_pool(_get(opts, "pqPublicKeys"))

    def hook(ctx: Dict[str, Any]) -> Dict[str, Any]:
        def no(reason: str) -> Dict[str, Any]:
            return {"enforced": True, "ok": False, "reason": reason}
        d = _check_descriptor(opts)
        if d is not None:
            return no(d)
        message = threshold_message(ctx["pcactn"])
        if trusted is None:
            return no("trusted FROST group key is not a canonical b64u(32) point")
        th = ctx["pcactn"].get("threshold")
        shares = th["shares"] if isinstance(th, dict) and isinstance(th.get("shares"), list) else []
        share = next((x for x in shares if isinstance(x, dict) and isinstance(x.get("sig"), str) and x.get("publicKey") == trusted), None)
        if share is None:
            return no("no FROST aggregate for the trusted group key in the step-up")
        if not _verify_frost_aggregate(share["sig"], message, trusted):
            return no("FROST aggregate does not verify under the trusted group key (quorum short or forged)")
        blk = _get(opts, "pqBlock")
        pqv = verify_pq_quorum(None if blk is _ABSENT else blk, message, pool, _get(opts, "pqT"))
        if not pqv["ok"]:
            return no(pqv.get("reason") or "post-quantum quorum short")
        return {"enforced": True, "ok": True}
    return hook


def verify_hybrid_step_up(step_up: Dict[str, Any], opts: Dict[str, Any]) -> Dict[str, Any]:
    """{allow, core, pq, reason?}: the full core verification of the folded PCActn with the hybrid threshold hook. `opts` carries
    grant, groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?, audience?, nowEpoch?."""
    from .pca import verify_pcactn_core
    pcactn = step_up["pcactn"]
    pool = normalize_pq_quorum_pool(_get(opts, "pqPublicKeys"))
    pq = verify_pq_quorum(step_up.get("pq"), threshold_message(pcactn), pool, _get(opts, "pqT"))
    hook_opts = {k: opts[k] for k in ("groupKey", "pqPublicKeys", "t", "pqT", "groupDescriptor", "trustedAuthorities", "signerSetCommitment") if k in opts}
    hook_opts["pqBlock"] = step_up.get("pq")
    core = verify_pcactn_core(pcactn, opts["grant"], now=opts.get("nowEpoch"), audience=opts.get("audience"), accept_any_audience="audience" in opts and opts["audience"] is None,
                              insecure_skip_plan_root_check=True, threshold_hook=create_hybrid_threshold_verifier(hook_opts))
    out: Dict[str, Any] = {"allow": core.allow, "core": core, "pq": pq}
    if not core.allow:
        out["reason"] = core.reason
    return out
