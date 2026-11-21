"""External-fact attestation for proof-carrying actions: a notary witnesses one HTTP request/response and signs a canonical
record of it; the response body is committed as a salted Merkle tree so one field can be disclosed while the rest stay hidden,
and the disclosure is bound to a PCActn. Port of the TypeScript reference (@atlasauth/pca-notary).

Trust boundary: this relies on a trusted or semi-trusted notary (it is NOT trustless zkTLS). Everything fails closed."""
from __future__ import annotations

from ._fin import fin
import functools
import math
import os
import time
from typing import Any, Callable, Dict, List, Optional

from . import ed25519
from .grants import merkle_proof
from .intent_v2 import compare_utf8
from .pca import (_neg_zero, b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical, merkle_root, sha256,
                  verify_inclusion, _verify_b64u, MAX_SAFE)

BODY_COMMIT_ALG = "salted-merkle-sha256-v1"
NOTARY_DOMAIN = b"atlas-pca/notary/v1\x00"
ATTESTED_FACT_CAVEAT = "attested_fact"
_UNSET = object()
_UTF8_ORDER = functools.cmp_to_key(compare_utf8)


# ---- helpers ------------------------------------------------------------------------------------------------------

def _safe_integer(v: Any) -> bool:
    """`Number.isSafeInteger`: integral and within 2^53-1 (negative zero counts)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, float):
        return fin(v) and v == math.trunc(v) and abs(v) <= MAX_SAFE
    return isinstance(v, int) and abs(v) <= MAX_SAFE


def _finite(v: Any) -> bool:
    return not isinstance(v, bool) and isinstance(v, (int, float)) and fin(v)


def _truthy(v: Any) -> bool:
    """JavaScript truthiness (an empty list/dict is truthy)."""
    if v is None or v is False or v == "":
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return not (v == 0 or v != v)
    return True


def _to_number(v: Any) -> float:
    """JavaScript ToNumber for the comparison operands a keyring window may carry."""
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        t = v.strip()
        if t == "":
            return 0.0
        try:
            return float(t) if "_" not in t and t.lower().lstrip("+-") not in ("inf", "nan", "infinity") else (math.inf if t == "Infinity" else -math.inf if t == "-Infinity" else math.nan)
        except ValueError:
            return math.nan
    return math.nan


def _canonical_equal(a: Any, b: Any) -> bool:
    try:
        return hash_canonical(a) == hash_canonical(b)
    except Exception:
        return False


def _normalize_path(path: Any) -> list:
    if isinstance(path, str):
        return [path]
    if isinstance(path, (list, tuple)):
        return list(path)
    raise TypeError("path must be a string or an array")


def _is_plain_object(v: Any) -> bool:
    return isinstance(v, dict)


def _flatten_value(value: Any, prefix: list) -> List[dict]:
    if isinstance(value, (list, tuple)):
        if len(value) == 0:
            return [{"path": prefix, "value": []}]
        out: List[dict] = []
        for i, x in enumerate(value):
            out.extend(_flatten_value(x, prefix + [i]))
        return out
    if _is_plain_object(value):
        keys = sorted(value.keys(), key=_UTF8_ORDER)
        if len(keys) == 0:
            return [{"path": prefix, "value": {}}]
        out = []
        for k in keys:
            out.extend(_flatten_value(value[k], prefix + [k]))
        return out
    return [{"path": prefix, "value": value}]


def _chunk_string(s: str, size: Any) -> List[dict]:
    chars = list(s)  # by code point
    if len(chars) == 0:
        return [{"path": ["#chunk", 0], "value": ""}]
    step = len(chars) if size == math.inf else int(size)
    return [{"path": ["#chunk", idx], "value": "".join(chars[i:i + step])} for idx, i in enumerate(range(0, len(chars), step))]


def _leaf_object(leaf: dict) -> dict:
    return {"p": leaf["path"], "v": leaf["value"], "s": leaf["salt"]}


def _request_headers_digest(headers: Any) -> str:
    norm: Dict[str, Any] = {}
    if headers is not None:
        for k, val in headers.items():
            norm[k.lower()] = val
    return hash_canonical(norm)


def to_pub_b64u(key: Any) -> str:
    """A public key as b64u: a b64u string, raw bytes, or a key pair ``{"publicKey": bytes, "secretKey": bytes}``."""
    if isinstance(key, str):
        return key
    if isinstance(key, (bytes, bytearray)):
        return b64u(bytes(key))
    if isinstance(key, dict):
        return b64u(key["publicKey"])
    raise TypeError("not a public key")


# ---- attestation --------------------------------------------------------------------------------------------------

def notary_message(session: Any) -> bytes:
    """The bytes the notary signs: ``NOTARY_DOMAIN || sha256(canonical(session))``."""
    return NOTARY_DOMAIN + sha256(canonical_bytes_strict(session))


def notarize_response(request: Any, response: Any, notary_key: Any, observed_at: Any = None, text_chunk_size: Any = None,
                      random_bytes: Callable[[int], bytes] = os.urandom) -> Dict[str, Any]:
    """Witness a request/response: the signed attestation plus the prover's private witness (the per-leaf openings)."""
    if not isinstance(request, dict) or not isinstance(request.get("method"), str) or len(request["method"]) == 0:
        raise TypeError("notarizeResponse: request.method is required")
    if not isinstance(request.get("url"), str) or len(request["url"]) == 0:
        raise TypeError("notarizeResponse: request.url is required")
    if not isinstance(response, dict) or not _safe_integer(response.get("status")):
        raise TypeError("notarizeResponse: response.status must be an integer")
    body = response.get("body")
    size = text_chunk_size
    if isinstance(body, str) and not isinstance(size, bool) and isinstance(size, (int, float)) and size >= 1:
        bare = _chunk_string(body, math.floor(size) if size != math.inf else size)
    else:
        bare = _flatten_value(body, [])
    leaves = [{"path": l["path"], "value": l["value"], "salt": b64u(random_bytes(16))} for l in bare]
    root = merkle_root([_leaf_object(l) for l in leaves])
    status = response["status"]
    session = {
        "v": 1,
        "method": request["method"].upper(),
        "url": request["url"],
        "requestHeadersDigest": _request_headers_digest(request.get("headers")),
        "responseStatus": int(status) if isinstance(status, float) and not _neg_zero(status) else status,
        "responseBodyCommit": {"alg": BODY_COMMIT_ALG, "root": root, "size": len(leaves)},
        "observedAt": int(time.time() * 1000) if observed_at is None else observed_at,
    }
    attestation = {
        "session": session,
        "notary": b64u(notary_key["publicKey"]),
        "sig": b64u(ed25519.sign_secret(notary_key["secretKey"], notary_message(session))),
    }
    return {"attestation": attestation, "witness": {"session": session, "leaves": leaves}}


def disclose_field(_attestation: Any, witness: Any, path: Any) -> Dict[str, Any]:
    """Reveal ONE response field (by path) with its Merkle inclusion proof. Raises if the path names no committed leaf."""
    want = _normalize_path(path)
    idx = -1
    for i, l in enumerate(witness["leaves"]):
        if _canonical_equal(l["path"], want):
            idx = i
            break
    if idx < 0:
        raise ValueError("discloseField: no committed field at path")
    leaf = witness["leaves"][idx]
    proof = merkle_proof([_leaf_object(l) for l in witness["leaves"]], idx)
    return {"path": leaf["path"], "value": leaf["value"], "salt": leaf["salt"], "proof": proof}


# ---- verification (fail closed) -----------------------------------------------------------------------------------

def _valid_commit(c: Any) -> bool:
    return (isinstance(c, dict) and c.get("alg") == BODY_COMMIT_ALG and isinstance(c.get("root"), str)
            and decode_b64u_strict(c["root"], 32) is not None and _safe_integer(c.get("size")) and c["size"] >= 1)


def _valid_session(s: Any) -> bool:
    if not isinstance(s, dict):
        return False
    v = s.get("v")
    return (v == 1 and not isinstance(v, bool) and isinstance(s.get("method"), str) and isinstance(s.get("url"), str)
            and isinstance(s.get("requestHeadersDigest"), str)
            and _safe_integer(s.get("responseStatus")) and not _neg_zero(s["responseStatus"])
            and _safe_integer(s.get("observedAt")) and not _neg_zero(s["observedAt"])
            and _valid_commit(s.get("responseBodyCommit")))


def verify_notary_attestation(attestation: Any, notary_key: Any) -> bool:
    """The attestation is structurally valid, signed by the TRUSTED notary key, and the signature verifies."""
    try:
        if not isinstance(attestation, dict) or not _valid_session(attestation.get("session")):
            return False
        if not isinstance(attestation.get("notary"), str) or not isinstance(attestation.get("sig"), str):
            return False
        if attestation["notary"] != to_pub_b64u(notary_key):
            return False
        return _verify_b64u(attestation["notary"], notary_message(attestation["session"]), attestation["sig"])
    except Exception:
        return False


def verify_disclosed_field(attestation: Any, disclosure: Any, notary_key: Any) -> bool:
    """The attestation is authentic AND the disclosed leaf is included under the attested body root."""
    try:
        if not verify_notary_attestation(attestation, notary_key):
            return False
        if not isinstance(disclosure, dict) or not isinstance(disclosure.get("path"), list) or not isinstance(disclosure.get("salt"), str):
            return False
        proof = disclosure.get("proof")
        if not isinstance(proof, dict) or not isinstance(proof.get("path"), list):
            return False
        commit = attestation["session"]["responseBodyCommit"]
        if isinstance(proof.get("size"), bool) or proof.get("size") != commit["size"]:
            return False
        leaf = _leaf_object({"path": disclosure["path"], "value": disclosure["value"], "salt": disclosure["salt"]})
        return verify_inclusion(commit["root"], proof, leaf)
    except Exception:
        return False


# ---- PCA binding --------------------------------------------------------------------------------------------------

def fact_ref(attestation: Any) -> str:
    """A stable digest of the attested fact (independent of any PCActn binding)."""
    return hash_canonical({"fact": "atlas-pca-notary/v1", "session": attestation["session"], "notary": attestation["notary"],
                           "sig": attestation["sig"]})


def bind_fact_to_pc_actn(attestation: Any, pc_actn: Any) -> Dict[str, Any]:
    """A new attestation stamped with the digest of the PCActn the fact is FOR."""
    base = {} if attestation is None else dict(attestation)
    return {**base, "fact_binding": {"pcactn_digest": hash_canonical(pc_actn)}}


def fact_matches_pc_actn(attestation: Any, pc_actn: Any) -> bool:
    """Bound in BOTH directions: the fact names the action AND the action's provenance.trusted_refs commits to the fact."""
    try:
        binding = attestation.get("fact_binding")
        if not isinstance(binding, dict) or not isinstance(binding.get("pcactn_digest"), str):
            return False
        if binding["pcactn_digest"] != hash_canonical(pc_actn):
            return False
        prov = pc_actn.get("provenance")
        refs = prov.get("trusted_refs") if isinstance(prov, dict) else None
        if not isinstance(refs, list):
            return False
        return fact_ref(attestation) in refs
    except Exception:
        return False


# ---- policy caveat ------------------------------------------------------------------------------------------------

def require_attested_fact(notary: Any, path: Any, equals: Any, url: Any = _UNSET, bind_to_pc_actn: Any = _UNSET) -> Dict[str, Any]:
    if not isinstance(path, (str, list, tuple)):  # path.slice(): a string slices to itself, a list copies, anything else has no slice
        raise TypeError("opts.path.slice is not a function")
    cv: Dict[str, Any] = {"type": ATTESTED_FACT_CAVEAT, "notary": to_pub_b64u(notary), "path": path if isinstance(path, str) else list(path), "equals": equals}
    if url is not _UNSET:
        cv["url"] = url
    if bind_to_pc_actn is not _UNSET:
        cv["bindToPcActn"] = bind_to_pc_actn
    return cv


def notary_key_usable(ring: Any, key: Any, observed_at: Any) -> bool:
    """`key` is listed in `ring`, not revoked, and `observed_at` lies in its [notBefore, notAfter) window."""
    if not isinstance(ring, (list, tuple)) or not _safe_integer(observed_at):
        return False
    entries = [e for e in ring if isinstance(e, dict) and e.get("key") == key]
    if not entries:
        return False
    obs = float(observed_at)

    def in_window(e: dict) -> bool:
        return (("notBefore" not in e) or obs >= _to_number(e["notBefore"])) and (("notAfter" not in e) or obs < _to_number(e["notAfter"]))

    return all(e.get("revoked") is not True for e in entries) and any(in_window(e) for e in entries)


def evaluate_attested_fact_caveat(caveat: Any, evidence: Any, policy: Any = _UNSET, now: Optional[int] = None) -> Dict[str, Any]:
    """Admit an action only when the notarized field verifies and satisfies the caveat; every step fails closed."""
    try:
        if not isinstance(caveat, dict) or caveat.get("type") != ATTESTED_FACT_CAVEAT:
            return {"ok": False, "reason": "not an attested_fact caveat"}
        if not isinstance(caveat.get("notary"), str) or not isinstance(caveat.get("path"), list):
            return {"ok": False, "reason": "caveat is malformed (notary/path)"}
        if evidence is None:
            raise TypeError("evidence is required")
        ev = evidence if isinstance(evidence, dict) else {}
        attestation, disclosure, pc_actn = ev.get("attestation"), ev.get("disclosure"), ev.get("pcActn")
        pol = {} if policy is _UNSET else policy
        if pol is None:
            raise TypeError("policy is null")
        if not isinstance(pol, dict):
            pol = {}
        if not verify_notary_attestation(attestation, caveat["notary"]):
            return {"ok": False, "reason": "notary attestation does not verify (fail closed)"}
        if "keyring" in pol and not notary_key_usable(pol["keyring"], attestation["notary"], attestation["session"]["observedAt"]):
            return {"ok": False, "reason": "notary key is not trusted for this observation time (unlisted, revoked or out of window)"}
        if "maxAgeMs" in pol:
            clock = pol.get("now")
            if clock is None:
                clock = now if now is not None else int(time.time() * 1000)
            if not _finite(pol["maxAgeMs"]) or not _finite(clock):
                return {"ok": False, "reason": "attestation is stale or from the future"}
            age = clock - attestation["session"]["observedAt"]
            if age < 0 or age > pol["maxAgeMs"]:
                return {"ok": False, "reason": "attestation is stale or from the future"}
        if "url" in caveat and attestation["session"]["url"] != caveat["url"]:
            return {"ok": False, "reason": "attested session URL does not match the caveat"}
        if not verify_disclosed_field(attestation, disclosure, caveat["notary"]):
            return {"ok": False, "reason": "disclosed field does not verify under the attested root"}
        if not _canonical_equal(disclosure["path"], caveat["path"]):
            return {"ok": False, "reason": "disclosed field is not the path the caveat requires"}
        if "equals" not in caveat or not _canonical_equal(disclosure["value"], caveat["equals"]):
            return {"ok": False, "reason": "disclosed field value does not satisfy the caveat"}
        if _truthy(caveat.get("bindToPcActn")):
            if not _truthy(pc_actn):
                return {"ok": False, "reason": "caveat requires PCActn binding but no PCActn was supplied"}
            if not fact_matches_pc_actn(attestation, pc_actn):
                return {"ok": False, "reason": "fact is not bound to this PCActn"}
        return {"ok": True, "trust": "notary-trusted"}
    except Exception as e:  # noqa: BLE001 - fail closed
        return {"ok": False, "reason": "attested_fact evaluation error (fail closed): %s" % (str(e) or "unknown")}


def is_attested_fact_caveat(cv: Any) -> bool:
    return isinstance(cv, dict) and cv.get("type") == ATTESTED_FACT_CAVEAT and isinstance(cv.get("notary"), str) and isinstance(cv.get("path"), list)
