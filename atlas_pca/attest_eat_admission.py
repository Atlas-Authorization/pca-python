"""EAT evidence for blueprint admission and the artifact attestation verifier: a port of the TypeScript reference
(@atlasauth/pca-attest-eat), the admission and provenance modules.

``eat_admission_evidence`` turns an EAT into admission evidence for one instance key: signature, issuer, freshness and RATS
appraisal must all pass and ``cnf.jkt`` must be the RFC 7638 thumbprint of THE INSTANCE KEY, so evidence for one instance cannot
admit another. ``issue_artifact_discharge`` joins Sigstore build provenance to the running image digest from an accepted EAT and
signs the discharge a K1 caveat asks for; any failure returns no discharge, so provenance can only remove authority.
"""
import base64
import hashlib
import math
import os
import re
from typing import Any, Dict, Optional

from .attest_eat_common import G, U, has, is_finite, js_string, js_strict_eq
from .pca import b64u

__all__ = ["ed25519_jkt", "eat_admission_evidence", "runtime_digest_from_eat", "issue_artifact_discharge"]

_TIER_RANK = {"rejected": 0, "contraindicated": 0, "warning": 1, "affirming": 2, "affirming-hw-rooted": 3}


def ed25519_jkt(holder_pub_b64u: Any) -> str:
    """RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url."""
    canonical = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % js_string(holder_pub_b64u)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode("utf-8", "replace")).digest()).rstrip(b"=").decode("ascii")


def eat_admission_evidence(eat: Any, o: Dict[str, Any]) -> Dict[str, Any]:
    """Admission evidence for ``o["instanceKey"]`` (unpadded base64url Ed25519 public key) from an EAT. `o` carries the options of
    ``verify_fresh_attested_eat`` (verifyKey, nonce, policy, now ...) plus ``minTier`` (``affirming`` by default, so degraded
    ``warning`` evidence does not admit). Anything unverifiable is ``ok: False``. The identity returned is the measured identity
    the verifier established. A ``minTier`` other than ``affirming`` / ``affirming-hw-rooted`` is refused before verification."""
    from .attest_eat import verify_fresh_attested_eat

    try:
        min_tier = o.get("minTier", U)
        if min_tier is not U and min_tier not in ("affirming", "affirming-hw-rooted"):
            return {"ok": False, "bound": False, "reason": "invalid minTier"}
        min_tier = "affirming" if min_tier is U else min_tier
        rest = {k: v for k, v in o.items() if k not in ("instanceKey", "minTier")}
        rest["channelBinding"] = {"jkt": ed25519_jkt(o.get("instanceKey", U))}
        v = verify_fresh_attested_eat(eat, rest)
        if not v["ok"] or v.get("tier") is None:
            return {"ok": False, "bound": False, "reason": v["reasons"][-1] if v["reasons"] else "EAT rejected"}
        if not _TIER_RANK.get(v["tier"], -1) >= _TIER_RANK[min_tier]:
            return {"ok": False, "bound": True, "reason": "appraisal tier %s is below the minimum" % v["tier"]}
        m = G(v.get("claims"), "measured") if v.get("claims") is not None else U
        # a pass checked cnf.jkt against the instance key, so it is bound
        if m is U or m is None:
            return {"ok": True, "bound": True}
        return {"ok": True, "bound": True, "identity": {"runtime_measurement": m["runtime_measurement"], "model_id": m["model_id"],
                                                         "weights_digest": m["weights_digest"], "operator": m["operator"]}}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "bound": False, "reason": "TypeError" if isinstance(e, TypeError) else "Error"}


# ---------------------------------------------------------------------------------------------------------------- provenance


def runtime_digest_from_eat(verdict: Any, o: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, str]]:
    """The running image's digest from an ACCEPTED EAT: exactly one ``measurements`` entry labelled ``slot`` (default ``image``),
    lowercase hex of the algorithm's length (sha256: 64, else 128). None when the verdict is not ok, the slot is missing or
    repeated, or the value is malformed (no case folding)."""
    o = {} if o is None else o
    if not isinstance(verdict, dict) or verdict.get("ok") is not True or verdict.get("claims") in (None, "", 0, False):
        return None
    slot, alg = G(o, "slot"), G(o, "alg")
    slot = "image" if slot is U or slot is None else slot
    alg = "sha256" if alg is U or alg is None else alg
    ms = G(verdict["claims"], "measurements")
    if ms is U or ms is None:
        ms = []
    if not isinstance(ms, list):
        raise TypeError("(verdict.claims.measurements ?? []).filter is not a function")
    hits = [m for m in ms if js_strict_eq(G(m, "type"), slot)]
    if len(hits) != 1:
        return None
    v = G(hits[0], "value")
    pat = r"[0-9a-f]{64}" if alg == "sha256" else r"[0-9a-f]{128}"
    return {"alg": alg, "digest": v} if isinstance(v, str) and re.fullmatch(pat, v) else None


def _discharge_body(request: Any, gate: Dict[str, Any], iat: Any, ttl_ms: Any, nonce: str) -> Dict[str, Any]:
    """The unsigned discharge body (request's binding + the gate's claims); raises unless the gate passed and the ttl fits the request."""
    if not gate.get("ok"):
        raise ValueError("provenanceDischargeBody: the provenance gate refused (%s)" % gate.get("code"))
    req_ttl = G(request, "ttl_ms")
    if not (is_finite(ttl_ms) and is_finite(iat)):
        raise ValueError("provenanceDischargeBody: ttl_ms and iat must be numbers")
    if req_ttl is not U and (not is_finite(req_ttl) or ttl_ms > req_ttl):
        raise ValueError("provenanceDischargeBody: ttl_ms exceeds what the caveat accepts")
    body: Dict[str, Any] = {"v": 1, "kind": "pca-discharge"}
    for k in ("caveat_id", "issuer", "cap_hash", "bind", "action_digest"):
        val = G(request, k)
        if val is not U:  # an undefined member is absent from the signed JSON
            body[k] = val
    body["claims"] = gate["claims"]
    body["iat"] = iat
    body["not_after"] = iat + ttl_ms
    body["nonce"] = nonce
    return body


def _seconds(now: Any) -> Any:
    return float("nan") if not is_finite(now) else (now // 1000 if isinstance(now, int) else math.floor(now / 1000))


def issue_artifact_discharge(i: Dict[str, Any]) -> Dict[str, Any]:
    """Run, for one discharge request: (1) the Sigstore bundle against the pinned roots, (2) the join with the running image digest
    (``runtime`` from ``runtime_digest_from_eat``; an EAT that yielded no digest, ``None``, is a failed join), (3) the provenance
    gate (the verifier's own pins), (4) sign the discharge with the gate's claims. Returns
    ``{"ok": True, "discharge", "facts", "level"}`` or ``{"ok": False, "stage": "sigstore" | "gate", "code", ...}``; raises on a
    malformed signing input.

    ``i``: bundle, roots (``parse_trusted_root`` result), policy, runtime (optional), request, now (epoch ms), issuerSecret (the
    32-byte Ed25519 seed of the ``artifact``-class key), ttl_ms (optional), nonce (optional, default random 16 bytes)."""
    from .agent import DISCHARGE_DOMAIN, KeyPair, sign_artifact
    from .caveat_lang import discharge_shape_error
    from .provenance_gate import provenance_gate
    from .sigstore_bundle import verify_sigstore_bundle

    v = verify_sigstore_bundle(G(i, "bundle"), G(i, "roots"))
    if not v["ok"]:
        return {"ok": False, "stage": "sigstore", "code": v["code"], "detail": v["detail"]}
    # an EAT that yielded no digest is not "no runtime": it is a failed join
    if has(i, "runtime") and i["runtime"] is None:
        return {"ok": False, "stage": "gate", "code": "no_runtime"}
    now = G(i, "now")
    inp: Dict[str, Any] = {"facts": v["facts"], "policy": G(i, "policy"), "now": _seconds(now)}
    if has(i, "runtime"):
        inp["runtime"] = i["runtime"]
    gate = provenance_gate(inp)
    if not gate["ok"]:
        return {"ok": False, "stage": "gate", "code": gate["code"]}
    request = G(i, "request")
    ttl = G(i, "ttl_ms")
    ttl = G(request, "ttl_ms") if ttl is U or ttl is None else ttl
    nonce = G(i, "nonce")
    nonce = b64u(os.urandom(16)) if nonce is U or nonce is None else nonce
    body = _discharge_body(request, gate, now, ttl, nonce)
    seed = G(i, "issuerSecret")
    discharge = sign_artifact(DISCHARGE_DOMAIN, body, KeyPair(bytes(seed)))
    e = discharge_shape_error(discharge)  # signDischarge throws on a malformed body (fail closed)
    if e:
        raise ValueError("signDischarge: %s" % e)
    return {"ok": True, "discharge": discharge, "facts": v["facts"], "level": gate["level"]}

