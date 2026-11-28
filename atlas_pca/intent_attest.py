"""Intent map attestations, runtime observations and ledger anchors (the TypeScript `intent` module beyond the statement): a detached
signature over an Intent Map digest, a signed labelled outcome against a map, and the verifier of an anchoring receipt (the artifact's
leaf under a guardian-signed tree head). Producers sign under any suite the runtime can sign; verifiers dispatch through the
verifier-pinned suite check. Verdicts are ``{"ok": True}`` / ``{"ok": False, "reason": ...}``; the verifiers never raise."""
from __future__ import annotations

from ._fin import fin
import json
from typing import Any, Dict, Optional

from .intent_statement import _suite_fields_error
from .intent_v2 import _UNDEF, _bind_suite_fields, _pinned_suite_error
from .pca import _is_safe_int, canonical_bytes_strict, decode_b64u_strict, hash_canonical

INTENT_MAP_SIG_DOMAIN = "atlas-pca/intent-map-sig/v1\0"
INTENT_OBS_SIG_DOMAIN = "atlas-pca/intent-obs/v1\0"
INTENT_ANCHOR_DOMAIN = "atlas-pca/intent-anchor/v1"
INTENT_ANCHOR_LOG = "pca-intent:v1"
INTENT_OBSERVATION_SOURCES = ("runtime", "witness", "elicitation", "import")
INTENT_ANCHOR_KINDS = ("statement", "map", "observation", "schema", "session", "delta", "receipt", "profile", "evidence")

_MAP_ATT_FIELDS = ("v", "map_digest", "intent_ref", "signer", "signed_at")
_OBS_FIELDS = ("v", "map_digest", "verb", "values", "y", "source", "observed_at", "pcactn_digest", "signer")


def _g(o: dict, k: str) -> Any:
    return o.get(k, _UNDEF)


def _int(v: Any) -> bool:
    return _is_safe_int(v)


def _b32(v: Any) -> bool:
    return decode_b64u_strict(v, 32) is not None


def _msg(domain: str, body: dict) -> bytes:
    return domain.encode("utf-8") + canonical_bytes_strict(body)


def _pinned(art: dict, identity: Any, domain: str, body: dict, opts: dict) -> bool:
    msg = _msg(domain, _bind_suite_fields(body, _g(art, "alg"), _g(art, "pq_pk")))
    pins = opts.get("pqPins") if isinstance(opts.get("pqPins"), dict) else None
    return _pinned_suite_error(_g(art, "alg"), identity, _g(art, "pq_pk"), msg, _g(art, "sig"), _g(art, "pq_sig"), pins) is None


def _sign(domain: str, body: dict, key: Any, alg: Optional[str], pq: Any) -> dict:
    from .agent import sign_artifact
    return sign_artifact(domain, body, key, alg, pq)


# ---- intent map attestation ---------------------------------------------------------------------------------

def intent_map_shape_error(m: Any) -> Optional[str]:
    """Structural check of an Intent Map (does not replay it)."""
    if not isinstance(m, dict) or _g(m, "v") != 1 or isinstance(_g(m, "v"), bool) or m.get("kind") != "pca-intent-map":
        return "not an intent map v1"
    ref = _g(m, "intent_ref")
    if ref is not None and not _b32(ref):
        return "intent_ref must be null or canonical base64url (32 bytes)"
    mt = _g(m, "metrics")
    if not isinstance(mt, dict):
        return "metrics must be an object"
    f = _g(mt, "fidelity_est_ppm")
    if not _int(f) or f < 0 or f > 1_000_000:
        return "metrics.fidelity_est_ppm must be an integer in [0, 1e6]"
    r = _g(mt, "residual_risk_ppm")
    if not _int(r) or r < 0:
        return "metrics.residual_risk_ppm must be a non-negative integer"
    return None


def _map_att_body(a: dict) -> dict:
    return {k: a[k] for k in _MAP_ATT_FIELDS if k in a}


def sign_intent_map_attestation(intent_map: dict, signer: Any, signed_at: int, alg: Optional[str] = None, pq: Any = None) -> dict:
    """Detached signature over the map's digest by `signer` (a KeyPair); raises on a malformed map or timestamp."""
    from .intent_mapkit import intent_map_digest
    bad = intent_map_shape_error(intent_map)
    if bad:
        raise ValueError("signIntentMapAttestation: %s" % bad)
    if not _int(signed_at) or signed_at < 0:
        raise ValueError("signIntentMapAttestation: signedAt must be a non-negative safe integer")
    body = {"v": 1, "map_digest": intent_map_digest(intent_map), "intent_ref": intent_map["intent_ref"], "signer": signer.public, "signed_at": signed_at}
    return _sign(INTENT_MAP_SIG_DOMAIN, body, signer, alg, pq)


def verify_intent_map_attestation(a: Any, intent_map: Any = _UNDEF, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Well-formed, signature valid, and (when `intent_map` is given) its digest and intent_ref match."""
    from .intent_mapkit import intent_map_digest
    opts = opts or {}
    try:
        if not isinstance(a, dict) or _g(a, "v") != 1 or isinstance(_g(a, "v"), bool):
            return {"ok": False, "reason": "not an intent map attestation v1"}
        if not _b32(_g(a, "map_digest")):
            return {"ok": False, "reason": "map_digest is not canonical base64url (32 bytes)"}
        ref = _g(a, "intent_ref")
        if ref is not None and not _b32(ref):
            return {"ok": False, "reason": "intent_ref must be null or canonical base64url (32 bytes)"}
        if not _b32(_g(a, "signer")):
            return {"ok": False, "reason": "signer is not canonical base64url (32 bytes)"}
        if not _int(_g(a, "signed_at")) or a["signed_at"] < 0:
            return {"ok": False, "reason": "signed_at must be a non-negative safe integer"}
        if opts.get("expectedSigner") is not None and a["signer"] != opts["expectedSigner"]:
            return {"ok": False, "reason": "signer mismatch"}
        se = _suite_fields_error(a)
        if se:
            return {"ok": False, "reason": se}
        if intent_map is not _UNDEF:
            bad = intent_map_shape_error(intent_map)
            if bad:
                return {"ok": False, "reason": bad}
            if intent_map_digest(intent_map) != a["map_digest"]:
                return {"ok": False, "reason": "map digest mismatch"}
            if intent_map.get("intent_ref") != _g(a, "intent_ref"):
                return {"ok": False, "reason": "intent_ref mismatch"}
        if not _pinned(a, a["signer"], INTENT_MAP_SIG_DOMAIN, _map_att_body(a), opts):
            return {"ok": False, "reason": "bad signature"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "malformed intent map attestation: %s" % e}


# ---- runtime observations -----------------------------------------------------------------------------------

def _obs_body(o: dict) -> dict:
    return json.loads(json.dumps({k: o[k] for k in _OBS_FIELDS if k in o and o[k] is not _UNDEF}))


def _obs_shape_error(o: Any) -> Optional[str]:
    if not isinstance(o, dict) or _g(o, "v") != 1 or isinstance(_g(o, "v"), bool):
        return "not an intent observation v1"
    if not _b32(_g(o, "map_digest")):
        return "map_digest is not canonical base64url (32 bytes)"
    verb = _g(o, "verb")
    if not isinstance(verb, str) or len(verb) == 0:
        return "verb must be a non-empty string"
    vals = _g(o, "values")
    if not isinstance(vals, dict) or not all(isinstance(x, str) or (isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)) for x in vals.values()):
        return "values must map paths to numbers or strings"
    y = _g(o, "y")
    if isinstance(y, bool) or not isinstance(y, (int, float)) or y not in (0, 1):
        return "y must be 0 or 1"
    src = _g(o, "source")
    if not isinstance(src, str) or src not in INTENT_OBSERVATION_SOURCES:
        return "unknown observation source"
    if not _int(_g(o, "observed_at")) or o["observed_at"] < 0:
        return "observed_at must be a non-negative safe integer"
    if _g(o, "pcactn_digest") is not _UNDEF and not _b32(o["pcactn_digest"]):
        return "pcactn_digest is not canonical base64url (32 bytes)"
    if not _b32(_g(o, "signer")):
        return "signer is not canonical base64url (32 bytes)"
    return None


def sign_intent_observation(o: dict, signer: Any, alg: Optional[str] = None, pq: Any = None) -> dict:
    """Sign a labelled outcome against a map (`o` carries no `v` or `signer`; both are set here)."""
    body = _obs_body({**o, "v": 1, "signer": signer.public})
    bad = _obs_shape_error(body)
    if bad:
        raise ValueError("signIntentObservation: %s" % bad)
    return _sign(INTENT_OBS_SIG_DOMAIN, body, signer, alg, pq)


def verify_intent_observation(o: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    opts = opts or {}
    try:
        bad = _obs_shape_error(o)
        if bad:
            return {"ok": False, "reason": bad}
        if opts.get("expectedSigner") is not None and o["signer"] != opts["expectedSigner"]:
            return {"ok": False, "reason": "signer mismatch"}
        se = _suite_fields_error(o)
        if se:
            return {"ok": False, "reason": se}
        if not _pinned(o, o["signer"], INTENT_OBS_SIG_DOMAIN, _obs_body(o), opts):
            return {"ok": False, "reason": "bad signature"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "malformed intent observation: %s" % e}


# ---- ledger anchoring ---------------------------------------------------------------------------------------

def _prop(o: Any, k: str) -> Any:
    """A member read as the reference does it: absent on a non-object, a refusal on null or an absent value."""
    if o is None or o is _UNDEF:
        raise TypeError("cannot read %r of %s" % (k, "null" if o is None else "undefined"))
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def intent_anchor_commit(kind: str, digest: str) -> str:
    """The log leaf for an anchored artifact: H({d, kind, digest})."""
    return hash_canonical({"d": INTENT_ANCHOR_DOMAIN, "kind": kind, "digest": digest})


def verify_intent_anchor(r: Any, guardian_public: str, instance_id: str, pins: Optional[dict] = None) -> Dict[str, Any]:
    """The head is signed by `guardian_public` for the intent log of `instance_id` and the artifact's leaf is included at `index`."""
    from .ledger import verify_ledger_inclusion, verify_tree_head
    try:
        kind, digest = _prop(r, "kind"), _prop(r, "digest")
        if not isinstance(kind, str) or kind not in INTENT_ANCHOR_KINDS:
            return {"ok": False, "reason": "unknown anchor kind"}
        if not _b32(digest):
            return {"ok": False, "reason": "digest is not canonical base64url (32 bytes)"}
        h, proof = _prop(r, "signed_tree_head"), _prop(r, "proof")
        if _prop(h, "principal") != INTENT_ANCHOR_LOG or _prop(h, "instance_id") != instance_id:
            return {"ok": False, "reason": "not a head of this instance intent log"}
        if not verify_tree_head(h, guardian_public, None, pins):
            return {"ok": False, "reason": "tree head signature invalid"}
        if _prop(proof, "index") != _prop(r, "index") or _prop(proof, "size") != _prop(h, "size"):
            return {"ok": False, "reason": "proof does not match the head"}
        if not verify_ledger_inclusion(_prop(h, "root"), proof, intent_anchor_commit(kind, digest)):
            return {"ok": False, "reason": "artifact is not included under the signed head"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "malformed anchor receipt: %s" % e}
