"""JSON Schema (draft 2020-12) documents for the PCA wire types (PCActn, Capability, the discovery document) and a small
dependency-free STRUCTURAL validator. Mirrors the TypeScript reference (@atlasauth/pca-schema).

The schemas describe structure only (fields, JSON types, required); they cannot express security invariants (signature,
attenuation, plan membership, iat < exp). Passing means "well-formed", never "authorized". Every object is open
(additionalProperties true) so an unknown future field never fails structural validation.

The validator implements only the keywords these schemas use: type (incl. unions), enum, required, properties,
additionalProperties:false, items, and local '#/...' $ref. No pattern/format/oneOf/anyOf/bounds (minItems is published in the
schema for external validators but, as in the reference, not enforced here): for full validation feed the schemas to a
draft-2020-12 validator such as `jsonschema`.
"""
from __future__ import annotations
from ._fin import fin, to_float

import math
from typing import Any, Dict, List

from .predicates import _js_number_string

DRAFT = "https://json-schema.org/draft/2020-12/schema"
_STR: Dict[str, Any] = {"type": "string"}
_ALG = {"type": "string", "enum": ["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"]}

_CAVEAT_DEF: Dict[str, Any] = {"type": "object", "required": ["type"], "properties": {"type": _STR}, "additionalProperties": True}

_CAPABILITY_DEF: Dict[str, Any] = {
    "type": "object",
    "required": ["id", "issuer", "holder", "caveats", "body_digest", "sig"],
    "properties": {
        "id": _STR,
        "issuer": _STR,
        "holder": _STR,
        "caveats": {"type": "array", "items": {"$ref": "#/$defs/caveat"}},
        "parent": _STR,
        "body_digest": _STR,
        "sig": _STR,
        "alg": _ALG,
        "pq_pk": _STR,
        "pq_sig": _STR,
    },
    "additionalProperties": True,
}

_ACTION_DEF: Dict[str, Any] = {
    "type": "object",
    "required": ["verb", "resource", "params_digest", "reversibility_class"],
    "properties": {"verb": _STR, "resource": _STR, "params_digest": _STR, "reversibility_class": _STR},
    "additionalProperties": True,
}

_INCLUSION_PROOF_DEF: Dict[str, Any] = {
    "type": "object",
    "required": ["index", "size", "path"],
    "properties": {
        "index": {"type": "integer"},
        "size": {"type": "integer"},
        "path": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
    },
    "additionalProperties": True,
}

_PLAN_DEF: Dict[str, Any] = {
    "type": "object",
    "required": ["root", "inclusion_proof", "node_id"],
    "properties": {"root": _STR, "inclusion_proof": {"$ref": "#/$defs/inclusionProof"}, "node_id": _STR, "conditions_digest": _STR},
    "additionalProperties": True,
}

_RISK_CLAIM_DEF: Dict[str, Any] = {
    "type": "object",
    "required": ["r", "inputs"],
    "properties": {"r": {"type": "number"}, "inputs": {"type": "object", "additionalProperties": True}},
    "additionalProperties": True,
}

_ATTESTATION_DEF: Dict[str, Any] = {
    "type": "object",
    "required": ["quote_digest", "epoch", "model_id", "measurement", "operator"],
    "properties": {"quote_digest": _STR, "epoch": {"type": "integer"}, "model_id": _STR, "measurement": _STR, "operator": _STR},
    "additionalProperties": True,
}

_PROVENANCE_DEF: Dict[str, Any] = {
    "type": "object",
    "required": ["causal_hash", "taint_level", "trusted_refs"],
    "properties": {"causal_hash": _STR, "taint_level": {"type": "number"}, "trusted_refs": {"type": "array", "items": _STR}},
    "additionalProperties": True,
}

_FRESHNESS_DEF: Dict[str, Any] = {
    "type": "object",
    "required": ["beacon_ref", "epoch", "accumulator_witness"],
    "properties": {"beacon_ref": _STR, "epoch": {"type": "integer"}, "accumulator_witness": _STR},
    "additionalProperties": True,
}

PCACTN_SCHEMA: Dict[str, Any] = {
    "$schema": DRAFT,
    "$id": "https://atlasauth.net/schemas/pca/pcactn.schema.json",
    "title": "PCActn",
    "description": "Proof-Carrying Authority action object (spec §7, wire format v2).",
    "type": "object",
    "required": [
        "ver", "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim",
        "aud", "iat", "exp", "sig",
    ],
    "properties": {
        "ver": {"type": "integer"},
        "action": {"$ref": "#/$defs/action"},
        "grant_ref": _STR,
        "cap_chain": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/capability"}},
        "plan": {"$ref": "#/$defs/plan"},
        "attestation": {"$ref": "#/$defs/attestation"},
        "provenance": {"$ref": "#/$defs/provenance"},
        "freshness": {"$ref": "#/$defs/freshness"},
        "counter": {"type": "integer"},
        "risk_claim": {"$ref": "#/$defs/riskClaim"},
        "aud": _STR,
        "iat": {"type": "integer"},
        "exp": {"type": "integer"},
        "nonce": _STR,
        "caution": {"type": "number"},
        "rationale_commitment": _STR,
        "progress_step": {"type": "object", "additionalProperties": True},
        "prohibition_evidence": {"type": ["object", "array"]},
        "tool_binding": _STR,
        "alg": _ALG,
        "pq_pk": _STR,
        "sig": _STR,
        "pq_sig": _STR,
        "threshold": {"type": "object", "additionalProperties": True},
        "zk_compliance": {"description": "Opaque zk-compliance proof; shape is verifier-defined."},
        "bond_ref": _STR,
    },
    "additionalProperties": True,
    "$defs": {
        "caveat": _CAVEAT_DEF,
        "capability": _CAPABILITY_DEF,
        "action": _ACTION_DEF,
        "inclusionProof": _INCLUSION_PROOF_DEF,
        "plan": _PLAN_DEF,
        "riskClaim": _RISK_CLAIM_DEF,
        "attestation": _ATTESTATION_DEF,
        "provenance": _PROVENANCE_DEF,
        "freshness": _FRESHNESS_DEF,
    },
}

CAPABILITY_SCHEMA: Dict[str, Any] = dict(
    {
        "$schema": DRAFT,
        "$id": "https://atlasauth.net/schemas/pca/capability.schema.json",
        "title": "Capability",
        "description": "An attenuable capability chain hop (spec §5.2).",
    },
    **_CAPABILITY_DEF,
    **{"$defs": {"caveat": _CAVEAT_DEF}},
)

DISCOVERY_SCHEMA: Dict[str, Any] = {
    "$schema": DRAFT,
    "$id": "https://atlasauth.net/schemas/pca/discovery.schema.json",
    "title": "PcaDiscoveryDocument",
    "description": "The .well-known/pca-configuration discovery document (internet-wide integration).",
    "type": "object",
    "required": ["audience", "pca_versions", "signature_suites", "action_header"],
    "properties": {
        "audience": _STR,
        "pca_versions": {"type": "array", "items": {"type": "integer"}},
        "signature_suites": {"type": "array", "items": _STR},
        "action_header": _STR,
        "required_checks": {"type": "array", "items": _STR},
        "endpoints": {"$ref": "#/$defs/endpoints"},
        "trusted_roots": {"type": "array", "items": _STR},
        "metadata": {"type": "object", "additionalProperties": True},
    },
    "additionalProperties": True,
    "$defs": {
        "endpoints": {
            "type": "object",
            "properties": {
                "attestation_challenge": _STR,
                "revocation_epoch": _STR,
                "liveness_beacon": _STR,
                "stepup": _STR,
                "grant": _STR,
            },
            "additionalProperties": True,
        }
    },
}

ALL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "PCActn": PCACTN_SCHEMA,
    "Capability": CAPABILITY_SCHEMA,
    "PcaDiscoveryDocument": DISCOVERY_SCHEMA,
}


def _is_record(v: Any) -> bool:
    return isinstance(v, dict)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_integer(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return fin(v)
    return isinstance(v, float) and v.is_integer()


def _neg_zero(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0


def json_type_of(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, list):
        return "array"
    if isinstance(v, bool):
        return "boolean"
    if _is_num(v):
        return "integer" if _is_integer(v) else "number"
    if isinstance(v, str):
        return "string"
    return "object"


def _matches_type(expected: Any, v: Any) -> bool:
    if expected == "object":
        return _is_record(v)
    if expected == "array":
        return isinstance(v, list)
    if expected == "string":
        return isinstance(v, str)
    if expected == "number":
        return _is_num(v) and fin(v)
    if expected == "integer":
        return _is_integer(v) and not _neg_zero(v)
    if expected == "boolean":
        return isinstance(v, bool)
    if expected == "null":
        return v is None
    return False


def _resolve_ref(root: Any, ref: str) -> Any:
    """A local '#/...' pointer walked over own keys of objects only; None when it does not name an object."""
    if not ref.startswith("#/"):
        return None
    cur = root
    for token in ref[2:].split("/"):
        if not _is_record(cur) or token not in cur:
            return None
        cur = cur[token]
    return cur if _is_record(cur) else None


def _label(path: str) -> str:
    return "(root)" if path == "" else path


def _strict_equal(a: Any, b: Any) -> bool:
    """JS === over decoded JSON: objects and arrays never match (identity)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None:
        return a is None and b is None
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def _stringify(v: Any) -> str:
    """JSON.stringify of a decoded JSON value."""
    import json

    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if _is_num(v):
        return _js_number_string(to_float(v)) if fin(v) else "null"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(_stringify(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(str(k), ensure_ascii=False) + ":" + _stringify(x) for k, x in v.items()) + "}"
    return "null"


def _truthy(v: Any) -> bool:
    return not (v is None or v is False or v == 0 and not isinstance(v, (dict, list)) or v == "")


def _join(path: str, key: str) -> str:
    return key if path == "" else path + "." + key


def _check_node(schema: Any, value: Any, path: str, root: Any, errors: List[str]) -> None:
    if schema is None:
        raise TypeError("schema node is null")
    if not _is_record(schema):
        return  # a boolean/number schema constrains nothing in this subset
    ref = schema.get("$ref")
    if isinstance(ref, str):
        resolved = _resolve_ref(root, ref)
        if resolved is None:
            errors.append("%s: unresolved $ref '%s'" % (_label(path), ref))
            return
        _check_node(resolved, value, path, root, errors)
        return

    if "type" in schema:
        t = schema["type"]
        types = t if isinstance(t, list) else [t]
        if not any(_matches_type(x, value) for x in types):
            errors.append("%s: expected type %s, got %s" % (_label(path), "|".join(str(x) for x in types), json_type_of(value)))
            return  # a wrong base type makes any deeper check meaningless

    enum = schema.get("enum")
    if isinstance(enum, list) and not any(_strict_equal(e, value) for e in enum):
        errors.append("%s: value is not one of [%s]" % (_label(path), ", ".join(_stringify(e) for e in enum)))

    if _is_record(value):
        required = schema.get("required")
        if isinstance(required, list):
            for key in required:
                if key not in value:
                    errors.append("%s: missing required property '%s'" % (_join(path, key), key))
        props = schema.get("properties")
        if _truthy(props) and _is_record(props):
            for key, sub in props.items():
                if key in value:
                    _check_node(sub, value[key], _join(path, key), root, errors)
        if schema.get("additionalProperties") is False and _truthy(props) and _is_record(props):
            for key in value:
                if key not in props:
                    errors.append("%s: additional property not allowed" % _join(path, key))

    items = schema.get("items")
    if isinstance(value, list) and _truthy(items):
        for i, el in enumerate(value):
            _check_node(items, el, "%s[%d]" % (path, i), root, errors)


def validate(schema: Any, value: Any) -> Dict[str, Any]:
    """Structural validation: {"valid": bool, "errors": [str]} (errors empty when valid). Never raises on a bad value."""
    errors: List[str] = []
    _check_node(schema, value, "", schema, errors)
    return {"valid": not errors, "errors": errors}
