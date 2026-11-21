"""Resource-server discovery: ``/.well-known/pca-configuration`` (the TypeScript ``discovery``). The OIDC-discovery analog for PCA: a
resource server publishes its audience id, the signature suites it accepts, the header it reads the PCActn from and the URLs of its
freshness and step-up endpoints. The document is PUBLIC configuration: never put keys or secrets in it.

Pure: :func:`build_discovery_document` and :func:`parse_discovery_document` do no I/O; :func:`fetch_discovery` takes an injected
``fetch(url, init) -> response`` (``response.ok``, ``response.status``, ``response.json()``)."""
from ._fin import fin
import math
from typing import Any, Callable, Dict, List, Optional

__all__ = ["WELL_KNOWN_PCA_PATH", "parse_discovery_intent", "build_discovery_document", "parse_discovery_document", "fetch_discovery",
           "accepts_suite"]

WELL_KNOWN_PCA_PATH = "/.well-known/pca-configuration"

_DEFAULT_SUITES = ["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"]
_DEFAULT_REQUIRED = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"]
_INTENT_KEYS = ("versions", "actions_uri", "schema_keys", "question_relay", "tiers", "evidence_uri")


def _num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _str_list(x: Any) -> bool:
    return isinstance(x, list) and all(isinstance(s, str) for s in x)


def parse_discovery_intent(v: Any) -> Dict[str, Any]:
    """Validate an ``intent`` discovery block (raises ValueError on anything malformed: fail closed)."""
    if not isinstance(v, dict):
        raise ValueError("parseDiscoveryDocument: intent must be an object")
    for k in v:
        if k not in _INTENT_KEYS:
            raise ValueError("parseDiscoveryDocument: intent has unknown member '%s'" % k)
    ver = v.get("versions")
    if not isinstance(ver, list) or len(ver) == 0 or not all(_num(n) and n in (1, 2) for n in ver):
        raise ValueError("parseDiscoveryDocument: intent.versions must list 1 and/or 2")
    out: Dict[str, Any] = {"versions": list(ver)}
    for k in ("actions_uri", "evidence_uri"):
        if k in v:
            if not isinstance(v[k], str) or len(v[k]) == 0:
                raise ValueError("parseDiscoveryDocument: intent.%s must be a non-empty string" % k)
            out[k] = v[k]
    if "schema_keys" in v:
        if not isinstance(v["schema_keys"], list):
            raise ValueError("parseDiscoveryDocument: intent.schema_keys must be an array")
        keys = []
        for e in v["schema_keys"]:
            if not isinstance(e, dict) or not all(isinstance(e.get(k), str) for k in ("kid", "alg", "pk")) \
                    or ("pq_pk" in e and not isinstance(e["pq_pk"], str)):
                raise ValueError("parseDiscoveryDocument: intent.schema_keys entries are {kid, alg, pk, pq_pk?}")
            keys.append({"kid": e["kid"], "alg": e["alg"], "pk": e["pk"], **({"pq_pk": e["pq_pk"]} if "pq_pk" in e else {})})
        out["schema_keys"] = keys
    if "question_relay" in v:
        if not isinstance(v["question_relay"], bool):
            raise ValueError("parseDiscoveryDocument: intent.question_relay must be a boolean")
        out["question_relay"] = v["question_relay"]
    if "tiers" in v:
        t = v["tiers"]
        if not isinstance(t, dict):
            raise ValueError("parseDiscoveryDocument: intent.tiers must be an object")
        if not all(_num(n) and fin(n) and n == int(n) and 0 <= n <= 4 and not (n == 0 and math.copysign(1, n) < 0) for n in t.values()):
            raise ValueError("parseDiscoveryDocument: intent.tiers values must be integers 0..4")
        out["tiers"] = dict(t)
    return out


def build_discovery_document(audience: str, *, signature_suites: Optional[List[str]] = None, pca_versions: Optional[List[int]] = None,
                             action_header: Optional[str] = None, required_checks: Optional[List[str]] = None,
                             endpoints: Optional[dict] = None, trusted_roots: Optional[List[str]] = None, metadata: Optional[dict] = None,
                             intent: Optional[dict] = None, obligations_supported: Optional[List[str]] = None) -> Dict[str, Any]:
    """Build a well-formed discovery document. Raises ValueError on an empty audience."""
    if not isinstance(audience, str) or len(audience) == 0:
        raise ValueError("buildDiscoveryDocument: audience is required")
    doc: Dict[str, Any] = {
        "audience": audience,
        "pca_versions": [2] if pca_versions is None else pca_versions,
        "signature_suites": list(_DEFAULT_SUITES) if signature_suites is None else signature_suites,
        "action_header": "PCA-Action" if action_header is None else action_header,
        "required_checks": list(_DEFAULT_REQUIRED) if required_checks is None else required_checks,
    }
    def truthy(x: Any) -> bool:  # JavaScript truthiness: an empty array or object is truthy
        return x is not None and x is not False and x != 0 and x != ""
    if truthy(endpoints):
        doc["endpoints"] = endpoints
    if truthy(trusted_roots):
        doc["trusted_roots"] = trusted_roots
    if truthy(metadata):
        doc["metadata"] = metadata
    if truthy(intent):
        doc["intent"] = parse_discovery_intent(intent)
    if truthy(obligations_supported):
        doc["obligations_supported"] = list(obligations_supported)
    return doc


def parse_discovery_document(value: Any) -> Dict[str, Any]:
    """Validate and narrow an untrusted value into a discovery document. Raises ValueError on anything malformed."""
    if not isinstance(value, dict):
        raise ValueError("parseDiscoveryDocument: not an object")
    v = value
    if not isinstance(v.get("audience"), str) or len(v["audience"]) == 0:
        raise ValueError("parseDiscoveryDocument: missing audience")
    if not isinstance(v.get("pca_versions"), list) or not all(_num(n) for n in v["pca_versions"]):
        raise ValueError("parseDiscoveryDocument: pca_versions must be a number[]")
    if not _str_list(v.get("signature_suites")):
        raise ValueError("parseDiscoveryDocument: signature_suites must be a string[]")
    if not isinstance(v.get("action_header"), str) or len(v["action_header"]) == 0:
        raise ValueError("parseDiscoveryDocument: missing action_header")
    doc: Dict[str, Any] = {"audience": v["audience"], "pca_versions": v["pca_versions"], "signature_suites": v["signature_suites"],
                           "action_header": v["action_header"]}
    if _str_list(v.get("required_checks")):
        doc["required_checks"] = v["required_checks"]
    if isinstance(v.get("endpoints"), (dict, list)):  # typeof object and not null: an array is kept as given
        doc["endpoints"] = v["endpoints"]
    if _str_list(v.get("trusted_roots")):
        doc["trusted_roots"] = v["trusted_roots"]
    if isinstance(v.get("metadata"), (dict, list)):
        doc["metadata"] = v["metadata"]
    if "intent" in v:
        doc["intent"] = parse_discovery_intent(v["intent"])
    if "obligations_supported" in v:
        if not _str_list(v["obligations_supported"]):
            raise ValueError("parseDiscoveryDocument: obligations_supported must be a string[]")
        doc["obligations_supported"] = list(v["obligations_supported"])
    return doc


def fetch_discovery(base_url: str, fetch: Callable[[str, dict], Any]) -> Dict[str, Any]:
    """Fetch and parse a resource server's discovery document. `base_url` is the server origin; the well-known path is appended.
    `fetch(url, init)` returns an object with ``ok``, ``status`` and ``json()``. Raises on a non-2xx response or a malformed document."""
    url = base_url.rstrip("/") + WELL_KNOWN_PCA_PATH
    res = fetch(url, {"headers": {"accept": "application/json"}})
    if not res.ok:
        raise ValueError("fetchDiscovery: %s returned %s" % (url, res.status))
    return parse_discovery_document(res.json())


def accepts_suite(doc: Dict[str, Any], suite: str) -> bool:
    """True iff this server (per its discovery document) accepts a given signature suite."""
    return suite in doc["signature_suites"]
