"""Binding of the objective-risk commitment to the decision path: the facts live in the signed grant envelope as an optional
`objective_risk` field (covered by the root signature). `read_objective_commitment` is the pure, total reader."""
from __future__ import annotations

from typing import Any, Dict

from .authorize import read_envelope

__all__ = ["read_objective_commitment", "resolve_objective_risk"]


def _obj(v: Any) -> bool:
    return isinstance(v, dict)


def _str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def read_objective_commitment(grant: Any) -> Dict[str, Any]:
    """``{}`` = not committed; ``{"commitment": ...}`` when well-formed; ``{"malformed": reason}`` otherwise."""
    env = read_envelope(grant)
    if not _obj(env) or "objective_risk" not in env:
        return {}
    raw = env["objective_risk"]
    if not _obj(raw) or isinstance(raw.get("v"), bool) or raw.get("v") != 1:
        return {"malformed": "objective_risk: unsupported shape/version"}
    emb = raw.get("embedder")
    if not _obj(emb) or emb.get("scheme") != "native" or not _str(emb.get("model_id")) or not _obj(emb.get("config")):
        return {"malformed": 'objective_risk.embedder must be { scheme: "native", model_id, config }'}
    if not _obj(raw.get("goal")) or not _str(raw["goal"].get("commit")):
        return {"malformed": "objective_risk.goal must be a goal commitment"}
    if not _str(raw.get("registry_digest")) or not _str(raw.get("graph_digest")):
        return {"malformed": "objective_risk needs registry_digest and graph_digest"}
    if "calibration_digest" in raw and not _str(raw["calibration_digest"]):
        return {"malformed": "objective_risk.calibration_digest must be a string"}
    kinds = raw.get("authorized_kinds")
    if not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
        return {"malformed": "objective_risk.authorized_kinds must be string[]"}
    if "denominations" in raw and not isinstance(raw["denominations"], list):
        return {"malformed": "objective_risk.denominations must be an array"}
    if "on_mismatch" in raw and raw["on_mismatch"] not in ("deny", "heuristic"):
        return {"malformed": 'objective_risk.on_mismatch must be "deny" or "heuristic"'}
    return {"commitment": raw}


def _build_registry(cfg: Any) -> Any:
    from .objective_risk import InMemoryInverseRegistry
    cfg = cfg if _obj(cfg) else {}
    reg = InMemoryInverseRegistry(cfg.get("trusted_verifiers") or [])
    for e in cfg.get("entries") or []:
        entry: Dict[str, Any] = {"inverseKind": e["inverse_kind"], "fidelity": e["fidelity"]}
        if e.get("verification"):
            entry["verification"] = {"verifierId": e["verification"]["verifier_id"], "evidenceDigest": e["verification"]["evidence_digest"]}
        reg.register(e["verb"], entry)
    return reg


def _build_graph(cfg: Any) -> Any:
    from .objective_risk import ResourceGraph
    cfg = cfg if _obj(cfg) else {}
    g = ResourceGraph()
    for n in cfg.get("nodes") or []:
        g.add_node(n)
    for e in cfg.get("edges") or []:
        g.add_edge(e)
    return g


def resolve_objective_risk(grant: Any, action: Any, instance: Any, taint: Any = None, age: Any = None) -> Dict[str, Any]:
    """The objective risk inputs for ``action`` under ``grant``. Total (never raises): nothing committed is ``{"mode": "none"}``; committed
    and reproduced is ``{"mode": "objective", "inputs", "r", "evidenceDigest"}``; committed but not reproducible is ``{"mode": "mismatch",
    "reasons", "onMismatch"}`` (``deny`` unless the verifier's own instance config allows the grant's ``heuristic`` fallback). ``taint`` and
    ``age`` are verifier-supplied (default 1, the worst case)."""
    from .objective_risk import calibration_digest, native_hash_embedder, objective_risk
    r = read_objective_commitment(grant)
    if r.get("malformed"):
        return {"mode": "mismatch", "reasons": [r["malformed"]], "onMismatch": "deny"}
    com = r.get("commitment")
    if not com:
        return {"mode": "none"}
    requested = com.get("on_mismatch") or "deny"
    # a GRANT cannot downgrade the verifier's objective risk to the heuristic on its own say-so
    on_mismatch = "heuristic" if requested == "heuristic" and _obj(instance) and instance.get("allow_heuristic_fallback") is True else "deny"

    def miss(*reasons: str) -> Dict[str, Any]:
        return {"mode": "mismatch", "reasons": list(reasons), "onMismatch": on_mismatch}

    try:
        env = read_envelope(grant)
        if not env:
            return miss("grant carries no valid envelope")
        if not _obj(instance):  # an empty config object is a config: it builds the empty registry and graph
            return miss("the grant commits objective-risk facts but the instance holds no objective-risk config")
        registry = _build_registry(instance.get("registry"))
        graph = _build_graph(instance.get("graph"))
        embedder = native_hash_embedder(com["embedder"]["config"])
        if embedder.model_id != com["embedder"]["model_id"]:
            return miss("embedder model_id does not match the committed one")
        calibration = instance.get("calibration")
        has_cal = "calibration_digest" in com
        if has_cal and (calibration is None or calibration_digest(calibration) != com["calibration_digest"]):
            return miss("calibration set does not match the committed digest")
        commitments = {"registryDigest": com["registry_digest"], "graphDigest": com["graph_digest"]}
        if has_cal:
            commitments["calibrationDigest"] = com["calibration_digest"]
        ctx: Dict[str, Any] = {"registry": registry, "authorizedKinds": set(com["authorized_kinds"]), "graph": graph, "embedder": embedder,
                               "goal": com["goal"], "commitments": commitments, "denominations": com.get("denominations") or [],
                               "weights": env["risk_policy"]["weights"], "taint": 1 if taint is None else taint, "age": 1 if age is None else age}
        if com.get("scope") is not None:
            ctx["scope"] = com["scope"]
        if has_cal and calibration is not None:
            ctx["calibration"] = calibration
        res = objective_risk(action, ctx)
        if not res["valid"]:
            return miss(*res["reasons"])
        i = res["inputs"]
        return {"mode": "objective", "inputs": {"reversibility": i["reversibility"], "blastRadius": i["blastRadius"], "semanticDistance": i["semanticDistance"]},
                "r": res["r"], "evidenceDigest": res["evidenceDigest"]}
    except Exception as e:  # noqa: BLE001 - fail closed
        return miss("objective risk evaluation error (fail closed): %s" % (str(e) or "unknown"))
