"""Differential oracle: atlas_pca.gateway (canonical query, request binding, path hardening, replay guard, provenance log,
presented artifacts, authorize / create_gateway over real signed proofs, the Envoy HTTP / gRPC shapes and the Lambda
authorizers) against the vectors generated from the TypeScript reference (@atlasauth/pca-gateway).

Compared after masking: the verdict objects print "<verdict>" and the strict-JSON parser's own message in
"undecodable PCA-Action header: <message>" prints "<json>"."""
import re

import pytest

from atlas_pca import gateway as G
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("gateway")


def _mask(s):
    if isinstance(s, str):
        return re.sub(r"undecodable PCA-Action header: (?!PCA-Action header)[\s\S]*", "undecodable PCA-Action header: <json>", s)
    if isinstance(s, list):
        return [_mask(x) for x in s]
    if isinstance(s, dict):
        out = {}
        for k, v in s.items():
            out[k] = "<verdict>" if k in ("x-pca-verdict", "pcaVerdict") and isinstance(v, str) and v != "" else _mask(v)
        h = out.get("header")
        if isinstance(h, dict) and h.get("key") == "x-pca-verdict" and h.get("value") != "":
            out["header"] = dict(h, value="<verdict>")
        return out
    return s


def _build(spec):
    now = spec["now"]
    kw = dict(audience=spec["audience"], routes=spec["routes"], resolve_grant=lambda ref, _p=None: spec["grants"].get(ref), now=lambda: now)
    b = spec.get("bindRequest")
    if b == "off":
        kw["bind_request"] = False
    elif b is not None:
        kw["bind_request"] = b
    if spec.get("unmatched") is not None:
        kw["unmatched_route"] = spec["unmatched"]
    if spec.get("pathPolicy") is not None:
        kw["path_policy"] = spec["pathPolicy"]
    if spec.get("requireChecks") is not None:
        kw["require_checks"] = spec["requireChecks"]
    if spec.get("realm") is not None:
        kw["realm"] = spec["realm"]
    if spec.get("skipPlan"):
        kw["insecure_skip_plan_root_check"] = True
    if spec.get("planRoots") is not None:
        kw["authorized_plan_roots"] = spec["planRoots"]

    class Raising:
        def claim(self, *_a):
            raise RuntimeError("store down")

    class Fixed:
        def __init__(self, v):
            self.v = v

        def claim(self, *_a):
            return self.v

    guards = {"always": lambda: Fixed(True), "false": lambda: Fixed(False), "throws": Raising,
              "memory": lambda: G.memory_replay_guard(100000, lambda: now), "memory-full": lambda: G.memory_replay_guard(1, lambda: now)}
    if spec["replay"] != "none":
        kw["replay_guard"] = guards[spec["replay"]]()

    def rev_throws(_c):
        raise RuntimeError("rev down")

    revs = {"ok": lambda _c: {"enforced": True, "ok": True}, "revoked": lambda _c: {"enforced": True, "ok": False, "reason": "grant revoked"},
            "revoked-noreason": lambda _c: {"enforced": True, "ok": False}, "notEnforced": lambda _c: {"enforced": False}, "throws": rev_throws}
    if spec["revocation"] != "none":
        kw["hooks"] = {"revocation": revs[spec["revocation"]]}

    def cp_throws(_c):
        raise RuntimeError("policy down")

    cps = {"true": lambda _c: True, "false": lambda _c: False, "obj-true": lambda _c: {"allow": True}, "obj-false": lambda _c: {"allow": False},
           "obj-false-reason": lambda _c: {"allow": False, "reason": "over limit"}, "throws": cp_throws}
    if spec.get("checkProof"):
        kw["check_proof"] = cps[spec["checkProof"]]
    pol = spec["policy"]
    if pol == "sig":
        kw["policy"] = {"mode": "signature-only"}
    elif pol == "bogus":
        kw["policy"] = {"mode": "bogus"}
    elif pol == "full-missing":
        kw["policy"] = {"mode": "full", "params": "body"}
    return G.GatewayOptions(**kw)


def _proj(d):
    out = {"allow": d["allow"], "status": d["status"], "code": d["code"], "reason": d["reason"], "headers": d["headers"]}
    if "matched" in d:
        out["matched"] = d["matched"]
    if d.get("pcactn") is not None and d["pcactn"].get("grant_ref") is not None:
        out["grant"] = d["pcactn"]["grant_ref"]
    if d.get("verdict") is not None:
        out["verdictAllow"] = d["verdict"]["allow"]
    return _mask(out)


def _authorize(spec):
    try:
        gw = G.create_gateway(_build(spec))
    except (TypeError, ValueError) as e:
        return {"create": str(e)}
    return [_proj(gw(r)) for r in spec["requests"]]


def _adapter(make):
    def call(spec):
        try:
            fn = make(_build(spec))
        except (TypeError, ValueError) as e:
            return {"create": str(e)}
        return _mask(fn(spec["events"][0]))
    return call


def _lambda_lone(make):
    def call(spec):
        try:
            return _mask(make(_build(spec))(spec["events"][0]))
        except ValueError as e:
            return {"threw": str(e)}
    return call


def _replay(spec):
    clock = [spec.get("clock", 0)]
    g = G.memory_replay_guard(spec["max"], lambda: clock[0])
    out = []
    for op in spec["ops"]:
        if "setClock" in op:
            clock[0] = op["setClock"]
            continue
        try:
            out.append(g.claim(op["key"], op["exp"], op.get("now")))
        except Exception as e:  # noqa: BLE001
            out.append({"threw": str(e)})
    return out


def _prov_log(spec):
    log = G.memory_provenance_log(spec["max"])
    out = []
    for op in spec["ops"]:
        if op.get("add"):
            log.add(op["session"], op["o"])
            out.append("added")
        else:
            out.append(log.seen(op["session"]))
    return out


def _policy(kind):
    return {"params": "body"} if kind == "body" else {"params": lambda _r: {}}


def _presented(fn):
    def call(rq, kind):
        v = fn({"method": "POST", "path": "/", **rq}, _policy(kind))
        return {"undef": True} if v is G.ABSENT else v
    return call


MAP = {
    # a JSON null is a JS null here (the reference throws reading startsWith of it); the native None means "no query"
    "canonicalQuery": lambda q: G.canonical_query(q) if q is not None else (_ for _ in ()).throw(TypeError("null query")),
    "requestBinding": lambda r, o=None: G.request_binding(dict(r, headers={}), o),
    "bindParams": lambda p, b=None: G.bind_params(p, b),
    "ambiguousPathReason": G.ambiguous_path_reason,
    "replayScenario": _replay,
    "provenanceLogScenario": _prov_log,
    "presentedProvenance": _presented(G.presented_provenance),
    "presentedArtifacts": _presented(G.presented_artifacts),
    "authorizeScenario": _authorize,
    "envoyScenario": _adapter(G.envoy_ext_authz),
    "grpcScenario": _adapter(G.envoy_grpc_ext_authz),
    "lambdaScenario": _lambda_lone(G.lambda_authorizer),
    "lambdaSimpleScenario": _lambda_lone(G.lambda_simple_authorizer),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in BY_FN.values()) and set(BY_FN) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _skipped = run(BY_FN[fn], MAP[fn])
    assert ran == len(BY_FN[fn])
