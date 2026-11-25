"""Differential oracle: atlas_pca.fetch (with_pca / create_pca_fetch_guard) against the vectors generated from the TypeScript
reference (@atlasauth/pca-fetch): the construction guards and the pre-verification refusals. Compared by shape: the core
verifier's reason text and challenge string are its own."""
import json

import pytest

from atlas_pca import fetch as F
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("fetch")
AUD = "rs_fetch"


def _construct(kind):
    def handler(_req, _ctx):
        return {"status": 200, "headers": {}, "body": "ok"}

    def resolve(_ref):
        return None

    if kind == "ok":
        F.with_pca(handler, audience=AUD, resolve_grant=resolve, insecure_allow_unbound_operation=True)
    elif kind == "noaudience":
        F.with_pca(handler, audience="", resolve_grant=resolve, insecure_allow_unbound_operation=True)
    elif kind == "nooperation":
        F.with_pca(handler, audience=AUD, resolve_grant=resolve)
    else:
        raise ValueError("unknown kind")
    return {"built": True}


def _request(spec):
    ran = []

    def resolve(_ref):
        if spec["resolve"] == "throws":
            raise RuntimeError("store down")
        return None

    def handler(_req, _ctx):
        ran.append(True)
        return {"status": 200, "headers": {}, "body": '{"ok":true}'}

    guarded = F.with_pca(handler, audience=AUD, resolve_grant=resolve, insecure_allow_unbound_operation=True)
    res = guarded({"method": "POST", "url": "http://localhost/refunds", "headers": spec.get("headers") or {}, "body": spec.get("body")})
    try:
        body = json.loads(res["body"])
    except ValueError:
        body = None
    www = res["headers"].get("WWW-Authenticate")
    return {"status": res["status"], "handlerRan": bool(ran), "decision": body.get("decision") if isinstance(body, dict) else None,
            "challenge": (www is not None and www.startswith('PCA realm="')) if res["status"] == 401 else None,
            "contentType": res["headers"].get("content-type"),
            "bodyKeys": sorted(body) if isinstance(body, dict) else None,
            "errorIsString": isinstance(body, dict) and isinstance(body.get("error"), str)}


MAP = {"constructScenario": _construct, "requestScenario": _request}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in BY_FN.values()) and set(BY_FN) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _skipped = run(BY_FN[fn], MAP[fn])
    assert ran == len(BY_FN[fn])
