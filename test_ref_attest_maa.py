"""Replays the TS-reference oracle of the Azure MAA key trust and its release-signed pins (testdata/ref-attest-maa.json.gz, 261 cases): the constants, JWKS
evaluation (the real public certificate sets and synthetic certificates), the built-in pin loader, multi-vantage corroboration, the guarded certs fetch
over a scripted transport (the URLs it requested are compared), the rotation-safe trust store over scripted fetches (the final store and the requested
URLs are compared), the durable store adapter and the construction refusals. Every fn has a handler and the totals are asserted; a reference refusal
needs a native exception. A rejection reason that is the certificate reader's own text (``error:`` / ``The first argument``) is compared by presence."""
import json
import os

import pytest

pytest.importorskip("cryptography")  # the dependency-free job has no cryptography; every other job replays this corpus

from atlas_pca import attest_maa_keys as K
from atlas_pca import attest_maa_pins as P
from atlas_pca.durable_state import create_memory_durable_kv
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("attest-maa", os.path.join(HERE, "testdata", "ref-attest-maa.json.gz"))
LIB_TEXT = ("error:", "The first argument")


def _response(r):
    if "$throws" in r:
        raise RuntimeError(r["$throws"])
    if "bodyBytes" in r:
        body = r["bodyBytes"]
    elif isinstance(r.get("body"), dict) and "$text" in r["body"]:
        body = r["body"]["$text"].encode("utf-8")
    else:
        body = json.dumps(r.get("body"), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    res = {"status": r.get("status", 200), "headers": {"content-type": "application/json"}, "body": body}
    if "contentLength" in r:
        res["headers"]["content-length"] = str(r["contentLength"])
    if "url" in r:
        res["url"] = r["url"]
    return res


def _seq_fetch(steps, log):
    i = [0]

    def fetch(url, init):
        log.append(url + (" [redirect:error]" if init.get("redirect") == "error" else ""))
        s = steps[min(i[0], len(steps) - 1)]
        i[0] += 1
        return _response({"body": s} if "keys" in s and "body" not in s else s)
    return fetch


def _constants():
    return {"BUILTIN_CHAIN_LEAF_CN": list(P.BUILTIN_CHAIN_LEAF_CN), "BUILTIN_MAA_PINS_ISSUER_ID": P.BUILTIN_MAA_PINS_ISSUER_ID,
            "BUILTIN_MAA_PINS_ISSUER_KEYS": P.BUILTIN_MAA_PINS_ISSUER_KEYS}


def _fetch_certs(a):
    log = []
    try:
        out = {"ok": True, "jwks": K.fetch_maa_certs(a["issuer"], dict(a.get("opts") or {}, fetch=_seq_fetch([a["response"]], log)))}
    except Exception as e:  # noqa: BLE001 - the refusal text is part of the corpus
        out = {"ok": False, "error": str(e)}
    out["requests"] = log
    return out


def _trust(sc):
    store = K.create_memory_maa_key_state_store()
    for k, v in (sc.get("initial") or {}).items():
        store.set(k, v)
    log = []
    t = K.create_maa_key_trust({"policy": sc["policy"], "store": store, "fetch": _seq_fetch(sc["fetches"], log)})
    results = []
    for c in sc["calls"]:
        call = {"nowMs": c["nowMs"]}
        if c.get("repin"):
            call["repin"] = c["repin"]
        results.append(t.get_trust_anchors(c["issuer"], call))
    return {"results": results, "store": store.snapshot(), "fetches": log}


def _kv_store(a):
    kv = create_memory_durable_kv()
    st = K.durable_maa_key_state_store(kv)
    out = []
    for s in a["steps"]:
        if "set" in s:
            st.set(s["set"][0], s["set"][1])
            out.append(None)
        else:
            out.append(st.get(s["get"]))
    return {"results": out, "kv": kv.snapshot()}


def _build_trust(c):
    K.create_maa_key_trust({"policy": c["policy"], "store": K.create_memory_maa_key_state_store(), "fetch": None if c.get("noFetch") else (lambda *_: {})})
    return {"built": True}


HANDLERS = {
    "constants": _constants,
    "evaluateMaaJwks": K.evaluate_maa_jwks,
    "loadBuiltinMaaPins": P.load_builtin_maa_pins,
    "corroborate": K.corroborate_maa_key_sets,
    "fetchCerts": _fetch_certs,
    "trust": _trust,
    "kvStore": _kv_store,
    "buildTrust": _build_trust,
}
TOTALS = {"constants": 1, "evaluateMaaJwks": 92, "loadBuiltinMaaPins": 32, "corroborate": 26, "fetchCerts": 36, "trust": 60, "kvStore": 5, "buildTrust": 9}


def _eq(g, o):
    if isinstance(o, str) and o.startswith(LIB_TEXT):
        return isinstance(g, str) and g != ""
    if isinstance(o, dict):
        return isinstance(g, dict) and set(g) == set(o) and all(_eq(g[k], o[k]) for k in o)
    if isinstance(o, list):
        return isinstance(g, list) and len(g) == len(o) and all(_eq(x, y) for x, y in zip(g, o))
    return canon(g) == canon(o)


def _same(got, out, _case):
    return _eq(json.loads(canon(got)), out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 261 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_maa_replay(fn):
    assert run(CASES[fn], HANDLERS[fn], compare=_same) == (TOTALS[fn], 0)
