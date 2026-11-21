"""Replays the TS-reference oracle of the software attestation layer (testdata/ref-attestation-soft.json.gz, 512 cases): the binding hash, the dev
attestor and its documents, the registry, the nonce store and entropy gate, the agent-binding match, verify_attestation and its hook, the
multi-root verifier and evidence anchoring. Every fn has a handler and the totals are asserted; a reference refusal needs a native exception.
A reference reason with "(fail closed):" carries the reference's own exception text after the colon: only the text up to it is compared. The 2
verifyAttestation cases the reference accepts only through the legacy unbound-PQ opt-out are asserted REFUSED (no native lane offers it)."""
import json
import math
import os

import pytest

from atlas_pca import attestation_soft as A
from atlas_pca.ledger_proofs import TransparencyLedger
from atlas_pca.pq_suites import ml_dsa65_keygen
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("attestation-soft", os.path.join(HERE, "testdata", "ref-attestation-soft.json.gz"))
UNBOUND = []
MARK = "(fail closed):"


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


class _Hw:
    def __init__(self, h):
        self._h = h

    def verify(self, inp):
        if "throws" in self._h:
            raise RuntimeError(self._h["throws"])
        return self._h.get("result")


def _hw(h):
    return None if h is None else _Hw(h)


def _suite(s):
    if s is None:
        return None
    if s["alg"] == "ed25519" or "pqSeed" not in s:
        return {"alg": s["alg"]}
    return {"alg": s["alg"], "pq": ml_dsa65_keygen(s["pqSeed"])}


def _nonce_store(max_entries, opts, ops):
    st = {"t": 0}
    store = A.memory_nonce_store(100_000 if max_entries is None else max_entries, dict(opts or {}, now=lambda: st["t"]))
    out = []
    for op in ops:
        if op[0] == "clock":
            st["t"] = op[1]
            out.append(None)
        else:
            out.append(store.consume(op[1]))
    return out


def _registry(docs, qs):
    r = A.attestation_registry(docs)
    return [r({"pcactn": {"attestation": {"quote_digest": q}}}) for q in qs]


def _verify(i):
    r = {k: v for k, v in i.items() if k not in ("hardware", "document")}
    r["document"] = i.get("document")
    r["hardwareVerifier"] = _hw(i.get("hardware"))
    return A.verify_attestation(r)


def _hook(op, ctxs):
    now = op["now"]
    o = {k: v for k, v in op.items() if k not in ("store", "storeConsume", "hardware", "docs", "binding", "now")}
    o.update(now=lambda: now, hardwareVerifier=_hw(op.get("hardware")), resolveDocument=A.attestation_registry(op.get("docs") or []))
    if op.get("store") is not None and op.get("store") is not False:  # a JS object is truthy even when empty
        s = op["store"]
        o["nonceStore"] = A.memory_nonce_store(s.get("max", 100_000), {"retentionMs": s.get("retentionMs"), "now": lambda: now})
    if "storeConsume" in op:
        o["nonceStore"] = type("Const", (), {"consume": staticmethod(lambda n: op["storeConsume"])})()
    b = op.get("binding")
    if b == "throws":
        def boom(c):
            raise RuntimeError("boom")
        o["expectedBinding"] = boom
    elif b:
        o["expectedBinding"] = lambda c: b["byNonce"].get(A._path(c, "pcactn", "attestation", "quote_digest"))
    hook = A.create_attestation_verifier(o)
    return [hook(c) for c in ctxs]


def _multi_root(pol, inp):
    roots = []
    for r in pol["roots"]:
        e = {"id": r["id"], "verifier": _hw(r.get("hw"))}
        if "required" in r:
            e["required"] = r["required"]
        if "suite" in r:
            e["suite"] = r["suite"]
        roots.append(e)
    v = A.create_multi_root_verifier({"threshold": pol["threshold"], "roots": roots})
    return {"built": True} if inp is None else v.verify(inp)


def _anchor(ev, op):
    ledger = TransparencyLedger(op.get("principal") or "") if op.get("ledger") == "ok" else None
    for i in range(op.get("preload") or 0):
        ledger.append_commitment("c%d" % i)
    o = {"ledger": ledger}
    if op.get("guardianSeed"):
        o["guardianSecret"] = op["guardianSeed"]
    if "instanceId" in op:
        o["instanceId"] = op["instanceId"]
    if "now" in op:
        o["now"] = lambda: op["now"]
    if "required" in op:
        o["required"] = op["required"]
    return A.anchor_attestation_evidence(ev, o)


HANDLERS = {
    "attestationBinding": A.attestation_binding, "attestationBindingB64u": A.attestation_binding_b64u,
    "attest": lambda secret, su, cl: A.create_dev_attestor(secret, _suite(su)).attest(cl),
    "attestorPublicKey": lambda secret, su: A.create_dev_attestor(secret, _suite(su)).public_key,
    "attestationDigest": A.attestation_digest, "registry": _registry, "nonceStore": _nonce_store,
    "nonceEntropyOk": lambda n, m: A.nonce_entropy_ok(n, m), "requiresAttestation": A.requires_attestation, "nonceBinds": A.nonce_binds,
    "matchAgentBinding": A.match_agent_binding, "verifyAttestation": _verify, "attestationHook": _hook, "multiRoot": _multi_root,
    "attestationEvidenceDigest": A.attestation_evidence_digest, "anchorEvidence": _anchor,
    "constants": lambda: {"ATTEST_BIND_DOMAIN": A.ATTEST_BIND_DOMAIN, "MAX_ATTESTATION_AGE_MS": A.MAX_ATTESTATION_AGE_MS,
                          "DEFAULT_NONCE_RETENTION_MS": A.DEFAULT_NONCE_RETENTION_MS, "MIN_ATTESTATION_NONCE_BYTES": A.MIN_ATTESTATION_NONCE_BYTES,
                          "ATTEST_ANCHOR_DOMAIN": A.ATTEST_ANCHOR_DOMAIN},
}
TOTALS = {"matchAgentBinding": 170, "verifyAttestation": 91, "nonceEntropyOk": 32, "requiresAttestation": 29, "attestationBinding": 27,
          "attestationBindingB64u": 27, "multiRoot": 27, "nonceStore": 23, "attestationHook": 23, "attest": 18, "attestationEvidenceDigest": 11,
          "anchorEvidence": 10, "nonceBinds": 8, "attestationDigest": 6, "registry": 6, "attestorPublicKey": 3, "constants": 1}


def _same(got, out, case):
    if case["fn"] == "verifyAttestation" and "allowUnboundPq" in json.dumps(case["args"]) and isinstance(out, dict) and out.get("ok") is True:
        UNBOUND.append(case["name"])
        return isinstance(got, dict) and got.get("ok") is False
    if isinstance(out, str) and MARK in out:
        return isinstance(got, str) and got.startswith(out[:out.index(MARK) + len(MARK)])
    if isinstance(out, dict) and isinstance(got, dict):
        return set(out) == set(got) and all(_same(got[k], out[k], case) for k in out)
    if isinstance(out, list) and isinstance(got, list):
        return len(out) == len(got) and all(_same(g, o, case) for g, o in zip(got, out))
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 512 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 69


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_attestation_soft_replay(fn):
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same) == (TOTALS[fn], 0)
    if fn == "verifyAttestation":
        assert len(UNBOUND) == 2
