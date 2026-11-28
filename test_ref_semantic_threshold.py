"""Replays the TS-reference oracle of the semantic judge threshold (testdata/ref-semantic-threshold.json.gz, 186 cases): score quantisation, the signed
statement and message, the verdict digest, signing under every suite, verdict verification, the judge attestation gate, the k-of-n threshold with
calibration, pins and the attestation gate, the hook and the risk contribution. Every fn has a handler and the totals are asserted; a reference refusal
needs a native exception. The 1 threshold the reference accepts only through the legacy unbound-PQ opt-out is asserted REFUSED (no native lane offers it)."""
import json
import math
import os

import pytest

from atlas_pca import semantic_threshold as S
from atlas_pca.pq_suites import ml_dsa65_keygen
from atlas_pca.intent_v2 import _UNDEF
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("semantic-threshold", os.path.join(HERE, "testdata", "ref-semantic-threshold.json.gz"))
UNBOUND = []
UNBOUND_VERDICT = []


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _suite(s):
    if s is None:
        return None
    if s["alg"] == "ed25519" or "pqSeed" not in s:
        return {"alg": s["alg"]}
    return {"alg": s["alg"], "pq": ml_dsa65_keygen(s["pqSeed"])}


def _att(a):
    if not a:
        return None
    o = {"require": a["require"], "resolve": lambda v: (a.get("byJudge") or {}).get(v.get("judge"))}
    if "approved" in a:
        o["approved"] = a["approved"]
    return o


def _threshold(verdicts, opts):
    o = {k: v for k, v in opts.items() if k not in ("attestation", "allowUnboundPq")}
    if opts.get("attestation"):
        o["attestation"] = _att(opts["attestation"])
    return S.verify_semantic_threshold(verdicts, o)


def _verifier(opts, ctxs):
    cfg = {k: v for k, v in opts.items() if k not in ("actionDigestMode",)}
    cfg["verdicts"] = lambda c: c.get("verdicts")
    cfg["goalCommitment"] = lambda c: c.get("goal")
    mode = opts.get("actionDigestMode", "default")
    if mode.startswith("fixed:"):
        cfg["actionDigest"] = lambda c: mode[6:]
    cfg["attestation"] = lambda c: _att(c.get("attestation"))
    hook = S.create_semantic_verifier(cfg)
    return [hook(c) for c in ctxs]


HANDLERS = {
    "quantizeScore": S.quantize_score, "statementOf": lambda v: {k: x for k, x in S.statement_of(v).items() if x is not _UNDEF}, "semanticJudgeMessage": S.semantic_judge_message, "verdictDigest": S.verdict_digest,
    "signJudgeVerdict": lambda sk, v, su: S.sign_judge_verdict(sk, v, _suite(su)),
    "verifyJudgeVerdict": lambda v, e, p: S.verify_judge_verdict(v, e, p),
    "verifyJudgeAttestation": lambda m, a, ap: S.verify_judge_attestation(m, a, ap),
    "verifySemanticThreshold": _threshold, "semanticVerifier": _verifier, "semanticRiskContribution": S.semantic_risk_contribution,
    "constants": lambda: {"SEMANTIC_JUDGE_DOMAIN": S.SEMANTIC_JUDGE_DOMAIN, "SCORE_SCALE": S.SCORE_SCALE},
}
TOTALS = {"verifySemanticThreshold": 39, "verifyJudgeVerdict": 27, "quantizeScore": 26, "statementOf": 21, "verifyJudgeAttestation": 18,
          "semanticRiskContribution": 14, "signJudgeVerdict": 13, "semanticVerifier": 12, "semanticJudgeMessage": 11, "verdictDigest": 4, "constants": 1}


def _same(got, out, case):
    if case["fn"] == "verifySemanticThreshold" and "allowUnboundPq" in json.dumps(case["args"]) and isinstance(out, dict) and out.get("ok") is True:
        UNBOUND.append(case["name"])
        return isinstance(got, dict) and got.get("ok") is False
    if case["fn"] == "verifyJudgeVerdict" and "allowUnboundPq" in json.dumps(case["args"]) and out is True:
        UNBOUND_VERDICT.append(case["name"])
        return got is False  # the legacy unbound-PQ opt-out is not offered: the reference's acceptance is a refusal here
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 186 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 5


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_semantic_threshold_replay(fn):
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same) == (TOTALS[fn], 0)
    if fn == "verifySemanticThreshold":
        assert len(UNBOUND) == 1
    if fn == "verifyJudgeVerdict":
        assert len(UNBOUND_VERDICT) == 1
