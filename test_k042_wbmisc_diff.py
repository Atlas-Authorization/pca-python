"""Differential kill tests (the W-B unit, rules 16-18: atlas_pca.intent_wb.decide_intent_wb) against the shared
TS-generated oracle testdata/k042-wbmisc.json.gz (tools/pca-audit/java-mutate/k042-wbmisc-oracle.mjs; Java
K042WbPcaMiscWbTest runs the same file): outcome, checks in order, exact reason, friction, world / prov / class env
members and single_source."""
import gzip
import json
import os

import pytest

from atlas_pca.intent_wb import decide_intent_wb

with gzip.open(os.path.join(os.path.dirname(__file__), "testdata", "k042-wbmisc.json.gz"), "rt", encoding="utf-8") as fh:
    CASES = json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))["cases"]

EVAL_ERR = "evaluation error (fail closed): "


def _shape(r):
    """The oracle's contract (the Java Result): on deny world / prov / class / friction / single_source are cleared. The
    Python (like the TS) result keeps what an earlier passing check reported; it is not part of a deny's meaning."""
    deny = r["outcome"] == "deny"
    env = {} if deny else (r.get("env") or {})
    r = dict(r, friction=None if deny else r.get("friction"), single_source=None if deny else r.get("single_source"))
    return {
        "outcome": r["outcome"],
        "checks": [[k, v] for k, v in r["checks"].items()],
        "reason": r.get("reason"),
        "friction": r.get("friction"),
        "world": env.get("world"),
        "prov": env.get("prov"),
        "class": env.get("class"),
        "single_source": list(r["single_source"]) if r.get("single_source") else None,
    }


def _clip(reason):
    """An internal-error text is language-specific: compare up to its fixed prefix."""
    if isinstance(reason, str) and EVAL_ERR in reason:
        return reason[: reason.index(EVAL_ERR) + len(EVAL_ERR)]
    return reason


def test_corpus_is_the_full_oracle():
    assert len(CASES) == 942


@pytest.mark.parametrize("c", CASES, ids=[c["name"] for c in CASES])
def test_matches_the_reference(c):
    got, want = _shape(decide_intent_wb(c["input"])), dict(c["expect"])
    got["reason"], want["reason"] = _clip(got["reason"]), _clip(want["reason"])
    assert json.dumps(got, sort_keys=False) == json.dumps(want, sort_keys=False)
