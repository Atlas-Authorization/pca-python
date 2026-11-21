"""Replays the TS-reference oracle of the reputation validator (testdata/ref-reputation.json.gz, 85 cases): validateReputationInput, the
fail-closed edges of reputation() (invalid input scores 0 with the reason, compared exactly; a dispute counts once per id; the rate
rounding) and the constants. Every fn has a handler and the total is asserted. The record cap is not in the corpus (it would be
megabytes): it is tested here with a generated list."""
import math
import os

import pytest

from atlas_pca import reputation as R
from base_oracle import HERE, canon, load

COUNT, CASES = load("reputation", os.path.join(HERE, "testdata", "ref-reputation.json.gz"))


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


HANDLERS = {
    "validateReputationInput": R.validate_reputation_input,
    "reputation": R.reputation,
    "constants": lambda: {"MAX_REPUTATION_RECORDS": R.MAX_REPUTATION_RECORDS, "COVERAGE_QUOTE_DOMAIN": R.COVERAGE_QUOTE_DOMAIN},
}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 85 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == {"validateReputationInput": 38, "reputation": 46, "constants": 1}


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_reputation_replay(fn):
    bad = []
    for c in CASES[fn]:
        try:
            got = HANDLERS[fn](*_dec(c["args"]))
        except Exception as e:  # noqa: BLE001 - neither function may raise
            bad.append("%s\n    native raised %s: %s" % (c["name"], type(e).__name__, e))
            continue
        if canon(got) != canon(c["out"]):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:400], canon(c["out"])[:400]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))


def test_the_record_cap():
    ev = {"agent": "a", "outcome": "auto"}
    assert R.validate_reputation_input({"subject": "s", "events": [ev] * R.MAX_REPUTATION_RECORDS}) is None
    over = {"subject": "s", "events": [ev] * (R.MAX_REPUTATION_RECORDS + 1)}
    assert R.validate_reputation_input(over) == "too many records"
    assert R.reputation(over)["score"] == 0 and R.reputation(over)["factors"] == ["invalid input: too many records"]
    d = {"id": "d", "subject": "s", "slashed": False, "at": 0}
    assert R.validate_reputation_input({"subject": "s", "disputes": [d] * (R.MAX_REPUTATION_RECORDS + 1)}) == "too many records"
