"""Replays the shared TS-generated oracle of the action schema checks (testdata/base-actionschema.json.gz, 16139 cases): the closed-world shape of a
signed and of an unsigned schema, the confirmation and wallet-floor declarations, the per-parameter value check and the v2 format checkers, over
well-formed documents and hostile values. Every fn has a handler and the case total is asserted. A shape reason that carries the strict canonicalizer's own
message (``malformed schema: canonicalize: ...``) is compared by that prefix: the text after it is the reference language's."""
import os

import pytest

from atlas_pca import intent_v2 as V
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("actionschema", os.path.join(HERE, "testdata", "base-actionschema.json.gz"))
CANON_PREFIX = "malformed schema: canonicalize: "


def _format(f, s):
    check = V.format_check(f)
    return "unknown" if check is None else check(s)


def _pvv(d, x):
    got = V.param_value_violation(d, x)
    return None if got is None else {"code": got["code"], "reason": got["reason"]}


HANDLERS = {
    "shape": V.action_schema_shape_error,
    "shapeUnsigned": lambda doc: V.action_schema_shape_error(doc, signed=False),
    "confirmation": V.confirmation_shape_error,
    "floors": V.schema_floors_error,
    "pvv": _pvv,
    "format": _format,
}
TOTALS = {"shape": 10502, "shapeUnsigned": 6, "confirmation": 425, "floors": 391, "pvv": 3027, "format": 1788}


def _same(got, out, _case):
    if isinstance(out, str) and out.startswith(CANON_PREFIX):
        return isinstance(got, str) and got.startswith(CANON_PREFIX)
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 16139 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_actionschema_replay(fn):
    assert run(CASES[fn], HANDLERS[fn], compare=_same) == (TOTALS[fn], 0)
