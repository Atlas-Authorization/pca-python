"""Differential kill tests (rule 14, signed action schemas) against the shared TS-generated oracle
testdata/k042-actionschema.json (tools/pca-audit/java-mutate/k042-actionschema-oracle.mts; Java K042ActionSchemaTest runs
the same file). Inputs are raw JSON text; verdicts and reasons are compared exactly."""
import json
import os

import pytest

from atlas_pca.intent_v2 import suite_capability_error
from atlas_pca.intent_v2 import (
    accumulation_params, action_schema_shape_error, canon_projection, conform_action, param_value_violation,
    verify_action_schema,
)

with open(os.path.join(os.path.dirname(__file__), "testdata", "k042-actionschema.json"), encoding="utf-8") as fh:
    G = json.load(fh)


def _j(t):
    return json.loads(t, parse_int=lambda s: -0.0 if s == "-0" else int(s))


PQ_ALGS = ("ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "fn-dsa-512", "fn-dsa-1024", "less-cat1")


def _skip_if_suite_unavailable(reason):
    """A PQ suite this host's backend lacks is refused `unsupported_suite` here by design (the reference host has it)."""
    if isinstance(reason, str) and "unsupported_suite" in reason and any(a in reason and suite_capability_error(a) for a in PQ_ALGS):
        pytest.skip("PQ suite unavailable on this host")


def _ids(k):
    return [c["name"] for c in G[k]]


def test_corpus_sizes():
    assert [len(G[k]) for k in ("shape", "pvv", "conform", "verify", "acc", "canon")] == [390, 258, 29, 40, 6, 5]


@pytest.mark.parametrize("c", G["shape"], ids=_ids("shape"))
def test_shape(c):
    want, got = c["expect"], action_schema_shape_error(_j(c["doc"]))
    _skip_if_suite_unavailable(got)
    if want and got and want.startswith("malformed schema: canonicalize: ") and got.startswith("malformed schema: canonicalize: "):
        return  # the strict canonicalizer's own message is language-specific
    assert got == want


@pytest.mark.parametrize("c", G["pvv"], ids=_ids("pvv"))
def test_param_value_violation(c):
    got = param_value_violation(_j(c["d"]), _j(c["x"]))
    want = c["expect"]
    assert (None if got is None else {"code": got["code"], "reason": got["reason"]}) == want


@pytest.mark.parametrize("c", G["conform"], ids=_ids("conform"))
def test_conform(c):
    want = c["expect"]
    try:
        got = conform_action(_j(c["doc"]), c["verb"], _j(c["params"]))
    except Exception as e:  # noqa: BLE001
        pytest.fail("threw %r" % e)
    if want.get("ok"):
        assert got["ok"] is True
    else:
        assert (got["ok"], got["code"], got.get("path"), got["reason"]) == (False, want["code"], want.get("path"), want["reason"])


@pytest.mark.parametrize("c", G["verify"], ids=_ids("verify"))
def test_verify(c):
    got = verify_action_schema(_j(c["doc"]), _j(c["keys"]))
    _skip_if_suite_unavailable(None if got["ok"] else got["reason"])
    assert (None if got["ok"] else got["reason"]) == c["expect"]


@pytest.mark.parametrize("c", G["acc"], ids=_ids("acc"))
def test_accumulation_params(c):
    assert accumulation_params(_j(c["v"]), c["unit"]) == c["expect"]


@pytest.mark.parametrize("c", G["canon"], ids=_ids("canon"))
def test_canon_projection(c):
    want = c["expect"]
    try:
        got = canon_projection(_j(c["doc"]), c["verb"], _j(c["params"]))
    except Exception:  # noqa: BLE001
        got = "threw"
    assert got == (want["out"] if want["ok"] else "threw")
