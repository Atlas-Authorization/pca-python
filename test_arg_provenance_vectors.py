"""Provenance by default: replays conformance/arg-provenance-vectors.json (made by the TypeScript reference; a missing file
FAILS, it never skips). Every section: tokens (occurs_as_token), leaves (prov_leaves), read_only (is_read_only_action) and
decisions (decide_arg_provenance, full equality; for a deny the code and a non-empty reason). The recorder reproduces the
reference's bundles byte for byte where the inputs are known."""
import hashlib
import json
import os

import pytest

from atlas_pca.arg_provenance import (create_provenance_recorder, decide_arg_provenance, is_read_only_action, occurs_as_token,
                                      principal_direct_provenance, prov_leaves)
from atlas_pca.pca import b64u

_HERE = os.path.dirname(os.path.abspath(__file__))
_P = next((p for p in (os.path.join(_HERE, "conformance", "arg-provenance-vectors.json"),
                       os.path.join(_HERE, "conformance", "arg-provenance-vectors.json"))
           if os.path.exists(p)), None)
assert _P is not None, "arg-provenance-vectors.json is missing (a missing vector file fails, never skips)"
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)
DECISIONS = {c["name"]: c for c in DOC["decisions"]}


def test_format_and_counts():
    assert DOC["format"] == "pca-arg-provenance-vectors/1"
    assert [len(DOC[k]) for k in ("tokens", "leaves", "read_only")] == [18, 11, 7] and len(DOC["decisions"]) >= 38


@pytest.mark.parametrize("t", DOC["tokens"], ids=[str(i) for i in range(len(DOC["tokens"]))])
def test_arg_provenance_tokens(t):
    assert occurs_as_token(t["text"], t["needle"]) is t["expect"]


@pytest.mark.parametrize("l", DOC["leaves"], ids=[l["name"] for l in DOC["leaves"]])
def test_arg_provenance_leaves(l):
    assert prov_leaves(l["value"]) == l["expect"]


@pytest.mark.parametrize("r", DOC["read_only"], ids=[r["name"] for r in DOC["read_only"]])
def test_arg_provenance_read_only(r):
    assert is_read_only_action(r["action"]) is r["expect"]


@pytest.mark.parametrize("c", DOC["decisions"], ids=list(DECISIONS))
def test_arg_provenance_decision(c):
    d, e = decide_arg_provenance(c["input"]), c["expect"]
    if e["outcome"] == "deny":
        assert d["code"] == e["code"] and isinstance(d.get("reason"), str) and d["reason"]
        d = dict(d, reason=e["reason"])
    assert d == e


def test_arg_provenance_every_outcome_and_code():
    assert {c["expect"]["outcome"] for c in DOC["decisions"]} == {"pass", "escalate", "deny"}
    codes = {c["expect"].get("code") for c in DOC["decisions"]}
    for k in ("untrusted_control", "untrusted_args", "untrusted_control_and_args", "malformed_bundle", "broken_chain",
              "bad_signature", "unbound_action", "content_mismatch", "malformed_action", "malformed_config"):
        assert k in codes


# ---- the recorder reproduces the reference's receipts byte for byte -----------------------------------------------------

def _seed(label):
    return hashlib.sha256(("atlas-pca-conformance/arg-provenance/" + label).encode("utf-8")).digest()


def _rec(issued_at):
    return create_provenance_recorder(mediator="assistant-harness", kid="k1", secret_key=_seed("key/harness"),
                                      session=b64u(_seed("session/harness")), now=lambda: issued_at)


def test_arg_provenance_recorder_pin_matches_the_vectors():
    assert _rec(0).pin == DOC["pin"]


def test_arg_provenance_recorder_principal_direct_byte_for_byte():
    c = DECISIONS["principal-direct"]["input"]
    want = c["bundle"]
    got = principal_direct_provenance(_rec(want["receipts"][0]["issued_at"]), c["operation"])
    assert json.dumps(got, sort_keys=True) == json.dumps(want, sort_keys=True)


def test_arg_provenance_recorder_principal_only_byte_for_byte():
    c = DECISIONS["principal-only"]["input"]
    want = c["bundle"]
    r = _rec(want["receipts"][0]["issued_at"])
    r.principal(want["contents"]["0"])
    assert r.for_action(c["operation"]) == want
