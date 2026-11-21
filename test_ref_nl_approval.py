"""Replays the TS-reference oracle of the approval half of natural-language policy authoring (testdata/ref-nl-approval.json.gz, 206 cases): the catalog digest,
the draft binding and digests, the grounded and linted policy, the draft, the reviewer's approval (v2 and the legacy v1), the loader's every rejection code and
the approved-agent path (only the deterministic envelope members are compared: the grant's goal salt is random). The model is a fixed completion text; a
completion of "THROWS" raises "llm down". Every fn has a handler and the totals are asserted; a reference refusal needs a native exception."""
import hashlib
import math
import os

import pytest

from atlas_pca import nl as N
from atlas_pca.agent import KeyPair
from atlas_pca.authorize import read_envelope
from atlas_pca.catalog import DEFAULT_CATALOG, build_catalog, define_action
from atlas_pca.facade import BUILTIN_ACTIONS
from base_oracle import HERE, load, run

COUNT, CASES = load("nl-approval", os.path.join(HERE, "testdata", "ref-nl-approval.json.gz"))
NUM = {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}


def _num(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return NUM[v["$num"]]
        return {k: _num(x) for k, x in v.items()}
    return [_num(x) for x in v] if isinstance(v, list) else v


def _n(f):
    return lambda *a: f(*[_num(x) for x in a])


def _cat(extras):
    return DEFAULT_CATALOG if extras is None else build_catalog(list(BUILTIN_ACTIONS) + [define_action(e) for e in extras])


def _complete(raw):
    def go(_prompt):
        if raw == "THROWS":
            raise RuntimeError("llm down")
        return raw
    return go


def _kp(label):
    return KeyPair(hashlib.sha256(("atlas-pca-conformance/" + label).encode("utf-8")).digest(), allow_insecure_signer=True)


def _policy_from_nl(instruction, raw, extras, model):
    return N.policy_from_nl(instruction, _complete(raw), None if extras is None else _cat(extras))


def _draft_policy(instruction, raw, extras, model):
    return N.draft_policy_from_nl(instruction, _complete(raw), None if extras is None else _cat(extras), model)


def _load(draft, approval, opts):
    o = {k: v for k, v in opts.items() if k != "extras"}
    if opts.get("extras"):
        o["catalog"] = _cat(opts["extras"])
    return N.load_approved_policy(draft, approval, o)


def _agent(a):
    opts = a["opts"]
    req = {k: v for k, v in opts.items() if k != "extras"}
    if opts.get("extras"):
        req["catalog"] = _cat(opts["extras"])
    req.update(draft=a["draft"], approval=a["approval"], principal=_kp(a["principalSeed"]), goal=a["goal"])
    if a.get("holderSeed"):
        req["holder"] = _kp(a["holderSeed"])
    if a.get("aud") is not None:
        req["aud"] = a["aud"]
    out = N.agent_from_approved_nl(req)
    env = read_envelope(out["agent"].grant)
    return {"reviewer": out["reviewer"], "legacy_unbound_instruction": out["legacy_unbound_instruction"],
            "envelope": {k: env.get(k) for k in ("predicates", "caveats", "risk_policy", "agent_binding") if k in env}}


HANDLERS = {
    "constants": lambda: {"NL_APPROVAL_DOMAIN": N.NL_APPROVAL_DOMAIN, "NL_APPROVAL_DOMAIN_V2": N.NL_APPROVAL_DOMAIN_V2,
                          "MAX_NL_OUTPUT_BYTES": N.MAX_NL_OUTPUT_BYTES, "MAX_NL_APPROVAL_TTL_MS": N.MAX_NL_APPROVAL_TTL_MS},
    "catalogDigest": lambda extras: N.catalog_digest(_cat(extras)),
    "draftBinding": lambda i, extras, model: N.draft_binding(i, _cat(extras), model),
    "draftDigestV2": N.draft_digest_v2,
    "draftDigest": N.draft_digest,
    "policyFromNL": _policy_from_nl,
    "draftPolicyFromNL": _draft_policy,
    "approveDraft": lambda d, s, op: N.approve_draft(d, s, op or {}),
    "approveDraftLegacy": lambda d, s, op: N.approve_draft_legacy_v1(d, s, op or {}),
    "loadApproved": _load,
    "agentFromApproved": _agent,
}
TOTALS = {"constants": 1, "catalogDigest": 3, "draftBinding": 6, "draftDigest": 7, "draftDigestV2": 10, "policyFromNL": 40, "draftPolicyFromNL": 42,
          "approveDraft": 24, "approveDraftLegacy": 5, "loadApproved": 58, "agentFromApproved": 10}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 206 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_nl_approval_replay(fn):
    assert run(CASES[fn], _n(HANDLERS[fn])) == (TOTALS[fn], 0)
