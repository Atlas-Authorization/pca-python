"""Differential replay of the TypeScript reference (@atlasauth/pca-goal review): the policy card, semantic diff, signed goal approval and
its loader, over an injected stub kernel (the proved compiler is not native)."""
import pytest

from atlas_pca import goal_review as R
from atlas_pca.ed25519 import allow_insecure_signer
from atlas_pca.pca import hash_canonical
from base_oracle import b64d, load_ref, run

COUNT, BY_FN = load_ref("goal-review")


@pytest.fixture(autouse=True, scope="module")
def _signer():
    allow_insecure_signer(True)
    yield
    allow_insecure_signer(False)


def _stub(mode):
    def compile_(g, _ont):
        if mode == "throwcompile":
            raise RuntimeError("boom")
        return {"ok": False, "reasons": ["empty"]} if len(g["grants"]) == 0 else {"ok": True, "policy": {"gids": [x["gid"] for x in g["grants"]], "n": len(g["grants"])}}

    def digest(p):
        if mode == "throwdigest":
            raise RuntimeError("boom")
        return hash_canonical({"d": "stub-policy", "p": p})

    def decide(g, _ont, act, _hist):
        return "allow" if any(x["verb"] == act["verb"] for x in g["grants"]) else "deny"

    def newly(prev, nxt, _ont=None, _limit=None):
        return {"witnesses": [{"verb": x["verb"], "res": "r", "params": {}, "t": 0, "sess": "s", "prin": "p", "org": "o", "agent": "a", "depth": 0}
                              for x in nxt["grants"] if not any(y["gid"] == x["gid"] for y in prev["grants"])], "complete": True}

    return R.ReviewKernel(compile_, digest, lambda p: ["too many"] if p["n"] >= 5 else [], None if mode == "nodecide" else decide, None if mode == "nonewly" else newly)


def _split(opts):
    o = dict(opts or {})
    return o, o.pop("kmode", "full")


def _diff(prev, nxt, opts):
    o, km = _split(opts)
    return R.diff_goals(prev, nxt, _stub(km), o)


def _approve(sub, seed, opts):
    o, km = _split(opts)
    o["kernel"] = _stub(km)
    return R.approve_goal(sub, b64d(seed), o)


def _load(sub, approval, opts):
    o, km = _split(opts)
    o["kernel"] = _stub(km)
    return R.load_approved_goal(sub, approval, o)


FNS = {
    "effectiveLimits": R.effective_limits, "renderPolicyCard": R.render_policy_card, "cardDigest": R.card_digest, "cardToText": R.card_to_text,
    "diffGoals": _diff, "diffToText": R.diff_to_text, "approveGoalSeed": _approve, "loadApprovedGoal": _load,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
