"""Replays the TS-reference oracle of proof of progress (testdata/ref-progress.json.gz, 723 cases): the potentials and their registry, goal
commitment, state and step digests, trajectory anchoring, signed state attestations and the attested source, the tracker (op scripts with
guards, sources and budgets), step and trajectory verification and signed steps. Every fn has a handler and the totals are asserted; a reference
refusal needs a native exception; {"$err": m} in a result list is one op that refused. The 4 verifyStateAttestation cases the reference accepts
only through the legacy unbound-PQ opt-out are asserted REFUSED (that option is not offered by any native lane); a reference message that
starts with "Cannot read properties" is a JavaScript engine message and any message matches it."""
import base64
import copy
import json
import math
import os

import pytest

from atlas_pca import progress as P
from atlas_pca.ledger_proofs import TransparencyLedger
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("progress", os.path.join(HERE, "testdata", "ref-progress.json.gz"))
ENGINE = "Cannot read properties"
UNBOUND = []


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _kind(k):
    if k == "l1-feature-v1":
        return P.l1_feature_potential
    if k == "dag-remaining-v1":
        return P.dag_remaining_potential
    if k == "dag-weighted-v1":
        return P.dag_weighted_potential
    if k.startswith("const:"):
        return lambda o, s: int(k[6:])
    if k == "v":
        return lambda o, s: s.get("v") if isinstance(s, dict) else None
    if k == "throws":
        def boom(o, s):
            raise RuntimeError("potential boom")
        return boom
    return {"negative": lambda o, s: -1, "frac": lambda o, s: 0.5, "nan": lambda o, s: math.nan, "big": lambda o, s: 2 ** 53}[k]


def _registry(s):
    if s is None:
        return None
    if s["mode"] == "record":
        return {p[0]: (_kind(p[1]) if len(p) < 3 else {"fn": _kind(p[1]), "embedder": p[2]}) for p in s["potentials"]}
    r = P.PotentialRegistry()
    for p in s["potentials"]:
        r.register(p[0], _kind(p[1]), *p[2:3])
    return r


def _guard(g):
    if g is None:
        return None
    if g == "allow":
        return lambda t: True
    if g == "deny":
        return lambda t: False
    if g == "throws":
        def boom(t):
            raise RuntimeError("guard boom")
        return boom
    if g == "truthy":
        return lambda t: "yes"
    if g.startswith("action:"):
        return lambda t: t["action_digest"] != g[7:]
    if g.startswith("seq:"):
        return lambda t: t["seq"] != int(g[4:])
    if g.startswith("after-v:"):
        return lambda t: (t["after"].get("v") if isinstance(t["after"], dict) else None) != int(g[8:])
    raise ValueError(g)


def _att(a):
    if a is None:
        return None
    if a == "allow":
        return lambda s: True
    if a == "deny":
        return lambda s: False
    if a == "throws":
        def boom(s):
            raise RuntimeError("att boom")
        return boom
    if a == "truthy":
        return lambda s: "yes"
    return P.attested_state_verifier(a["attested"])


def _opts(o):
    out = dict(o or {})
    if "registry" in out:
        out["registry"] = _registry(out["registry"])
    if "guard" in out:
        out["guard"] = _guard(out["guard"])
    if "attestation" in out:
        out["attestation"] = _att(out["attestation"])
    return out


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class _Wrap:
    def __init__(self, s):
        self.id = s["id"]
        self._kind = s["kind"]
        self._mem = P.InMemoryStateSource(s.get("initial"), s["id"])
        self.set = self._mem.apply

    def observe(self, req):
        if self._kind == "throws":
            raise RuntimeError("source boom")
        if self._kind == "null":
            return None
        ob = self._mem.observe(req)
        if self._kind == "liar-digest":
            return dict(ob, state_digest="x" * 43)
        if self._kind == "liar-source":
            return dict(ob, source="someone-else")
        return ob


def _source(s):
    if s["kind"] == "attested":
        world = [copy.deepcopy(s.get("initial"))]
        a = P.AttestedStateSource(s["id"], _b64d(s["signerSecret"]), lambda req: world[0], {"alg": s["alg"]} if s.get("alg") else None)
        a.set = lambda n: world.__setitem__(0, copy.deepcopy(n))
        return a
    if s["kind"] == "memory":
        m = P.InMemoryStateSource(s.get("initial"), s["id"])
        m.set = m.apply
        return m
    return _Wrap(s)


def _registry_ops(ops):
    state, out = {}, []
    for op, *a in ops:
        try:
            if op == "new":
                state["r"] = P.PotentialRegistry()
                out.append(None)
            elif op == "defaults":
                state["r"] = P.PotentialRegistry.defaults()
                out.append(None)
            elif op == "default-frozen":
                state["r"] = P.DEFAULT_POTENTIALS
                out.append(None)
            elif op == "from":
                state["r"] = P.PotentialRegistry.from_record({i: (_kind(v) if isinstance(v, str) else {"fn": _kind(v["fn"]), "embedder": v.get("embedder")})
                                                              for i, v in a[0].items()})
                out.append(None)
            elif op == "register":
                state["r"].register(a[0], _kind(a[1]), *a[2:3])
                out.append(None)
            elif op == "get":
                sp = state["r"].get(a[0])
                out.append({"embedder": sp.get("embedder")} if sp else None)
            elif op == "has":
                out.append(state["r"].has(a[0]))
            elif op == "ids":
                out.append(state["r"].ids())
            elif op == "freeze":
                state["r"].freeze()
                out.append(None)
            else:
                raise ValueError("bad op")
        except Exception as e:  # noqa: BLE001 - a refused op, compared against the reference's {"$err": message}
            out.append({"$err": str(e)})
    return out


def _attested_source(src, reqs):
    s = _source(src)
    obs = []
    for r in reqs:
        try:
            obs.append(s.observe(r))
        except Exception as e:  # noqa: BLE001
            obs.append({"$err": str(e)})
    return {"observations": obs, "attestations": getattr(s, "attestations", None)}


def _tracker(goal, commitment, initial, prs, gd, sources, ops):
    srcs = [_source(s) for s in sources]
    t = P.ProgressTracker(goal, commitment if commitment is not None else P.goal_digest(goal), initial, _registry(prs), _guard(gd))
    out = []
    for op, *a in ops:
        try:
            if op == "step":
                out.append(t.step(a[0], a[1]))
            elif op == "stepObserved":
                out.append(t.step_observed(srcs[a[0]], a[1]))
            elif op == "apply":
                srcs[a[0]].set(a[1])
                out.append(None)
            elif op == "steps":
                out.append(t.steps)
            else:
                out.append(getattr(t, {"currentStateDigest": "current_state_digest"}.get(op, op)))
        except Exception as e:  # noqa: BLE001
            out.append({"$err": str(e)})
    return out


def _anchor(steps, salt, prior):
    ledger = TransparencyLedger("p")
    for c in prior:
        ledger.append_commitment(c)
    return P.anchor_trajectory_head(ledger, steps, salt)


HANDLERS = {
    "constants": lambda: {"PROGRESS_VERSION": P.PROGRESS_VERSION, "PROGRESS_SIG_DOMAIN": P.PROGRESS_SIG_DOMAIN,
                          "TRAJECTORY_ANCHOR_DOMAIN": P.TRAJECTORY_ANCHOR_DOMAIN, "STATE_ATTESTATION_DOMAIN": P.STATE_ATTESTATION_DOMAIN},
    "l1FeaturePotential": P.l1_feature_potential, "dagRemainingPotential": P.dag_remaining_potential, "dagWeightedPotential": P.dag_weighted_potential,
    "registryOps": _registry_ops, "goalDigest": P.goal_digest, "commitGoal": P.commit_goal, "verifyGoalCommitment": P.verify_goal_commitment,
    "stateDigest": P.state_digest, "trajectoryHead": P.trajectory_head, "progressStepDigest": P.progress_step_digest,
    "trajectoryAnchorCommit": P.trajectory_anchor_commit, "verifyTrajectoryAnchor": P.verify_trajectory_anchor, "anchorTrajectoryHead": _anchor,
    "verifyStateAttestation": lambda att, key, pin: P.verify_state_attestation(att, key, pin),
    "attestedStateVerifier": lambda opts, step: P.attested_state_verifier(opts)(step),
    "attestedSource": _attested_source, "tracker": _tracker,
    "verifyProgressStep": lambda g, c, s, o: P.verify_progress_step(g, c, s, _opts(o)),
    "verifyTrajectory": lambda g, c, st, o: P.verify_trajectory(g, c, st, _opts(o)),
    "verifySignedProgressStep": lambda g, c, s, o: P.verify_signed_progress_step(g, c, s, _opts(o)),
    "verifySignedTrajectory": lambda g, c, st, o: P.verify_signed_trajectory(g, c, st, _opts(o)),
    "signProgressStep": P.sign_progress_step,
}
TOTALS = {"verifyProgressStep": 147, "verifyTrajectory": 130, "verifyStateAttestation": 55, "verifyGoalCommitment": 53, "tracker": 40,
          "progressStepDigest": 37, "goalDigest": 31, "commitGoal": 31, "verifySignedProgressStep": 26, "dagWeightedPotential": 24,
          "dagRemainingPotential": 21, "l1FeaturePotential": 20, "verifyTrajectoryAnchor": 17, "attestedStateVerifier": 15,
          "verifySignedTrajectory": 15, "stateDigest": 14, "anchorTrajectoryHead": 10, "trajectoryAnchorCommit": 8, "attestedSource": 8,
          "registryOps": 7, "signProgressStep": 7, "trajectoryHead": 6, "constants": 1}


def _same(got, out, case):
    if "allowUnboundPq" in json.dumps(case["args"]) and out is True:
        UNBOUND.append(case["name"])
        if "pq" not in json.dumps(case["args"][0]):
            return got is True  # a classical-only attestation verifies whatever the (irrelevant) opt-out says
        return got is False  # the legacy unbound-PQ opt-out is not offered: the reference's acceptance is a refusal here
    if isinstance(out, dict) and isinstance(got, dict) and isinstance(out.get("$err"), str) and out["$err"].startswith(ENGINE):
        return isinstance(got.get("$err"), str)
    if isinstance(out, dict) and isinstance(got, dict):
        return set(out) == set(got) and all(_same(got[k], out[k], case) for k in out)
    if isinstance(out, list) and isinstance(got, list):
        return len(out) == len(got) and all(_same(g, o, case) for g, o in zip(got, out))
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 723 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 98


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_progress_replay(fn):
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same) == (TOTALS[fn], 0)
    if fn == "verifyStateAttestation":
        assert len(UNBOUND) == 4
