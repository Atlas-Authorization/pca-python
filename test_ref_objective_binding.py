"""Replays the reference's own kill tests of the objective-risk binding (a TypeScript test file, ported case by case): every refusal of
``read_objective_commitment`` with its exact message (array / null / non-string look-alikes included) and every outcome of ``resolve_objective_risk``
(exact mismatch reasons, empty instance defaults, a direct ``objective_risk`` over the same facts, denominations, the calibration wiring and the
fail-closed catch). The expectations are the reference test's, not recomputed natively."""
import pytest

from atlas_pca.agent import DEFAULT_RISK_POLICY, generate_keypair, mint_grant
from atlas_pca.objective_binding import read_objective_commitment, resolve_objective_risk
from atlas_pca.objective_risk import (DEFAULT_NATIVE_CONFIG, InMemoryInverseRegistry, ResourceGraph, calibration_digest, commit_goal, native_hash_embedder,
                                      objective_risk)

P, A = generate_keypair(allow_insecure_signer=True), generate_keypair(allow_insecure_signer=True)
NATIVE = native_hash_embedder()
ACT = {"verb": "revoke_session", "resource": "/acct/1/s", "params": {"device": "laptop"}}
ABSENT = object()

INSTANCE = {
    "registry": {"trusted_verifiers": ["acme"], "entries": [{"verb": "revoke_session", "inverse_kind": "restore_session", "fidelity": "exact",
                                                            "verification": {"verifier_id": "acme", "evidence_digest": "e1"}}]},
    "graph": {"nodes": [{"id": "/acct/1/s", "harm": {"rows": 10}}, {"id": "/acct/1", "harm": {"rows": 100}}, {"id": "/other", "harm": {"rows": 1}}],
              "edges": [{"from": "/acct/1/s", "to": "/acct/1", "kind": "owns"}]},
}


def _reg():
    return InMemoryInverseRegistry(["acme"]).register("revoke_session", {"inverseKind": "restore_session", "fidelity": "exact",
                                                                          "verification": {"verifierId": "acme", "evidenceDigest": "e1"}})


def _graph():
    return (ResourceGraph().add_node({"id": "/acct/1/s", "harm": {"rows": 10}}).add_node({"id": "/acct/1", "harm": {"rows": 100}})
            .add_node({"id": "/other", "harm": {"rows": 1}}).add_edge({"from": "/acct/1/s", "to": "/acct/1", "kind": "owns"}))


EMPTY_REG, EMPTY_GRAPH = InMemoryInverseRegistry([]).digest(), ResourceGraph().digest()


def commitment(**over):
    c = {"v": 1, "embedder": {"scheme": "native", "model_id": NATIVE.model_id, "config": DEFAULT_NATIVE_CONFIG}, "goal": commit_goal(NATIVE, ACT),
         "registry_digest": _reg().digest(), "graph_digest": _graph().digest(), "authorized_kinds": ["restore_session"]}
    for k, v in over.items():
        if v is ABSENT:
            c.pop(k, None)
        else:
            c[k] = v
    return c


def grant(objective=ABSENT):
    env = {"predicates": [{"verb": "revoke_session", "resource": "/acct/*"}], "caveats": [{"type": "expires", "at": 9e12}], "agent_binding": {},
           "risk_policy": DEFAULT_RISK_POLICY}
    if objective is not ABSENT:
        env["objective_risk"] = objective
    return mint_grant(P, A.public, env, "secure my account")["grant"]


def fake(objective):
    return {"caveats": [{"type": "envelope", "goal_commit": "g", "predicates": [], "caveats": [], "agent_binding": {}, "risk_policy": DEFAULT_RISK_POLICY,
                         "objective_risk": objective}]}


def read(o):
    return read_objective_commitment(fake(o))


M = {"shape": "objective_risk: unsupported shape/version",
     "emb": 'objective_risk.embedder must be { scheme: "native", model_id, config }',
     "goal": "objective_risk.goal must be a goal commitment",
     "dig": "objective_risk needs registry_digest and graph_digest",
     "cal": "objective_risk.calibration_digest must be a string",
     "kinds": "objective_risk.authorized_kinds must be string[]",
     "den": "objective_risk.denominations must be an array",
     "onm": 'objective_risk.on_mismatch must be "deny" or "heuristic"'}


def mal(key):
    return {"malformed": M[key]}


def test_read_no_envelope_or_no_field_is_empty():
    assert read_objective_commitment({"caveats": []}) == {}
    assert read_objective_commitment(grant()) == {}


def test_read_accepts_a_well_formed_commitment():
    c = commitment()
    assert read(c) == {"commitment": c}
    for over in ({"on_mismatch": "deny"}, {"on_mismatch": "heuristic"}, {"denominations": []}, {"calibration_digest": "cd"}, {"authorized_kinds": []}):
        x = commitment(**over)
        assert read(x) == {"commitment": x}


def test_read_shape_and_version():
    assert read(None) == mal("shape") and read("x") == mal("shape") and read(commitment(v=2)) == mal("shape")
    assert read(list(commitment().values())) == mal("shape")  # an array look-alike


def test_read_embedder():
    e = commitment()["embedder"]
    for embedder in (None, ABSENT, "native", [dict(e)], dict(e, scheme="byo"), dict(e, model_id=""), dict(e, model_id=7), dict(e, model_id=["m"]),
                     dict(e, config="x"), dict(e, config=None), dict(e, config=[1])):
        assert read(commitment(embedder=embedder)) == mal("emb")


def test_read_goal():
    g = commitment()["goal"]
    for goal in (ABSENT, None, "x", [dict(g)], dict(g, commit=""), dict(g, commit=["c"])):
        assert read(commitment(goal=goal)) == mal("goal")


def test_read_digests():
    assert read(commitment(registry_digest="")) == mal("dig") and read(commitment(graph_digest="")) == mal("dig")
    assert read(commitment(graph_digest=ABSENT)) == mal("dig")
    assert read(commitment(calibration_digest="")) == mal("cal") and read(commitment(calibration_digest=5)) == mal("cal")


def test_read_authorized_kinds():
    for kinds in (ABSENT, "a", ["a", 5], [5]):
        assert read(commitment(authorized_kinds=kinds)) == mal("kinds")


def test_read_denominations_and_on_mismatch():
    assert read(commitment(denominations="x")) == mal("den") and read(commitment(denominations={})) == mal("den")
    for om in ("bogus", "", None):
        assert read(commitment(on_mismatch=om)) == mal("onm")


def _res(g, **kw):
    return resolve_objective_risk(g, ACT, kw.pop("instance", INSTANCE), **kw)


def _mismatch(*reasons):
    return {"mode": "mismatch", "reasons": list(reasons), "onMismatch": "deny"}


def test_resolve_a_malformed_commitment_is_a_deny_mismatch():
    assert _res(fake({"v": 2})) == _mismatch(M["shape"])


def test_resolve_no_instance_config():
    assert _res(grant(commitment(on_mismatch="heuristic")), instance=None) == _mismatch(
        "the grant commits objective-risk facts but the instance holds no objective-risk config")


def test_resolve_re_reads_the_envelope_and_fails_closed_when_it_is_gone():
    real = grant(commitment())
    n = [0]

    class Flaky(dict):
        def get(self, k, d=None):
            if k == "caveats":
                n[0] += 1
                return real["caveats"] if n[0] == 1 else []
            return dict.get(self, k, d)
    assert _res(Flaky(real)) == _mismatch("grant carries no valid envelope")


def test_resolve_embedder_model_mismatch():
    g = grant(commitment(embedder={"scheme": "native", "model_id": "native:other", "config": DEFAULT_NATIVE_CONFIG}))
    assert _res(g) == _mismatch("embedder model_id does not match the committed one")


def test_resolve_an_empty_instance_config_builds_an_empty_registry_and_graph():
    g = grant(commitment(registry_digest=EMPTY_REG, graph_digest=EMPTY_GRAPH, authorized_kinds=[]))
    res = _res(g, instance={})
    assert res["mode"] == "objective"
    assert _res(g, instance={"registry": {}, "graph": {}}) == res


def test_resolve_digest_mismatches_carry_the_objective_risk_reasons_verbatim():
    assert _res(grant(commitment()), instance={}) == _mismatch("registry digest does not match the committed digest",
                                                                  "graph digest does not match the committed digest")


def _expected(direct):
    i = direct["inputs"]
    return {"mode": "objective", "inputs": {"reversibility": i["reversibility"], "blastRadius": i["blastRadius"], "semanticDistance": i["semanticDistance"]},
            "r": direct["r"], "evidenceDigest": direct["evidenceDigest"]}


def test_resolve_matches_a_direct_objective_risk_over_the_same_facts():
    for denominations in ([{"id": "rows", "ceiling": 1, "weight": 1}], None):
        g = grant(commitment(**({"denominations": denominations} if denominations else {})))
        res = _res(g, taint=0.25, age=0.5)
        reg, gr = _reg(), _graph()
        direct = objective_risk(ACT, {"registry": reg, "authorizedKinds": {"restore_session"}, "graph": gr, "embedder": NATIVE, "goal": commitment()["goal"],
                                      "commitments": {"registryDigest": reg.digest(), "graphDigest": gr.digest()}, "denominations": denominations or [],
                                      "weights": DEFAULT_RISK_POLICY["weights"], "taint": 0.25, "age": 0.5})
        assert res == _expected(direct)


def test_resolve_denominations_change_the_blast_radius():
    a = _res(grant(commitment(denominations=[{"id": "rows", "ceiling": 1, "weight": 1}])))
    b = _res(grant(commitment()))
    assert a["mode"] == "objective" and b["mode"] == "objective" and a["inputs"]["blastRadius"] != b["inputs"]["blastRadius"]


def test_resolve_calibration_digest_must_match_and_the_matching_set_calibrates_r():
    scores = [0.0, 0.01, 0.02, 5, 6, 7]
    g = grant(commitment(calibration_digest=calibration_digest(scores)))
    ok = _res(g, instance=dict(INSTANCE, calibration=scores))
    reg, gr = _reg(), _graph()
    direct = objective_risk(ACT, {"registry": reg, "authorizedKinds": {"restore_session"}, "graph": gr, "embedder": NATIVE, "goal": commitment()["goal"],
                                  "commitments": {"registryDigest": reg.digest(), "graphDigest": gr.digest(), "calibrationDigest": calibration_digest(scores)},
                                  "denominations": [], "weights": DEFAULT_RISK_POLICY["weights"], "taint": 1, "age": 1, "calibration": scores})
    assert ok == _expected(direct)
    assert direct["r"] != direct["raw"]
    cal = _mismatch("calibration set does not match the committed digest")
    assert _res(g, instance=dict(INSTANCE, calibration=[0.9])) == cal
    assert _res(g) == cal


def test_resolve_an_instance_calibration_set_is_ignored_when_the_grant_commits_no_digest():
    g = grant(commitment())
    with_cal = _res(g, instance=dict(INSTANCE, calibration=[0.0, 0.01, 5]))
    assert with_cal["mode"] == "objective" and with_cal == _res(g)


def test_resolve_fails_closed_with_the_error_message_and_names_an_empty_error_unknown():
    g = grant(commitment())
    bad_edge = dict(INSTANCE, graph={"nodes": [], "edges": [{"from": "a", "to": "b", "kind": "owns"}]})
    assert _res(g, instance=bad_edge) == _mismatch("objective risk evaluation error (fail closed): edge endpoints must exist")

    class Boom(Exception):
        def __str__(self):
            return ""

    class Entry(dict):
        def get(self, k, d=None):
            if k == "verification":
                raise Boom()
            return dict.get(self, k, d)
    throws = {"registry": {"entries": [Entry({"verb": "v", "inverse_kind": "k", "fidelity": "exact"})]}}
    assert _res(g, instance=throws) == _mismatch("objective risk evaluation error (fail closed): unknown")
