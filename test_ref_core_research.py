"""Replays the TS-reference oracle of the research-tier modules (testdata/ref-core-research-java.json.gz, 6188 cases): data-flow
governance (evaluateDlp, defaultDlpPolicy), the read side of the behavioural immune system (updateBaseline, baselineStd, observe, assess,
validateImmuneState), the console (buildConsole, anomalies, eventFromPCActn, the freeze set), sessions (op scripts, the 32-hop limit
included), the policy simulator and its lints over compiled policies, and disputes derived from signed settlement records.
Every fn and every session op has a handler and the totals are asserted. Keys are sha256("atlas-pca-conformance/research/" + label);
null in an optional position is "not given"; a session op that the reference refuses is {"$err": "Error"}: the native must raise there."""
import hashlib
import os

import pytest

from atlas_pca import console as C
from atlas_pca import dlp as D
from atlas_pca import immune as I
from atlas_pca import policy_sim as PS
from atlas_pca import session as S
from atlas_pca.agent import KeyPair
from atlas_pca.authorize import read_envelope
from atlas_pca.facade import compile_policy, create_agent
from atlas_pca.reputation_evidence import disputes_from_settlements
from base_oracle import HERE, load, run

COUNT, CASES = load("core-research-java", os.path.join(HERE, "testdata", "ref-core-research-java.json.gz"))
TOTALS = {"evaluateDlp": 5436, "defaultDlpPolicy": 8, "updateBaseline": 35, "baselineStd": 5, "assess": 57, "validateImmuneState": 28,
          "observe": 126, "buildConsole": 13, "anomalies": 7, "eventFromPCActn": 12, "freezeAgent": 72, "unfreezeAgent": 72, "isFrozen": 72,
          "session": 5, "simulate": 189, "lintPolicy": 9, "disputesFromSettlements": 42}


def _kp(label):
    return KeyPair(hashlib.sha256(("atlas-pca-conformance/research/" + label).encode("utf-8")).digest(), allow_insecure_signer=True)


def compiled(spec):
    return compile_policy(spec["permissions"], limits=spec.get("limits"), budget_model=spec.get("budgetModel"),
                          risk_policy=spec.get("riskPolicy"), now=spec.get("now"))


def _goal_of(agent):
    env = read_envelope(agent.grant)
    return env["goal_commit"] if env else ""


def _op_agent(ags, sess, name, spec):
    ags[name] = create_agent(_kp(spec["principal"]), spec["goal"], spec["permissions"], holder=_kp(spec["holder"]), goal_salt=spec["goalSalt"],
                             now=spec["now"])
    return ags[name].holder.public


def _op_start(ags, sess, name, agent):
    sess[name] = S.start_session(ags[agent])
    return sess[name]["goalCommit"]


def _op_mk(ags, sess, name, agents, goal):
    members = [ags[n] for n in agents]
    sess[name] = {"root": members[0] if members else None, "members": members,
                  "goalCommit": (_goal_of(members[0]) if members else "") if goal is None else goal}
    return sess[name]["goalCommit"]


def _op_add(ags, sess, name, parent, holder, caveats):
    kw = {} if holder is None else {"holder": _kp(holder)}
    if caveats is not None:
        kw["added_caveats"] = caveats
    r = S.add_member(sess[parent], **kw)
    sess[name] = r["session"]
    return r["member"].holder.public


SESSION_OPS = {
    "agent": _op_agent,
    "start": _op_start,
    "mk": _op_mk,
    "add": _op_add,
    "agents": lambda ags, sess, name: S.session_agents(sess[name]),
    "depth": lambda ags, sess, name: S.session_depth(sess[name]),
    "shares": lambda ags, sess, name: S.shares_goal(sess[name]),
    "goal": lambda ags, sess, name: sess[name]["goalCommit"],
    "console": lambda ags, sess, name, events: S.session_console(sess[name], events),
}


def _session(ops):
    ags, sess, out = {}, {}, []
    for op in ops:
        try:
            out.append(SESSION_OPS[op[0]](ags, sess, *op[1:]))
        except Exception:  # noqa: BLE001 - a refused op, compared against the reference's {"$err"}
            out.append({"$err": "Error"})
    return out


def _disputes(records, guardian, subjects, pin):
    return disputes_from_settlements(records, _kp("guardian").public if guardian == "@g" else guardian, subjects.get,
                                     None if pin is None else pin.get("pqPins"))


HANDLERS = {
    "evaluateDlp": D.evaluate_dlp,
    "defaultDlpPolicy": D.default_dlp_policy,
    "updateBaseline": I.update_baseline,
    "baselineStd": I.baseline_std,
    "assess": I.assess,
    "validateImmuneState": I.validate_immune_state,
    "observe": I.observe,
    "buildConsole": C.build_console,
    "anomalies": lambda events: C.anomalies(C.build_console(events)),
    "eventFromPCActn": C.event_from_pcactn,
    "freezeAgent": C.freeze_agent,
    "unfreezeAgent": C.unfreeze_agent,
    "isFrozen": C.is_frozen,
    "session": _session,
    "simulate": lambda spec, actions, start: PS.simulate(compiled(spec), actions, start=start),
    "lintPolicy": lambda spec: PS.lint_policy(compiled(spec)),
    "disputesFromSettlements": _disputes,
}


def test_every_corpus_fn_has_a_handler_and_the_totals_are_pinned():
    assert COUNT == 6188 and set(CASES) == set(HANDLERS) == set(TOTALS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert {op[0] for c in CASES["session"] for op in c["args"][0]} == set(SESSION_OPS)


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_core_research_replay(fn):
    ran, skipped = run(CASES[fn], HANDLERS[fn])
    assert (ran, skipped) == (TOTALS[fn], 0)
