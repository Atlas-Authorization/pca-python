"""Replays the TS-reference oracle of the blue control protocol (testdata or test-data ref-control-blue.json.gz, 362 cases): the example agent (its compiled
policy and the review of a battery of actions), the example blue protocol over three agents, one episode through the stack for eight blue configurations (the
data-flow policy off, the agent's own thresholds, other clocks, immune and adaptation settings), the example agent, two environments and every red policy,
and the example evaluation report. Numbers compare to a relative 1e-12. The keys of the agents are fresh in both implementations: nothing recorded
depends on key material."""
import math
import os

import pytest

from atlas_pca import control_evals as CE
from atlas_pca import ed25519
from atlas_pca.agent import generate_keypair
from atlas_pca.approvals import review_action
from atlas_pca.facade import create_agent
from base_oracle import HERE, load, norm, run

ed25519.allow_insecure_signer()  # the example agents use throwaway keys that may sign without the `cryptography` package
_PATH = os.path.join(HERE, "test-data", "ref-control-blue.json.gz")
COUNT, CASES = load("control-blue", _PATH if os.path.exists(_PATH) else os.path.join(HERE, "testdata", "ref-control-blue.json.gz"))
TOTALS = {"buildExampleAgent": 1, "exampleBlue": 3, "blueEpisode": 352, "exampleEval": 6}
PERMS = {"stripe": ["refund"], "gmail": ["send", "draft"], "files": ["read", "write"], "github": ["read"]}
GOAL = "handle refunds and customer email for October"


def _agent(name):
    if name == "example":
        return CE.build_example_agent()
    limits = {"refund": "$50/day"} if name == "cap50" else None
    return create_agent(generate_keypair(allow_insecure_signer=True), GOAL, PERMS, limits=limits, aud="ins_example", now=0)


def _blue(b):
    a = _agent(b["agent"])
    base = a.policy["riskPolicy"] if b["theta"] == "agent" else dict(a.policy["riskPolicy"], theta1=1, theta2=1)
    blue = CE._ExampleBlue(a, base, CE.example_dlp_policy() if b["dlp"] else None, b.get("immune"), b.get("adapt"))
    if b.get("stepMs") is not None:
        blue.step_ms = b["stepMs"]
    if b.get("startMs") is not None:
        blue.start_ms = b["startMs"]
    return blue


def _env(name):
    return CE.EXAMPLE_ENV if name == "example" else CE.gap_aware_env()


_REDS = {"over-cap": CE.OVER_CAP_RED, "off-verb": CE.OFF_VERB_RED, "slow-burn": CE.SLOW_BURN_RED, "taint-exfil": CE.TAINT_EXFIL_RED, "replay": CE.REPLAY_RED,
         "immune-probe": CE.IMMUNE_PROBE_BURST_RED, "benign": CE.BENIGN_BASELINE_RED}


def _episode(spec, actions=None):
    red = CE.RedPolicy("custom", "custom", lambda ctx: actions) if actions is not None else (CE.gap_exploit_red() if spec["red"] == "gap-exploit" else _REDS[spec["red"]])
    return CE.run_episode(red, _blue(spec["blue"]), _env(spec["env"]), spec["seed"])


def _build_example_agent():
    a = CE.build_example_agent()
    pol = a.policy
    battery = CASES["buildExampleAgent"][0]["out"]["reviews"]  # the battery is the oracle's own; its inputs are recorded in the case
    reviews = []
    for b in battery:
        r = review_action(a, b["verb"], b["resource"], b.get("params"), now=b["now"], insecure_unbound_approval=True)
        rev = {"kind": r["kind"]}
        if r.get("reason") is not None:
            rev["reason"] = r["reason"]
        entry = {k: b[k] for k in ("verb", "resource", "params", "now") if k in b}
        reviews.append(dict(entry, review=rev))
    acts = []
    for s in pol["actions"]:
        e = {k: s[k] for k in ("connector", "action", "verb", "reversibility", "blastRadius") if k in s}
        for k in ("amountField", "resource"):
            if s.get(k) is not None:
                e[k] = s[k]
        acts.append(e)
    return {"policy": {"predicates": pol["predicates"], "caveats": pol["caveats"], "riskPolicy": pol["riskPolicy"], "budgetModel": pol["budgetModel"],
                       "approximations": pol["approximations"], "inputLimits": pol["inputLimits"], "actions": acts}, "reviews": reviews}


def _example_blue(name):
    b = CE.example_blue(_agent(name))
    return {"name": b.name, "basePolicy": b.base_policy, "dlp": b.dlp, "startMs": b.start_ms, "stepMs": b.step_ms}


HANDLERS = {"buildExampleAgent": _build_example_agent, "exampleBlue": _example_blue, "blueEpisode": _episode,
            "exampleEval": lambda spec: CE.example_control_eval(spec["episodes"], spec["seed"])}


def _eq(g, o):
    g = norm(g)
    if isinstance(o, dict):
        return isinstance(g, dict) and set(g) == set(o) and all(_eq(g[k], o[k]) for k in o)
    if isinstance(o, list):
        return isinstance(g, (list, tuple)) and len(g) == len(o) and all(_eq(x, y) for x, y in zip(g, o))
    if isinstance(o, (int, float)) and not isinstance(o, bool):
        return isinstance(g, (int, float)) and not isinstance(g, bool) and math.isclose(g, o, rel_tol=1e-12, abs_tol=1e-12)
    return g == o


def _same(got, out, _case):
    return _eq(got, out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 362 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_control_blue_replay(fn):
    assert run(CASES[fn], HANDLERS[fn], compare=_same) == (TOTALS[fn], 0)
