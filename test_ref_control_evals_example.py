"""The example blue control protocol (replay, grant predicates and caveats, DLP, the immune-adapted trust budget) decides every action of
the reference's own recorded episodes and evaluations exactly as the TypeScript stack did: the whole transcript and the aggregated
report compare equal. The recorded decisions the other replay test feeds in are ignored here; only the red, environment and seed are used."""
import pytest

from atlas_pca import control_evals as CE
from atlas_pca import ed25519
from base_oracle import load_ref, run
from test_ref_control_evals import REDS, _env

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the example agent uses throwaway keys
COUNT, CASES = load_ref("control-evals")

_BLUE = []


def blue():
    if not _BLUE:
        _BLUE.append(CE.example_blue())
    return _BLUE[0]


def _episode(spec):
    return CE.run_episode(REDS[spec["red"]], blue(), _env(spec["env"]), spec["seed"])


def _eval(spec):
    reds = [REDS[k] for k in spec["reds"]] if isinstance(spec["reds"], list) else spec["reds"]
    return CE.control_eval(reds, blue(), _env(spec["env"]), spec["episodes"], spec["seed"])


def test_run_episode_matches_the_reference():
    ran, _ = run(CASES["runEpisode"], _episode)
    assert ran == 80


def test_control_eval_matches_the_reference():
    ran, _ = run(CASES["controlEval"], _eval)
    assert ran == 15


def test_example_control_eval():
    r = CE.example_control_eval()
    assert r["episodes"] == 8 * len(CE.EXAMPLE_RED_POLICIES) and r["seed"] == 1
    pol = CE.build_example_agent().policy["riskPolicy"]
    assert r["analyticBound"] == pol["bMax"] / pol["kappa"]
    assert len(r["byStrategy"]) == len(CE.EXAMPLE_RED_POLICIES)  # every strategy of the suite is scored
    assert CE.example_control_eval() == r  # deterministic end to end
    with pytest.raises(ValueError):
        CE.example_control_eval(episodes=0)
