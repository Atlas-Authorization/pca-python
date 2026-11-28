"""Differential replay of the empirical control-evaluation harness (seeded PRNG, Wilson bound, CI gate, red policies, modeled
environments, episode runner and aggregation) against the TypeScript reference. The blue control decisions are replayed from the
decisions the reference recorded."""
import pytest

from atlas_pca import control_evals as CE
from base_oracle import load_ref, run

COUNT, CASES = load_ref("control-evals")

REDS = {
    "over-cap": CE.OVER_CAP_RED, "off-verb": CE.OFF_VERB_RED, "slow-burn": CE.SLOW_BURN_RED, "taint-exfil": CE.TAINT_EXFIL_RED,
    "replay": CE.REPLAY_RED, "immune-probe": CE.IMMUNE_PROBE_BURST_RED, "benign": CE.BENIGN_BASELINE_RED, "gap-exploit": CE.gap_exploit_red(),
}


def _env(name):
    if name == "example":
        return CE.EXAMPLE_ENV
    return CE.gap_aware_env() if name == "gap-aware" else CE.gap_aware_env(name[len("gap-aware:"):])


class _Episode:
    def __init__(self, rec):
        self.rec, self.i = rec, -1

    def decide(self, action, at):
        self.i += 1
        d = dict(self.rec["steps"][self.i])
        d.pop("money", None)
        return d

    def money_amount(self, action):
        return self.rec["steps"][self.i]["money"]

    def end_budget(self):
        return self.rec["endBudget"]


class _Stub(CE.Blue):
    def __init__(self, spec, recs):
        self.start_ms, self.step_ms, self.analytic_bound = spec["startMs"], spec["stepMs"], spec.get("analyticBound")
        self._recs = list(recs)

    def new_episode(self):
        return _Episode(self._recs.pop(0))


def _episode(spec):
    return CE.run_episode(REDS[spec["red"]], _Stub(spec, [spec["recorded"]]), _env(spec["env"]), spec["seed"])


def _eval(spec):
    reds = [REDS[k] for k in spec["reds"]] if isinstance(spec["reds"], list) else spec["reds"]
    recs = [r for per_red in spec["recorded"] for r in per_red]
    return CE.control_eval(reds, _Stub(spec, recs), _env(spec["env"]), spec["episodes"], spec["seed"])


def _stream(gen, k):
    return [gen() for _ in range(k)]


def _red_gen(name):
    r = REDS[name]
    return {"name": r.name, "strategy": r.strategy, "actions": r.gen({"env": CE.EXAMPLE_ENV, "rng": CE.mulberry32(1), "now": 0})}


def _gap_custom():
    r = CE.gap_exploit_red("file:x")
    return {"name": r.name, "actions": r.gen({})}


MAP = {
    "mulberry32": lambda seed, k: _stream(CE.mulberry32(seed), k),
    "mixSeed": CE.mix_seed,
    "wilsonLowerBound": CE.wilson_lower_bound,
    "assertControlGate": lambda r, g: CE.assert_control_gate(r, g),
    "redGen": _red_gen,
    "gapExploitCustom": _gap_custom,
    "redLists": lambda: {"builtin": [r.strategy for r in CE.BUILTIN_RED_POLICIES], "example": [r.strategy for r in CE.EXAMPLE_RED_POLICIES]},
    "exampleDlpPolicy": CE.example_dlp_policy,
    "envJudge": lambda env, action, ctx: _env(env).unacceptable_if_allowed(action, ctx),
    "runEpisode": _episode,
    "controlEval": _eval,
}


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
