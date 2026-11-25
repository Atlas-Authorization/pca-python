"""Differential oracle: the goal benchmark (atlas_pca.goal_bench) against the vectors generated from the TypeScript reference
(@atlasauth/pca-goal `bench`): the seeded generator, labelled cases with hostile variants, simulated-model fixtures, the four-level
evaluation, the calibrated report and the case-set digest."""
from atlas_pca import goal_bench as B
from base_oracle import load_ref, run

COUNT, CASES = load_ref("goal-bench")


def _items(cases):
    out = []
    for c in cases:
        g = B.truth_goal(c)
        out.append({"goal": g, "ont": B.truth_ont(c, g)})
    return out


def _rng_seq(seed, n):
    r = B.rng(seed)
    return [r() for _ in range(n)]


def _generate(dom, n, seed, every=None, only=None):
    o = {}
    if every is not None:
        o["hostileEvery"] = every
    if only is True:
        o["hostileOnly"] = True
    return B.generate_cases(dom, n, seed, o)


MAP = {
    "rngSeq": _rng_seq,
    "generateCases": _generate,
    "truthGoalOf": lambda c: B.truth_goal(c),
    "simulateOutputOf": lambda c, id_: B.simulate_output(c, next(s for s in B.SIM_SPECS if s["id"] == id_)),
    "recordFixturesOf": lambda cs: B.record_fixtures(cs),
    "caseSetDigest": lambda cs: B.case_set_digest(cs),
    "evalCaseOf": lambda c: B.eval_case(c, B.completions_from(B.record_fixtures([c]))),
    "compileWideningOf": lambda cs: B.compile_widening_count(_items(cs)),
    "summarizeOf": lambda dom, outs, ms, cw=None: B.summarize(dom, outs, ms, cw),
    "runDomainOf": lambda dom, cs: B.run_domain(dom, cs, B.record_fixtures(cs)),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        ran, _ = run(CASES[fn], MAP[fn])
        assert ran == len(CASES[fn])
