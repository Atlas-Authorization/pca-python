"""Differential replay of the intent numerics (exact Clopper-Pearson, binomial CDF, Hoeffding, Wilson) against the
TypeScript reference (@atlasauth/pca-intent) vectors."""
from atlas_pca import intent_clopper as C, intent_metrics as M
from base_oracle import load_ref, run

COUNT, CASES = load_ref("intent-stats")


def _bi(x):
    return x["$bigint"] if isinstance(x, dict) and "$bigint" in x else x


def _unbig(x):
    return int(_bi(x)) if isinstance(x, dict) and "$bigint" in x else x


def _big(x):
    return {"$bigint": str(x)}


def _dyadic(x):
    d = C.double_to_dyadic(x)
    return {"num": _big(d["num"]), "exp": d["exp"]}


def _certified(k, n, a):
    c = C.clopper_pearson_certified(k, n, a)
    return {"upper": c["upper"], "upperUnits": _big(c["upperUnits"]), "lowerUnits": _big(c["lowerUnits"])}


MAP = {
    "clopperPearsonUpper": C.clopper_pearson_upper,
    "clopperPearsonCertified": _certified,
    "binomialCdf": C.binomial_cdf,
    "doubleToDyadic": _dyadic,
    "cdfRecNumerator": lambda n, k, a: _big(C.cdf_rec_numerator(n, k, _unbig(a))),
    "cdfExceeds": lambda n, k, a, al: C.cdf_exceeds(n, k, _unbig(a), {"num": _unbig(al["num"]), "exp": al["exp"]}),
    "hoeffdingHalfWidth": M.hoeffding_half_width,
    "wilsonInterval": M.wilson_interval,
}


def test_corpus_is_fully_covered():
    assert set(CASES) == set(MAP)


def _close(got, out, _c):
    """binomialCdf sums libm exp/log terms (the engine's own, up to 1 ulp apart per call): equal to 1e-12 relative, the doc'd diagnostic precision."""
    return isinstance(got, (int, float)) and isinstance(out, (int, float)) and abs(got - out) <= 1e-12 * max(abs(out), 1e-300)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn], compare=_close if fn == "binomialCdf" else None)
