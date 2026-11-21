"""Measuring a grant against an intent: Monte Carlo and exact risk / burden / fidelity, the Hoeffding half-width and
the Wilson interval. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

import math
from typing import Any, Callable, Dict, Optional

from .intent_omega import (DEFAULT_HARM, cell_rep, cell_stats, decode_cell, harm_of, js_div, js_log, js_max, js_min, js_sqrt,
                           rng, sample_outcome, verb_cell_count)
from .intent_policy import admitter


def acceptability_of(policy: Any) -> Callable[[dict, dict], float]:
    a = admitter(policy)
    return lambda vs, o: 1 if a.admits(vs, o) else 0


def hoeffding_half_width(range_: float, samples: float, delta_prime: float = 0.05) -> float:
    return range_ * js_sqrt(js_div(js_log(js_div(2, delta_prime)), 2 * samples))


def measure_grant(omega: dict, grant: Any, acceptability: Callable[[dict, dict], float], opts: Optional[dict] = None) -> Dict[str, Any]:
    opts = opts or {}
    M = opts.get("samples", 20000)
    harm = opts.get("harm") or DEFAULT_HARM
    rand = rng(opts.get("seed", 1))
    g = admitter(grant)
    R = B = Rm = 0.0
    h_max = 0.0
    for _ in range(M):
        vs, o = sample_outcome(omega, rand, harm)
        a = acceptability(vs, o)
        h = harm_of(vs, o, harm)
        h_max = max(h_max, h)
        if g.admits(vs, o):
            R += (1 - a) * h
        else:
            B += a
        Rm += (1 - a) * h
    R = js_div(R, M)
    B = js_div(B, M)
    Rm = js_div(Rm, M)
    hm = opts.get("hMax")
    return {"risk": R, "burden": B, "riskMax": Rm, "fidelity": 1 - R / Rm if Rm > 0 else 1, "samples": M,
            "riskHalfWidth": hoeffding_half_width(hm if hm is not None else h_max, M)}


def estimate_residual_risk_mc(learner: Any, opts: Optional[dict] = None) -> float:
    """The Monte Carlo form of the learner's residual-risk estimate, for the cross-check."""
    opts = opts or {}
    M = opts.get("samples", 20000)
    rand = rng(opts.get("seed", 7))
    g = admitter(learner.synthesize())
    R = 0.0
    for _ in range(M):
        vs, o = sample_outcome(learner.omega, rand, learner.harm)
        if g.admits(vs, o):
            R += (1 - learner.acceptance(o)) * harm_of(vs, o, learner.harm)
    return js_div(R, M)


def measure_grant_exact(omega: dict, grant: Any, acceptability: Callable[[dict, dict], float], harm: Any = DEFAULT_HARM) -> Dict[str, Any]:
    """Exact R, B, R_max, F by summing over the cells (no sampling error)."""
    g = admitter(grant)
    R = B = Rm = Eh = 0.0
    for vs in omega["verbs"]:
        for c in range(verb_cell_count(vs)):
            idx = decode_cell(vs, c)
            o = cell_rep(vs, idx)
            st = cell_stats(vs, idx, harm)
            mass, h = st["mass"], st["harm"]
            a = acceptability(vs, o)
            Eh += mass * h
            Rm += mass * (1 - a) * h
            if g.admits(vs, o):
                R += mass * (1 - a) * h
            else:
                B += mass * a
    return {"risk": R, "burden": B, "riskMax": Rm, "fidelity": 1 - R / Rm if Rm > 0 else 1, "meanHarm": Eh}


def wilson_interval(k: float, n: float, z: float = 1.959963984540054) -> Dict[str, float]:
    """Wilson score interval for a binomial proportion k/n (default 95%)."""
    if not (n > 0):
        return {"p": math.nan, "lo": 0, "hi": 1}
    p = k / n
    z2 = z * z
    den = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / den
    half = (z * js_sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / den
    return {"p": p, "lo": js_max(0, centre - half), "hi": js_min(1, centre + half)}
