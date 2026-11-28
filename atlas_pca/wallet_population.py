"""Opt-in, privacy-preserving population priors for the wallet (PCA Intent Layer v2, V16, T23): one vote per principal, cell and
period; a central (epsilon, delta)-DP Gaussian release; local-DP randomized response; the mixture prior for the learner and the mass
it admits beyond the base prior. Native port of the TypeScript reference (@atlasauth/pca-wallet, population.ts). Votes, releases and
priors are plain dicts with the reference's member names; the randomness source is an injected callable."""
from __future__ import annotations

from ._fin import fin
import math
import os
from typing import Any, Callable, Dict, List, Optional, Set

from .intent_omega import js_div, js_log
from .pca import hash_canonical
from .wallet import coords_of_cell, is_b64u32
from .wallet_omega import decode_cell, verb_cell_count

POPULATION_VOTE_DOMAIN = "atlas-pca/intent-population-cell/v1"
BETA_MAX = 0.9


def _js_round(x: float) -> int:
    f = math.floor(x)
    return f + 1 if x - f >= 0.5 else f


def _is_integer(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x) and x == math.floor(x)


def population_cell_key(schema_digest: str, vs: dict, idx: List[int]) -> str:
    """The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb."""
    return hash_canonical({"d": POPULATION_VOTE_DOMAIN, "s": schema_digest, "v": vs["verb"], "c": coords_of_cell(vs, idx)})


def crypto_rand() -> float:
    """Uniform (0, 1) from 53 random bits of the OS CSPRNG."""
    b = os.urandom(8)
    hi = int.from_bytes(b[:4], "big") >> 5
    lo = int.from_bytes(b[4:], "big") >> 6
    return (hi * 67108864 + lo + 0.5) / 9007199254740992


def gaussian(rand: Callable[[], float]) -> float:
    """A standard normal draw (Box-Muller) from a uniform source."""
    u = rand()
    while u <= 0:
        u = rand()
    v = rand()
    return math.sqrt(-2 * math.log(u)) * math.cos(2 * math.pi * v)


def gaussian_sigma(epsilon: float, delta: float, l2_sensitivity: float) -> float:
    """Sigma of the Gaussian mechanism for L2 sensitivity (requires epsilon in (0, 1), delta in (0, 1))."""
    if not (epsilon > 0 and epsilon < 1):
        raise ValueError("gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)")
    if not (delta > 0 and delta < 1):
        raise ValueError("gaussianSigma: delta must be in (0, 1)")
    if not (l2_sensitivity > 0):
        raise ValueError("gaussianSigma: sensitivity must be > 0")
    return js_div(l2_sensitivity * math.sqrt(2 * math.log(1.25 / delta)), epsilon)


class PopulationAggregator:
    def __init__(self, schema_digest: str, period: Any, opts: Optional[dict] = None):
        opts = opts if opts is not None else {}
        if not is_b64u32(schema_digest):
            raise ValueError("PopulationAggregator: schemaDigest must be a canonical b64u digest")
        self.schema_digest = schema_digest
        self.period = period
        mc = opts.get("maxCellsPerPrincipal")
        self._max_cells = 32 if mc is None else mc
        if not (_is_integer(self._max_cells) and self._max_cells > 0):
            raise ValueError("PopulationAggregator: maxCellsPerPrincipal must be a positive integer")
        rand = opts.get("rand")
        self._rand = crypto_rand if rand is None else rand
        self._votes: Dict[str, Dict[str, Any]] = {}
        self._per_principal: Dict[str, Set[str]] = {}

    def contribute(self, v: dict) -> Dict[str, Any]:
        """Accept a vote; refuses a second vote on a cell, a vote past the per-principal cell cap, or a foreign schema/period."""
        if v.get("schemaDigest") != self.schema_digest:
            return {"ok": False, "reason": "vote for another schema"}
        if v.get("period") != self.period or isinstance(v.get("period"), bool):
            return {"ok": False, "reason": "vote for another period"}
        y = v.get("y")
        if not (isinstance(y, (int, float)) and not isinstance(y, bool) and (y == 0 or y == 1)):
            return {"ok": False, "reason": "y must be 0 or 1"}
        principal = v.get("principal")
        if not isinstance(principal, str) or len(principal) == 0:
            return {"ok": False, "reason": "an accountable principal is required"}
        key = v.get("cellKey")
        mine = self._per_principal.get(principal, set())
        if key in mine:
            return {"ok": False, "reason": "one vote per principal per cell per period (sensitivity 1)"}
        if not (len(mine) < self._max_cells):
            return {"ok": False, "reason": "at most %s cells per principal per period" % self._max_cells}
        mine.add(key)
        self._per_principal[principal] = mine
        c = self._votes.get(key, {"yes": 0, "total": 0})
        self._votes[key] = {"yes": c["yes"] + y, "total": c["total"] + 1}
        return {"ok": True}

    def release(self, opts: dict) -> Dict[str, Any]:
        """The (epsilon, delta)-DP release. Cells whose noisy count is below `minCount` are suppressed."""
        sensitivity = math.sqrt(2 * self._max_cells)
        sigma = gaussian_sigma(opts["epsilon"], opts["delta"], sensitivity)
        q_min = 0.02 if opts.get("qMin") is None else opts["qMin"]
        if not (q_min > 0 and q_min < 0.5):
            raise ValueError("release: qMin must be in (0, 0.5)")
        min_count = 3 * sigma if opts.get("minCount") is None else opts["minCount"]
        cells: Dict[str, Any] = {}
        for key in sorted(self._votes, key=lambda k: k.encode("utf-16-be", "surrogatepass")):
            c = self._votes[key]
            yes = c["yes"] + sigma * gaussian(self._rand)
            total = c["total"] + sigma * gaussian(self._rand)
            if not (total >= min_count):
                continue
            cells[key] = {"q": min(1 - q_min, max(q_min, js_div(yes, total))), "n": _js_round(total)}
        return {"v": 1, "kind": "pca-intent-population-prior", "schema": self.schema_digest, "period": self.period, "epsilon": opts["epsilon"],
                "delta": opts["delta"], "sigma": sigma, "sensitivity": sensitivity, "cells": cells}


# ---- local DP ---------------------------------------------------------------------------------------------------------------

def rr_keep_probability(epsilon: float) -> float:
    if not (epsilon > 0 and fin(epsilon)):
        raise ValueError("randomized response: epsilon must be > 0")
    return math.exp(epsilon) / (1 + math.exp(epsilon))


def randomized_response(y: int, epsilon: float, rand: Callable[[], float] = crypto_rand) -> int:
    """epsilon-LDP randomized response: report y with probability e^eps/(1+e^eps), else 1 - y."""
    return y if rand() < rr_keep_probability(epsilon) else 1 - y


def debias_randomized_response(yes_reports: Any, total: Any, epsilon: float) -> float:
    """Unbiased estimate of the true yes-rate from randomized reports: (ybar - (1 - p)) / (2p - 1)."""
    if not (_is_integer(yes_reports) and _is_integer(total) and total > 0 and yes_reports >= 0 and yes_reports <= total):
        raise ValueError("debias: bad counts")
    p = rr_keep_probability(epsilon)
    return js_div(js_div(yes_reports, total) - (1 - p), 2 * p - 1)


# ---- the mixture prior --------------------------------------------------------------------------------------------------------

def population_prior(release: dict, beta: float) -> Dict[str, Any]:
    """The learner's priorMix for a release: weight(theta) = prod_c q_c^{1[c in theta]} (1 - q_c)^{1[c not in theta]} over the released
    cells of the verb (unreleased cells contribute the constant 1/2 and drop out), mixed with weight beta <= BETA_MAX < 1."""
    if not (beta >= 0 and beta <= BETA_MAX):
        raise ValueError("populationPrior: beta must be in [0, %s] (full support needs beta < 1)" % BETA_MAX)
    per_verb: Dict[int, Any] = {}

    def tables(vs: dict) -> Dict[str, list]:
        hit = per_verb.get(id(vs))
        if hit is not None and hit[0] is vs:
            return hit[1]
        t: Dict[str, list] = {"cells": [], "lq": [], "lnq": []}
        for c in range(verb_cell_count(vs)):
            r = release["cells"].get(population_cell_key(release["schema"], vs, decode_cell(vs, c)))
            if not r:
                continue
            t["cells"].append(c)
            t["lq"].append(js_log(r["q"]))
            t["lnq"].append(js_log(1 - r["q"]))
        per_verb[id(vs)] = (vs, t)
        return t

    def weight(vs: dict, contains: Callable[[int], bool]) -> float:
        t = tables(vs)
        lw = 0.0
        for i in range(len(t["cells"])):
            lw += t["lq"][i] if contains(t["cells"][i]) else t["lnq"][i]
        return math.exp(lw)

    return {"beta": beta, "weight": weight}


def prior_admitted_ppm(omega: dict, base: dict, observations: List[dict], mix: dict) -> int:
    """Mass (ppm) of cells admitted only because of the population prior: in the grant with the prior, not without it, after the
    same observations. Zero at tau = 1 under noise-free answers (T23)."""
    from .intent_learner import IntentLearner
    rest = {k: v for k, v in base.items() if k != "priorMix"}
    without = IntentLearner.replay(omega, rest, observations)
    with_pop = IntentLearner.replay(omega, {**rest, "priorMix": mix}, observations)
    a = without.cells()
    b = with_pop.cells()
    mass = 0.0
    for i, c in enumerate(b):
        if c["inGrant"] and not a[i]["inGrant"]:
            mass += c["mass"]
    return _js_round(mass * 1000000)
