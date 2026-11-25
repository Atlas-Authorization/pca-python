"""Classifier error folded into the residual-risk estimate: the confusion calibration (exact Clopper-Pearson upper
bounds per entry), the risk on explicit arrays, the label-sound bound, the classifier-aware residual risk of a learner
and the gamma-max JIT gate. Native port of the TypeScript reference (@atlasauth/pca-intent). A "learner" exposes .omega
and .cells() -> [{verb, cell, p, mass, harm, inGrant}]."""
from __future__ import annotations

import functools
import math
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Dict, List, Optional

from .intent_clopper import clopper_pearson_upper
from .intent_omega import encode_cell
from .intent_v2 import compare_utf8
from .pca import hash_canonical


def calibrate_confusion(samples: List[dict], labels: List[str], delta_gamma: float = 0.05) -> Dict[str, Any]:
    """Calibrate a classifier on labelled examples. Labels outside the label set are refused."""
    L = list(dict.fromkeys(labels))
    L.sort(key=functools.cmp_to_key(compare_utf8))
    if len(L) == 0:
        raise ValueError("calibrateConfusion: empty label set")
    if not (0 < delta_gamma < 1):
        raise ValueError("calibrateConfusion: delta must be in (0, 1)")
    ix = {l: i for i, l in enumerate(L)}
    counts = [[0 for _ in L] for _ in L]
    for s in samples:
        t = ix.get(s["truth"])
        p = ix.get(s["predicted"])
        if t is None or p is None:
            raise ValueError("calibrateConfusion: label outside L (%s / %s)" % (s["truth"], s["predicted"]))
        counts[t][p] += 1
    alpha = delta_gamma / (len(L) * len(L))
    gamma = []
    gamma_bar = []
    for row in counts:
        n = sum(row)
        gamma.append([c / n if n else 0 for c in row])
        gamma_bar.append([clopper_pearson_upper(c, n, alpha) for c in row])
    return {"labels": L, "counts": counts, "gamma": gamma, "gammaBar": gamma_bar, "delta_ppm": int(math.floor(delta_gamma * 1000000 + 0.5))}


def confusion_digest(c: dict) -> str:
    return hash_canonical({"d": "atlas-pca/intent-classifier-calibration/v1", "labels": c["labels"], "counts": c["counts"], "delta_ppm": c["delta_ppm"]})


def published_error_rate(c: dict) -> float:
    """Max over true labels of the capped upper bound of any other label."""
    worst = 0
    for t, row in enumerate(c["gammaBar"]):
        s = 0
        for p, g in enumerate(row):
            if p != t:
                s += g
        e = min(1, s)
        if e > worst:
            worst = e
    return worst


def classifier_card_note(id_: str, c: dict) -> str:
    pct = Decimal(published_error_rate(c) * 100).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)  # JS toFixed(1)
    return '"%s" is decided by an attested classifier, not by a person. Published error rate: up to %s%%.' % (id_, pct)


def _gamma_of_set(g: List[List[float]], A: List[int], t: int) -> float:
    s = 0
    for p in A:
        s += g[p][t]
    return min(1, s)


def classifier_risk(m: dict) -> float:
    """R_kappa(G) = sum mu (1 - a) h Gamma(A_G(x) | l), with Gamma(A | l) capped at 1."""
    r = 0.0
    for x, row in enumerate(m["mu"]):
        A = [p for p, b in enumerate(m["inG"][x]) if b]
        for t, mu in enumerate(row):
            r += mu * (1 - m["a"][x][t]) * m["h"][x][t] * _gamma_of_set(m["g"], A, t)
    return r


def label_sound(m: dict) -> bool:
    return all(all((not b) or m["a"][x][p] == 1 for p, b in enumerate(row)) for x, row in enumerate(m["inG"]))


def label_sound_bound(m: dict, h_max: float) -> float:
    s = 0.0
    for x, row in enumerate(m["mu"]):
        A = [p for p, b in enumerate(m["inG"][x]) if b]
        for t, mu in enumerate(row):
            if m["a"][x][t] == 0:
                s += mu * _gamma_of_set(m["g"], A, t)
    return h_max * s


def _groups_of(l: Any, spec: dict):
    vs = next((v for v in l.omega["verbs"] if v["verb"] == spec["verb"]), None)
    if vs is None:
        raise ValueError("classifier: no verb %s in Ω" % spec["verb"])
    k = next((i for i, d in enumerate(vs["dims"]) if d["path"] == spec["path"]), -1)
    dim = vs["dims"][k] if k >= 0 else None
    if k < 0 or dim is None or dim["kind"] != "cat":
        raise ValueError("classifier: %s has no categorical dimension %s" % (spec["verb"], spec["path"]))
    groups: Dict[str, Dict[int, dict]] = {}
    for c in l.cells():
        if c["verb"] != spec["verb"]:
            continue
        key = ",".join(str(x) for i, x in enumerate(c["cell"]) if i != k)
        groups.setdefault(key, {})[c["cell"][k]] = {"cell": c["cell"], "p": c["p"], "mass": c["mass"], "harm": c["harm"], "inGrant": c["inGrant"]}
    return dim, k, groups


def _gbar(spec: dict, dim: dict, pred: int, truth: int) -> float:
    pv = dim["values"][pred]
    tv = dim["values"][truth]
    if pv["kind"] != "exact":
        return 0
    labels = spec["cal"]["labels"]
    pi = labels.index(pv["value"]) if pv["value"] in labels else -1
    if pi < 0:
        return 0
    ti = (labels.index(tv["value"]) if tv["value"] in labels else -1) if tv["kind"] == "exact" else -1
    if ti < 0:
        return 1
    return spec["cal"]["gammaBar"][ti][pi]


def _sum_gbar(spec: dict, dim: dict, A: List[int], t: int) -> float:
    s = 0
    for p in A:
        s += _gbar(spec, dim, p, t)
    return s


def classifier_aware_residual_risk(l: Any, specs: List[dict]) -> Dict[str, Any]:
    """R-hat of the learner's grant with classifier error folded in; other verbs contribute the ordinary sum."""
    per_verb: Dict[str, float] = {}
    spec_verbs = {s["verb"] for s in specs}
    for c in l.cells():
        if c["verb"] in spec_verbs:
            continue
        prev = per_verb.get(c["verb"], 0)
        per_verb[c["verb"]] = prev + c["mass"] * (1 - c["p"]) * c["harm"] if c["inGrant"] else prev
    for spec in specs:
        dim, _k, groups = _groups_of(l, spec)
        r = 0.0
        for g in groups.values():
            A = [i for i, m in g.items() if m["inGrant"]]
            for t, m in g.items():
                r += m["mass"] * (1 - m["p"]) * m["harm"] * min(1, _sum_gbar(spec, dim, A, t))
        per_verb[spec["verb"]] = r
    total = 0
    for x in per_verb.values():
        total += x
    return {"total": total, "perVerb": per_verb}


def classifier_jit_cells(l: Any, spec: dict, gamma_max: float) -> List[dict]:
    """Cells admitted on a classifier label that go to JIT consent: some true label the grant does not admit at the same x
    has an upper-bounded mislabel rate above gamma_max."""
    dim, _k, groups = _groups_of(l, spec)
    vs = next(v for v in l.omega["verbs"] if v["verb"] == spec["verb"])
    out: List[dict] = []
    for g in groups.values():
        A = [i for i, m in g.items() if m["inGrant"]]
        if len(A) == 0:
            continue
        bad = [t for t, m in g.items() if not m["inGrant"] and dim["values"][t]["kind"] == "exact"]
        worst = 0
        for t in bad:
            worst = max(worst, min(1, _sum_gbar(spec, dim, A, t)))
        if worst > gamma_max:
            for p in A:
                cell = g[p]["cell"]
                out.append({"verb": spec["verb"], "cell": cell, "flat": encode_cell(vs, cell)})
    return sorted(out, key=lambda c: c["flat"])
