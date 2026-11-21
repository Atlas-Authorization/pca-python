"""Elicitation as learning: the exact Bayesian posterior over a per-verb hypothesis class (boxes, unions of boxes, decision
lists), the conservative grant it implies, the next question, the audit round and the synthesis of the grant as predicates.
Native port of the TypeScript reference (@atlasauth/pca-intent, learner.ts). Omegas, verb spaces, options, observations and
questions are plain dicts with the reference's field names; the posterior arithmetic keeps the reference's operation order
(Python floats are IEEE doubles)."""
from __future__ import annotations

from ._fin import fin
import itertools
import math
from typing import Any, Callable, Dict, List, Optional, Tuple

from .intent_omega import DEFAULT_HARM, cell_of, cell_rep, cell_stats, decode_cell, js_max, js_min, num_cells, verb_cell_count
from .intent_policy import admitter
from .intent_region import region_cells

_ORDER = ["reversible", "rate_limited", "irreversible"]


def _is_integer(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x) and x == math.floor(x)


def _or1(x: float) -> float:
    """JS `x || 1`: 0 and NaN are falsy there."""
    return x if (x == x and x != 0) else 1


def _opt(o: Any, k: str, default: Any = None) -> Any:
    """JS `o.k ?? default`."""
    v = o.get(k) if isinstance(o, dict) else None
    return default if v is None else v


def hypothesis_class_name(h: dict) -> str:
    """The canonical name of a hypothesis class (stored in the Intent Map)."""
    k = h.get("kind")
    if k == "box":
        return "per-verb-box/v1"
    if k == "union":
        return "per-verb-union/v1"
    return "per-verb-decision-list/v1" if _opt(h, "conditions", "box") == "atomic" else "per-verb-decision-list/v2"


def _bin_ent(p: float) -> float:
    if p <= 0 or p >= 1:
        return 0
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def _range_choices(n: int) -> List[Tuple[int, int]]:
    return [(i, j) for i in range(n) for j in range(i, n)]


def _build_box_tables(vs: dict, n_cells_d: List[int]) -> Tuple[List[bytearray], List[int]]:
    contains: List[bytearray] = []
    n_choice: List[int] = []
    for k, d in enumerate(vs["dims"]):
        n = n_cells_d[k]
        if d["kind"] == "num":
            ch = _range_choices(n)
            t = bytearray(len(ch) * n)
            for c, (i, j) in enumerate(ch):
                for x in range(i, j + 1):
                    t[c * n + x] = 1
            contains.append(t)
            n_choice.append(len(ch))
        else:
            if n > 20:
                raise ValueError("pca-intent: categorical dimension %s has %d values (max 20 for exact enumeration)" % (d["path"], n))
            m = (1 << n) - 1
            t = bytearray(m * n)
            for mask in range(1, m + 1):
                for x in range(n):
                    if mask & (1 << x):
                        t[(mask - 1) * n + x] = 1
            contains.append(t)
            n_choice.append(m)
    return contains, n_choice


def _box_masks(vs: dict, n_cells: int, cell_idx: List[int], n_cells_d: List[int], contains: List[bytearray], n_choice: List[int], cap: int) -> List[bytearray]:
    D = len(vs["dims"])
    boxes = 1
    for c in n_choice:
        boxes *= c
    if boxes > cap:
        raise ValueError("pca-intent: %d boxes for %s exceed the enumeration cap; coarsen the cuts" % (boxes, vs["verb"]))
    out: List[bytearray] = []
    cur = [0] * D
    for _b in range(boxes):
        mask = bytearray(n_cells)
        for c in range(n_cells):
            inside = True
            d = 0
            while d < D and inside:
                if contains[d][cur[d] * n_cells_d[d] + cell_idx[c * D + d]] == 0:
                    inside = False
                d += 1
            if inside:
                mask[c] = 1
        out.append(mask)
        for d in range(D - 1, -1, -1):
            cur[d] += 1
            if cur[d] < n_choice[d]:
                break
            cur[d] = 0
    return out


def _enumerate_unions(boxes: List[bytearray], k: int, cap: int, verb: str) -> Tuple[List[bytearray], List[int]]:
    seen: Dict[bytes, int] = {}
    sets: List[bytearray] = []
    complexity: List[int] = []
    frontier: List[bytearray] = []
    for b in boxes:
        key = bytes(b)
        if key in seen:
            continue
        seen[key] = len(sets)
        sets.append(b)
        complexity.append(1)
        frontier.append(b)
    work = 0
    for level in range(2, k + 1):
        nxt: List[bytearray] = []
        for s in frontier:
            for b in boxes:
                work += 1
                if work > cap:
                    raise ValueError("pca-intent: the union-of-%s-boxes class for %s exceeds the enumeration cap; coarsen the cuts or lower k" % (k, verb))
                u = bytearray(x | y for x, y in zip(s, b))
                key = bytes(u)
                if key in seen:
                    continue
                seen[key] = len(sets)
                sets.append(u)
                complexity.append(level)
                nxt.append(u)
        frontier = nxt
    return sets, complexity


def _atomic_tests(vs: dict, n_cells: int, cell_idx: List[int], n_cells_d: List[int]) -> List[bytearray]:
    D = len(vs["dims"])
    tests: List[bytearray] = []

    def add(k: int, pred: Callable[[int], bool]) -> None:
        m = bytearray(n_cells)
        any_ = False
        all_ = True
        for c in range(n_cells):
            if pred(cell_idx[c * D + k]):
                m[c] = 1
                any_ = True
            else:
                all_ = False
        if any_ and not all_:
            tests.append(m)

    for k, d in enumerate(vs["dims"]):
        n = n_cells_d[k]
        if d["kind"] == "num":
            for i in range(n - 1):
                add(k, lambda x, i=i: x <= i)
            for i in range(1, n):
                add(k, lambda x, i=i: x >= i)
            if n > 2:
                for i in range(1, n - 1):
                    add(k, lambda x, i=i: x == i)
        else:
            for i in range(n):
                add(k, lambda x, i=i: x == i)
    return _dedup_masks(tests)


def _dedup_masks(masks: List[bytearray]) -> List[bytearray]:
    seen = set()
    out = []
    for t in masks:
        key = bytes(t)
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def _enumerate_decision_lists(tests: List[bytearray], n_cells: int, L: int, cap: int, verb: str) -> Tuple[List[bytearray], List[int]]:
    seen: Dict[bytes, int] = {}
    sets: List[bytearray] = []
    complexity: List[int] = []

    def emit(acc: bytearray, decided: bytearray, rules: int) -> None:
        for dflt in (0, 1):
            s = bytearray(n_cells)
            any_ = False
            for c in range(n_cells):
                s[c] = acc[c] if decided[c] else dflt
                if s[c]:
                    any_ = True
            if not any_:
                continue
            key = bytes(s)
            if key in seen:
                continue
            seen[key] = len(sets)
            sets.append(s)
            complexity.append(max(1, rules))

    frontier: List[Tuple[bytearray, bytearray]] = [(bytearray(n_cells), bytearray(n_cells))]  # (decided, acc)
    emit(frontier[0][1], frontier[0][0], 0)
    work = 0
    for depth in range(1, L + 1):
        states: Dict[Tuple[bytes, bytes], Tuple[bytearray, bytearray]] = {}
        for st_decided, st_acc in frontier:
            for t in tests:
                for label in (0, 1):
                    work += 1
                    if work > cap:
                        raise ValueError("pca-intent: the decision-list class (≤ %d rules) for %s exceeds the enumeration cap" % (L, verb))
                    decided = bytearray(n_cells)
                    acc = bytearray(n_cells)
                    fresh = False
                    for c in range(n_cells):
                        if st_decided[c]:
                            decided[c] = 1
                            acc[c] = st_acc[c]
                        elif t[c]:
                            decided[c] = 1
                            acc[c] = label
                            fresh = True
                    if not fresh:
                        continue
                    key = (bytes(decided), bytes(acc))
                    if key in states:
                        continue
                    states[key] = (decided, acc)
        frontier = list(states.values())
        for decided, acc in frontier:
            emit(acc, decided, depth)
    return sets, complexity


class _VerbModel:
    __slots__ = ("vs", "n_choice", "contains", "n_cells_d", "nh", "choice", "member", "complexity", "prior", "w", "err", "n_cells",
                 "cell_idx", "mass", "harm", "p", "veto", "seen", "dirty")


def _build_verb_model(vs: dict, opts: dict, harm: Any) -> _VerbModel:
    D = len(vs["dims"])
    n_cells_d = [len(num_cells(d)) if d["kind"] == "num" else len(d["values"]) for d in vs["dims"]]
    contains, n_choice = _build_box_tables(vs, n_cells_d)
    n_cells = verb_cell_count(vs)
    cell_idx = [0] * (n_cells * D)
    mass = [0.0] * n_cells
    hm = [0.0] * n_cells
    for c in range(n_cells):
        idx = decode_cell(vs, c)
        for d in range(D):
            cell_idx[c * D + d] = idx[d]
        s = cell_stats(vs, idx, harm)
        mass[c] = s["mass"]
        hm[c] = s["harm"]
    hc = _opt(opts, "hypothesisClass", {"kind": "box"})
    choice: List[int] = [0]
    member: Optional[List[bytearray]] = None
    complexity: Optional[List[int]] = None
    if hc["kind"] == "box":
        boxes = 1
        for c in n_choice:
            boxes *= c
        if boxes + 1 > opts["maxHypotheses"]:
            raise ValueError("pca-intent: |Θ_%s| = %d exceeds maxHypotheses %s; coarsen the cuts" % (vs["verb"], boxes + 1, opts["maxHypotheses"]))
        nh = boxes + 1
        choice = [0] * max(1, boxes * D)
        cur = [0] * D
        for h in range(boxes):
            for d in range(D):
                choice[h * D + d] = cur[d]
            for d in range(D - 1, -1, -1):
                cur[d] += 1
                if cur[d] < n_choice[d]:
                    break
                cur[d] = 0
    else:
        if hc["kind"] == "union":
            k = hc.get("k")
            if not (_is_integer(k) and k >= 1):
                raise ValueError("pca-intent: union class needs an integer k ≥ 1")
            boxes_m = _box_masks(vs, n_cells, cell_idx, n_cells_d, contains, n_choice, opts["maxEnumeration"])
            sets, cx = _enumerate_unions(boxes_m, int(k), opts["maxEnumeration"], vs["verb"])
        else:
            mr = hc.get("maxRules")
            if not (_is_integer(mr) and mr >= 1):
                raise ValueError("pca-intent: decision-list class needs an integer maxRules ≥ 1")
            cond = _opt(hc, "conditions", "box")
            if cond != "box" and cond != "atomic":
                raise ValueError("pca-intent: decision-list conditions must be 'box' or 'atomic'")
            if cond == "atomic":
                tests = _atomic_tests(vs, n_cells, cell_idx, n_cells_d)
            else:
                tests = _dedup_masks(_box_masks(vs, n_cells, cell_idx, n_cells_d, contains, n_choice, opts["maxEnumeration"]))
            sets, cx = _enumerate_decision_lists(tests, n_cells, int(mr), opts["maxEnumeration"], vs["verb"])
        if len(sets) + 1 > opts["maxHypotheses"]:
            raise ValueError("pca-intent: |Θ_%s| = %d exceeds maxHypotheses %s; coarsen the cuts" % (vs["verb"], len(sets) + 1, opts["maxHypotheses"]))
        nh = len(sets) + 1
        member = [bytearray(n_cells)] + sets
        complexity = [0] + list(cx)
    m = _VerbModel()
    m.vs = vs
    m.n_choice = n_choice
    m.contains = contains
    m.n_cells_d = n_cells_d
    m.nh = nh
    m.choice = choice
    m.member = member
    m.complexity = complexity
    m.prior = [0.0] * nh
    m.w = [0.0] * nh
    m.err = [0] * nh
    m.n_cells = n_cells
    m.cell_idx = cell_idx
    m.mass = mass
    m.harm = hm
    m.p = [0.0] * n_cells
    m.veto = bytearray(n_cells)
    m.seen = bytearray(n_cells)
    m.dirty = True
    return m


def _holds(m: _VerbModel, h: int, c: int) -> bool:
    """Does hypothesis h (>= 1) contain flat cell c?"""
    if m.member is not None:
        return m.member[h][c] == 1
    D = len(m.vs["dims"])
    base = (h - 1) * D
    for d in range(D):
        n = m.n_cells_d[d]
        if m.contains[d][m.choice[base + d] * n + m.cell_idx[c * D + d]] == 0:
            return False
    return True


def hypothesis_cell_sets(vs: dict, hypothesis_class: Optional[dict] = None, caps: Optional[dict] = None) -> Dict[str, Any]:
    """The non-empty hypotheses of Theta_v for a class as cell masks over the verb's flat cells, each with its Occam complexity."""
    o = {"maxHypotheses": 400000, "maxEnumeration": 4000000}
    for k, v in (caps or {}).items():
        if v is not None:
            o[k] = v
    o["hypothesisClass"] = hypothesis_class if hypothesis_class is not None else {"kind": "box"}
    m = _build_verb_model(vs, o, DEFAULT_HARM)
    sets: List[bytearray] = []
    complexity: List[int] = []
    for h in range(1, m.nh):
        s = bytearray(m.n_cells)
        for c in range(m.n_cells):
            if _holds(m, h, c):
                s[c] = 1
        sets.append(s)
        complexity.append(m.complexity[h] if m.complexity is not None else 1)
    return {"sets": sets, "complexity": complexity}


def _apply_monotone_prior(m: _VerbModel, mono: dict) -> None:
    off = _opt(mono, "offMass", 0)
    if not (off >= 0 and off <= 1):
        raise ValueError("pca-intent: monotone.offMass must be in [0, 1]")
    D = len(m.vs["dims"])
    paths = mono["paths"]
    ks = [k for k, d in enumerate(m.vs["dims"]) if d["kind"] == "num" and d["path"] in paths]
    if not ks:
        return
    stride = []
    for k in ks:
        s = 1
        for x in m.n_cells_d[k + 1:]:
            s *= x
        stride.append(s)
    for h in range(1, m.nh):
        is_mono = True
        c = 0
        while c < m.n_cells and is_mono:
            if _holds(m, h, c):
                for i in range(len(ks)):
                    if m.cell_idx[c * D + ks[i]] > 0 and not _holds(m, h, c - stride[i]):
                        is_mono = False
                        break
            c += 1
        if not is_mono:
            m.w[h] = m.w[h] * off


def _holds_all(m: _VerbModel, h: int, cells: List[int]) -> bool:
    if h == 0:
        return False
    for c in cells:
        if not _holds(m, h, c):
            return False
    return True


def _normalize(w: List[float]) -> None:
    s = 0.0
    for x in w:
        s += x
    if s > 0:
        for i in range(len(w)):
            w[i] = w[i] / s


def _mix_prior(m: _VerbModel, mix: dict) -> None:
    beta = mix["beta"]
    if not (beta >= 0 and beta < 1):
        raise ValueError("pca-intent: priorMix.beta must be in [0, 1)")
    pop = [0.0] * m.nh
    z = 0.0
    for h in range(m.nh):
        def contains(c: Any, h: int = h) -> bool:
            return h != 0 and _is_integer(c) and 0 <= c < m.n_cells and _holds(m, h, int(c))
        x = mix["weight"](m.vs, contains)
        if not (isinstance(x, (int, float)) and fin(x) and x >= 0):
            raise ValueError("pca-intent: priorMix.weight must be finite and >= 0")
        x = float(x)
        pop[h] = x
        z += x
    if not (z > 0):
        return
    for h in range(m.nh):
        m.w[h] = (1 - beta) * m.w[h] + (beta * pop[h]) / z


def _flat(m: _VerbModel, idx: List[int]) -> int:
    f = 0
    for d in range(len(idx)):
        f = f * m.n_cells_d[d] + idx[d]
    return f


class IntentLearner:
    """The exact posterior over Theta = prod_v Theta_v; options are the reference's plain-data LearnerOptions."""

    def __init__(self, omega: dict, opts: Optional[dict] = None):
        opts = opts if opts is not None else {}
        self.omega = omega
        self._opts = opts
        self.eta = _opt(opts, "eta", 0)
        if not (self.eta >= 0 and self.eta < 0.5):
            raise ValueError("pca-intent: eta must be in [0, 0.5)")
        self.eta_pos = _opt(opts, "etaPos", self.eta)
        self.eta_neg = _opt(opts, "etaNeg", self.eta)
        if not (self.eta_pos >= 0 and self.eta_pos < 0.5 and self.eta_neg >= 0 and self.eta_neg < 0.5):
            raise ValueError("pca-intent: etaPos and etaNeg must be in [0, 0.5)")
        self._noisy = self.eta_pos != 0 or self.eta_neg != 0
        self.tau = _opt(opts, "tau", 0.95 if self._noisy else 1)
        self.strategy = _opt(opts, "strategy", "disagreement")
        self.harm = _opt(opts, "harm", DEFAULT_HARM)
        self.hypothesis_class = _opt(opts, "hypothesisClass", {"kind": "box"})
        self.agnostic_slack = opts.get("agnosticSlack")
        if self.agnostic_slack is not None:
            if not (_is_integer(self.agnostic_slack) and self.agnostic_slack >= 0):
                raise ValueError("pca-intent: agnosticSlack must be a non-negative integer")
            if self._noisy:
                raise ValueError("pca-intent: agnostic selection replaces the noise model; use eta = 0")
        full = {"maxHypotheses": 400000, "maxEnumeration": 4000000}
        full.update({k: v for k, v in opts.items() if v is not None})
        self.observations: List[dict] = []
        self._models = [_build_verb_model(vs, full, self.harm) for vs in omega["verbs"]]
        self._init_prior()

    def _init_prior(self) -> None:
        opts = self._opts
        anchors = ([opts["anchor"]] if opts.get("anchor") else []) + list(opts.get("anchors") or [])
        anchors = [a for a in anchors if a["lambda"] > 0]
        admitters = [(admitter(a["policy"]), a["lambda"]) for a in anchors]
        decay = 1 if self.hypothesis_class["kind"] == "box" else _opt(self.hypothesis_class, "decay", 0.25)
        if not (decay > 0 and decay <= 1):
            raise ValueError("pca-intent: decay must be in (0, 1]")
        for m in self._models:
            nmo = opts.get("nullMass")
            nm = nmo(m.vs) if callable(nmo) else (0.2 if nmo is None else nmo)
            if not (nm >= 0 and nm <= 1):
                raise ValueError("pca-intent: nullMass must be in [0, 1]")
            m.w[0] = nm
            z = 0.0
            for h in range(1, m.nh):
                raw = math.pow(decay, m.complexity[h] - 1) if m.complexity is not None else 1
                m.w[h] = raw
                z += raw
            for h in range(1, m.nh):
                m.w[h] = ((1 - nm) * m.w[h]) / _or1(z)
            if opts.get("monotone"):
                _apply_monotone_prior(m, opts["monotone"])
            if admitters:
                tot = 0.0
                for c in range(m.n_cells):
                    tot += m.mass[c]
                accs = []
                for adm, _lam in admitters:
                    acc = bytearray(m.n_cells)
                    for c in range(m.n_cells):
                        acc[c] = 1 if adm.admits(m.vs, cell_rep(m.vs, decode_cell(m.vs, c))) else 0
                    accs.append(acc)
                for h in range(m.nh):
                    mix = 0.0
                    for i, acc in enumerate(accs):
                        dist = 0.0
                        for c in range(m.n_cells):
                            in_h = 0 if h == 0 else (1 if _holds(m, h, c) else 0)
                            if in_h != acc[c]:
                                dist += m.mass[c]
                        mix += math.exp((-admitters[i][1] * dist) / _or1(tot))
                    m.w[h] = m.w[h] * (mix / len(accs))
            _normalize(m.w)
            if opts.get("priorMix"):
                _mix_prior(m, opts["priorMix"])
            m.prior = list(m.w)
            m.dirty = True

    def _in_grant(self, m: _VerbModel, c: int) -> bool:
        return m.veto[c] == 0 and m.p[c] >= self.tau - 1e-12

    def _model(self, verb: Any) -> Optional[_VerbModel]:
        for m in self._models:
            if m.vs["verb"] == verb:
                return m
        return None

    def _refresh(self, m: _VerbModel) -> None:
        if not m.dirty:
            return
        m.p = [0.0] * m.n_cells
        # certainty is decided combinatorially (p = 1 iff every live hypothesis holds the cell), not by the float sum
        any_in = bytearray(m.n_cells)
        any_out = bytearray(m.n_cells)
        live = False
        for h in range(m.nh):
            w = m.w[h]
            if w == 0:
                continue
            live = True
            for c in range(m.n_cells):
                if h > 0 and _holds(m, h, c):
                    m.p[c] = m.p[c] + w
                    any_in[c] = 1
                else:
                    any_out[c] = 1
        for c in range(m.n_cells):
            m.p[c] = 0 if (not live or any_in[c] == 0) else (1 if any_out[c] == 0 else js_min(1, js_max(0, m.p[c])))
        m.dirty = False

    def acceptance(self, o: dict) -> float:
        """p_n(omega) for a concrete outcome (0 if outside Omega: the conservative reading)."""
        m = self._model(o.get("verb"))
        if m is None:
            return 0
        idx = cell_of(m.vs, o)
        if idx is None:
            return 0
        self._refresh(m)
        return m.p[_flat(m, idx)]

    def admits_outcome(self, o: dict) -> bool:
        m = self._model(o.get("verb"))
        if m is None:
            return False
        idx = cell_of(m.vs, o)
        if idx is None:
            return False
        self._refresh(m)
        return self._in_grant(m, _flat(m, idx))

    def is_vetoed(self, o: dict) -> bool:
        m = self._model(o.get("verb"))
        idx = cell_of(m.vs, o) if m is not None else None
        return m is not None and idx is not None and m.veto[_flat(m, idx)] == 1

    def vetoed_cells(self) -> List[str]:
        out: List[str] = []
        for m in self._models:
            for c in range(m.n_cells):
                if m.veto[c]:
                    out.append("%s|%d" % (m.vs["verb"], c))
        return out

    def observe(self, o: dict, y: int, source: str = "elicitation", region: Optional[dict] = None) -> Optional[dict]:
        """Record the principal's answer y to "should omega be allowed?" (or, with a region, "should EVERY outcome in it be
        allowed?") and update the posterior. None when the outcome is outside Omega or the region covers no cell."""
        m = self._model(o.get("verb"))
        if m is None:
            return None
        idx = cell_of(m.vs, o)
        if idx is None:
            return None
        cells = region_cells(m.vs, region, "inner" if y == 1 else "outer") if region is not None else [_flat(m, idx)]
        if len(cells) == 0:
            return None
        self._refresh(m)
        obs: Dict[str, Any] = {"verb": o["verb"], "values": dict(o.get("values") or {}), "cell": idx, "y": y, "source": source}
        if region is not None:
            obs["region"] = region
        # a "no" about a region every live hypothesis contains contradicts the whole class (the CONFLICT of spec 4.2c)
        region_p = 0.0
        for h in range(1, m.nh):
            if m.w[h] > 0 and _holds_all(m, h, cells):
                region_p += m.w[h]
        contradicts_all = region_p >= 1 - 1e-12 if y == 0 else region_p <= 1e-12
        if source == "runtime" and y == 0:
            for c in cells:
                m.veto[c] = 1
        for c in cells:
            m.seen[c] = 1
        if self.agnostic_slack is not None:
            for h in range(m.nh):
                if (1 if _holds_all(m, h, cells) else 0) != y:
                    m.err[h] += 1
            min_err = math.inf
            for h in range(m.nh):
                if m.prior[h] > 0:
                    min_err = js_min(min_err, m.err[h])
            for h in range(m.nh):
                m.w[h] = m.prior[h] if m.err[h] <= min_err + self.agnostic_slack else 0.0
            _normalize(m.w)
            if contradicts_all:
                obs["conflict"] = True
                if y == 0:
                    for c in cells:
                        m.veto[c] = 1
        else:
            prev = list(m.w) if (self.eta_pos == 0 or self.eta_neg == 0) else None
            eta_pos, eta_neg = self.eta_pos, self.eta_neg

            def lik(in_h: int) -> float:
                if in_h == 1:
                    return 1 - eta_neg if y == 1 else eta_neg
                return eta_pos if y == 1 else 1 - eta_pos

            total = 0.0
            for h in range(m.nh):
                m.w[h] = m.w[h] * lik(1 if _holds_all(m, h, cells) else 0)
                total += m.w[h]
            if total == 0 and prev is not None:
                m.w = prev  # every hypothesis contradicted: the truth is outside Theta; keep VS, flag the conflict
                obs["conflict"] = True
                if y == 0:
                    for c in cells:
                        m.veto[c] = 1
            else:
                _normalize(m.w)
        m.dirty = True
        self.observations.append(obs)
        return obs

    def cells(self) -> List[dict]:
        out: List[dict] = []
        for m in self._models:
            self._refresh(m)
            for c in range(m.n_cells):
                out.append({"verb": m.vs["verb"], "cell": decode_cell(m.vs, c), "p": m.p[c], "mass": m.mass[c], "harm": m.harm[c],
                            "inGrant": self._in_grant(m, c), "vetoed": m.veto[c] == 1})
        return out

    def metrics(self) -> Dict[str, Any]:
        R = B = U = H = vs_bits = dis = mean_harm = 0.0
        for m in self._models:
            self._refresh(m)
            for c in range(m.n_cells):
                p = m.p[c]
                mu = m.mass[c]
                mean_harm += mu * m.harm[c]
                if self._in_grant(m, c):
                    R += mu * (1 - p) * m.harm[c]
                else:
                    B += mu * p
                U += mu * js_min(p, 1 - p)
                if p > 1e-12 and p < 1 - 1e-12:
                    dis += mu
            alive = 0
            for h in range(m.nh):
                w = m.w[h]
                if w > 0:
                    alive += 1
                    H -= w * math.log2(w)
            vs_bits += math.log2(max(1, alive))
        return {
            "residualRisk": R, "burden": B, "uncertainty": U, "entropyBits": H,
            "log2VersionSpace": None if self._noisy else vs_bits,
            "disagreementMass": dis, "meanHarm": mean_harm,
            "questions": sum(1 for o in self.observations if o["source"] == "elicitation"),
            "conflicts": sum(1 for o in self.observations if o.get("conflict")),
        }

    def next_question(self) -> Optional[dict]:
        """The next question: argmax expected information (x mu*h for the risk strategy). None when nothing is uncertain."""
        best: Optional[dict] = None
        h_pos = _bin_ent(self.eta_pos)
        h_neg = _bin_ent(self.eta_neg)
        for m in self._models:
            self._refresh(m)
            for c in range(m.n_cells):
                if m.veto[c]:
                    continue
                p = m.p[c]
                if p <= 1e-9 or p >= 1 - 1e-9:
                    continue
                pe = p * (1 - self.eta_neg) + (1 - p) * self.eta_pos
                score = _bin_ent(pe) - (h_pos if self.eta_pos == self.eta_neg else p * h_neg + (1 - p) * h_pos)
                if self.strategy == "risk":
                    score *= m.mass[c] * m.harm[c]
                if score <= 1e-15:
                    continue
                if best is None or score > best["score"] + 1e-12:
                    cell = decode_cell(m.vs, c)
                    best = {"verb": m.vs["verb"], "cell": cell, "outcome": cell_rep(m.vs, cell), "p": p, "score": score}
        return best

    def unconfirmed_grant_cells(self) -> List[dict]:
        """Grant cells INFERRED but never directly observed, most consequential first."""
        out: List[dict] = []
        for m in self._models:
            self._refresh(m)
            for c in range(m.n_cells):
                if m.seen[c] or not self._in_grant(m, c):
                    continue
                out.append({"verb": m.vs["verb"], "cell": decode_cell(m.vs, c), "weight": m.mass[c] * m.harm[c]})
        out.sort(key=lambda x: x["weight"], reverse=True)  # stable, like the reference's sort
        return out

    def synthesize(self) -> Dict[str, Any]:
        """The conservative grant G_tau as a real PCA policy: allow only cells with p_n >= tau."""
        predicates: List[dict] = []
        worst = -1
        for m in self._models:
            self._refresh(m)
            allowed = bytearray(m.n_cells)
            any_ = False
            for c in range(m.n_cells):
                if self._in_grant(m, c):
                    allowed[c] = 1
                    any_ = True
            if not any_:
                continue
            rv = m.vs.get("reversibility")
            worst = max(worst, _ORDER.index(rv) if rv in _ORDER else -1)
            predicates.extend(boxes_to_predicates(m.vs, allowed))
        caveats = [{"type": "reversibility_max", "class": _ORDER[worst]}] if worst >= 0 else []
        return {"predicates": predicates, "caveats": caveats}

    @staticmethod
    def replay(omega: dict, opts: Optional[dict], observations: List[dict]) -> "IntentLearner":
        """Replay observations onto a fresh learner (used to verify an Intent Map)."""
        l = IntentLearner(omega, opts)
        for o in observations:
            l.observe({"verb": o["verb"], "values": o["values"]}, o["y"], o["source"], o.get("region"))
        return l


# ---- synthesis: allowed cells -> union of boxes -> predicates ----------------------------------------------------------

def _encode(vs: dict, idx: List[int]) -> int:
    f = 0
    for i, d in enumerate(vs["dims"]):
        f = f * (len(num_cells(d)) if d["kind"] == "num" else len(d["values"])) + idx[i]
    return f


def _box_cells(ranges: List[Any]) -> List[Tuple[int, ...]]:
    vals = []
    for r in ranges:
        if isinstance(r, list):
            vals.append(list(range(r[0], r[1] + 1)))
        else:
            vals.append(sorted(r))
    return list(itertools.product(*vals))


def _cat_condition(d: dict, S: Dict[int, bool]) -> Optional[dict]:
    if len(S) == len(d["values"]):
        return None
    exacts = [v["value"] for v in d["values"] if v["kind"] == "exact"]
    prefixes = [v["value"] for v in d["values"] if v["kind"] == "prefix"]
    alts: List[dict] = []
    allowed_exacts = [d["values"][i]["value"] for i in S if d["values"][i]["kind"] == "exact"]  # set insertion order
    if len(allowed_exacts) == 1:
        alts.append({"field": d["path"], "op": "eq", "value": allowed_exacts[0]})
    elif len(allowed_exacts) > 1:
        alts.append({"field": d["path"], "op": "in", "value": allowed_exacts})
    for i in sorted(S):
        v = d["values"][i]
        if v["kind"] == "exact":
            continue
        parts: List[dict] = []
        if v["kind"] == "prefix":
            parts.append({"field": d["path"], "op": "prefix", "value": v["value"]})
            under = [e for e in exacts if e.startswith(v["value"])]
            if under:
                parts.append({"field": d["path"], "op": "nin", "value": under})
            for q in prefixes:
                if q != v["value"] and q.startswith(v["value"]):
                    parts.append({"not": {"field": d["path"], "op": "prefix", "value": q}})
        else:
            if exacts:
                parts.append({"field": d["path"], "op": "nin", "value": exacts})
            for q in prefixes:
                parts.append({"not": {"field": d["path"], "op": "prefix", "value": q}})
        if len(parts) == 1:
            alts.append(parts[0])
        elif len(parts) > 1:
            alts.append({"all_of": parts})
    if not alts:
        return None
    return alts[0] if len(alts) == 1 else {"any_of": alts}


def _box_to_predicate(vs: dict, ranges: List[Any]) -> dict:
    where: List[dict] = []
    for k, d in enumerate(vs["dims"]):
        r = ranges[k]
        if d["kind"] == "num" and isinstance(r, list):
            cells = num_cells(d)
            where.append({"field": d["path"], "op": "gte", "value": cells[r[0]]["lo"]})
            where.append({"field": d["path"], "op": "lte", "value": cells[r[1]]["hi"]})
        elif d["kind"] == "cat" and isinstance(r, dict):
            c = _cat_condition(d, r)
            if c:
                where.append(c)
    out: Dict[str, Any] = {"verb": vs["verb"], "resource": "*"}
    if where:
        out["where"] = where
    return out


def boxes_to_predicates(vs: dict, allowed: Any) -> List[dict]:
    """Cover the allowed cell set exactly with greedily-grown maximal boxes; one predicate per box."""
    covered = bytearray(len(allowed))
    out: List[dict] = []

    def all_(ranges: List[Any]) -> bool:
        return all(allowed[_encode(vs, idx)] == 1 for idx in _box_cells(ranges))

    for c in range(len(allowed)):
        if not allowed[c] or covered[c]:
            continue
        idx = decode_cell(vs, c)
        ranges: List[Any] = [[idx[k], idx[k]] if d["kind"] == "num" else {idx[k]: True} for k, d in enumerate(vs["dims"])]
        for k, d in enumerate(vs["dims"]):
            if d["kind"] == "num":
                n = len(num_cells(d))
                r = ranges[k]
                while r[1] + 1 < n:
                    r[1] += 1
                    if not all_(ranges):
                        r[1] -= 1
                        break
                while r[0] > 0:
                    r[0] -= 1
                    if not all_(ranges):
                        r[0] += 1
                        break
            else:
                s = ranges[k]
                for v in range(len(d["values"])):
                    if v in s:
                        continue
                    s[v] = True
                    if not all_(ranges):
                        del s[v]
        for bi in _box_cells(ranges):
            covered[_encode(vs, list(bi))] = 1
        out.append(_box_to_predicate(vs, ranges))
    return out


# ---- the stop rule -----------------------------------------------------------------------------------------------------

def _seed_question(learner: IntentLearner, s: dict) -> Optional[dict]:
    vs = next((v for v in learner.omega["verbs"] if v["verb"] == s["verb"]), None)
    if vs is None or len(s["cell"]) != len(vs["dims"]):
        return None
    outcome = cell_rep(vs, s["cell"])
    p = learner.acceptance(outcome)
    if p <= 1e-9 or p >= 1 - 1e-9 or learner.is_vetoed(outcome):
        return None
    return {"verb": s["verb"], "cell": list(s["cell"]), "outcome": outcome, "p": p, "score": 0}


def elicit(learner: IntentLearner, answer: Callable[[dict], int], o: dict) -> Dict[str, Any]:
    """Ask questions until the stop rule of spec 2.5 holds."""
    asked: List[dict] = []
    seed_questions = 0
    for s in o.get("seed") or []:
        if len(asked) >= o["maxQuestions"]:
            break
        m = learner.metrics()
        if m["residualRisk"] <= o["epsRisk"] and m["burden"] <= o["epsBurden"]:
            break
        q = _seed_question(learner, s)
        if q is None:
            continue
        learner.observe(q["outcome"], answer(q), "elicitation")
        asked.append(q)
        seed_questions += 1
    stop: Optional[str] = None
    while stop is None:
        m = learner.metrics()
        if m["residualRisk"] <= o["epsRisk"] and m["burden"] <= o["epsBurden"]:
            stop = "converged"
        elif len(asked) >= o["maxQuestions"]:
            stop = "budget"
        else:
            q = learner.next_question()
            if q is None:
                stop = "no-disagreement"
            else:
                learner.observe(q["outcome"], answer(q), "elicitation")
                asked.append(q)
    audit = audit_round(learner, answer, o, asked)
    if audit["exhausted"]:
        stop = "budget"
    return {"stop": stop, "questions": len(asked), "auditQuestions": audit["asked"], "seedQuestions": seed_questions, "asked": asked}


def audit_round(learner: IntentLearner, answer: Callable[[dict], int], o: dict, asked: List[dict]) -> Dict[str, Any]:
    """The audit round on its own (spec 4.2c): the questions asked, and whether the budget ran out. Appends to `asked`."""
    n = 0
    if not o.get("audit"):
        return {"asked": 0, "exhausted": False}
    while True:
        pending = learner.unconfirmed_grant_cells()
        mass = 0.0
        for x in pending:
            mass += x["weight"]
        if len(pending) == 0 or mass <= o["epsRisk"]:
            return {"asked": n, "exhausted": False}
        if len(asked) >= o["maxQuestions"]:
            return {"asked": n, "exhausted": True}
        top = pending[0]
        vs = next(v for v in learner.omega["verbs"] if v["verb"] == top["verb"])
        outcome = cell_rep(vs, top["cell"])
        q = {"verb": top["verb"], "cell": top["cell"], "outcome": outcome, "p": learner.acceptance(cell_rep(vs, top["cell"])), "score": top["weight"]}
        learner.observe(q["outcome"], answer(q), "elicitation")
        asked.append(q)
        n += 1
