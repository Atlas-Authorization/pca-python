"""Multi-principal intent: aggregation rules (unanimity, quorum, weighted, vetoers), the exact joint-acceptance DP and the
common refinement of several outcome spaces. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from ._fin import fin
import copy
import math
from typing import Any, Dict, List

from .intent_omega import u16key
from .intent_v2 import _UNDEF, _js_string

PPM = 1000000


def ppm(x: float) -> int:
    return int(math.floor(x * PPM + 0.5))


def _member(o: Any, k: str) -> Any:
    """o.k with the reference's TypeError on null / undefined (the message is part of the observable behaviour)."""
    if o is None:
        raise TypeError("Cannot read properties of null (reading '%s')" % k)
    if o is _UNDEF:
        raise TypeError("Cannot read properties of undefined (reading '%s')" % k)
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def _is_int(x: Any) -> bool:
    return (isinstance(x, int) and not isinstance(x, bool)) or (isinstance(x, float) and fin(x) and x.is_integer())


def normalize_rule(rule: Any, refs: List[str]) -> Dict[str, Any]:
    """A rule in normal form: {weights, threshold, veto}; the reference's error messages."""
    vs = _member(rule, "vetoers")
    if vs is None or vs is _UNDEF:
        vs = []
    if isinstance(vs, (list, str)):
        vetoers = list(vs)
    else:
        raise TypeError("rule.vetoers is not iterable")
    for v in vetoers:
        if v not in refs:
            raise ValueError("aggregateIntentMaps: vetoer %s is not one of the maps" % v)
    veto = [r in vetoers for r in refs]
    kind = _member(rule, "kind")
    if kind == "unanimity":
        return {"weights": [1 for _ in refs], "threshold": len(refs), "veto": veto}
    if kind == "quorum":
        k = _member(rule, "k")
        if not (_is_int(k) and k >= 1 and k <= len(refs)):
            raise ValueError("aggregateIntentMaps: quorum k must be an integer in [1, %d]" % len(refs))
        return {"weights": [1 for _ in refs], "threshold": k, "veto": veto}
    wmap = _member(rule, "weights")
    weights = [_member(wmap, r) for r in refs]
    if any(not (_is_int(w) and w >= 0) for w in weights):
        raise ValueError("aggregateIntentMaps: every principal needs a non-negative integer weight")
    W = 0
    for w in weights:
        W += w
    th = _member(rule, "threshold")
    if not (_is_int(th) and th >= 1 and th <= W):
        raise ValueError("aggregateIntentMaps: threshold must be an integer in [1, %s]" % _js_string(W))
    return {"weights": weights, "threshold": th, "veto": veto}


def effective_vetoers(rule: Any, refs: List[str]) -> List[str]:
    """Principals that bound the joint grant: explicit vetoers plus implicit ones (T > W - w_i)."""
    n = normalize_rule(rule, refs)
    W = sum(n["weights"])
    return [r for i, r in enumerate(refs) if n["veto"][i] or n["threshold"] > W - n["weights"][i]]


def rule_admits(n: dict, ins: List[bool]) -> bool:
    """Vetoers must admit; the admitting weight must reach the threshold."""
    s = 0
    for i in range(len(ins)):
        if n["veto"][i] and not ins[i]:
            return False
        if ins[i]:
            s += n["weights"][i]
    return s >= n["threshold"]


def joint_acceptance(n: dict, ps: List[float]) -> float:
    """P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the (capped) admitting weight."""
    th = n["threshold"]
    dist = [0.0] * (th + 1)
    dist[0] = 1.0
    for i, p in enumerate(ps):
        nxt = [0.0] * (th + 1)
        w = n["weights"][i]
        for s in range(th + 1):
            m = dist[s]
            if m == 0:
                continue
            t = min(th, s + w)
            nxt[t] = nxt[t] + m * p
            if not n["veto"][i]:
                nxt[s] = nxt[s] + m * (1 - p)
        dist = nxt
    return dist[th]


# ---- cross-org: common refinement ---------------------------------------------------------------------------------

_SEV = ["reversible", "rate_limited", "irreversible"]


def _sev(r: Any) -> int:
    return _SEV.index(r) if r in _SEV else -1


def _merge_dim(a: dict, b: dict) -> dict:
    if a["kind"] != b["kind"]:
        raise ValueError("commonRefinement: %s is numeric in one Ω and categorical in another" % a["path"])
    if a["kind"] == "num":
        if a["lo"] != b["lo"] or a["hi"] != b["hi"]:
            raise ValueError("commonRefinement: %s has different domains ([%s, %s] vs [%s, %s])" % (a["path"], a["lo"], a["hi"], b["lo"], b["hi"]))
        cuts: List[Any] = []
        for c in list(a["cuts"]) + list(b["cuts"]):
            if c not in cuts:
                cuts.append(c)
        return {"kind": "num", "path": a["path"], "lo": a["lo"], "hi": a["hi"], "dist": a.get("dist"), "cuts": sorted(cuts)}
    ex: Dict[str, None] = {}
    pre: Dict[str, None] = {}
    for v in list(a["values"]) + list(b["values"]):
        if v["kind"] == "exact":
            ex[v["value"]] = None
        elif v["kind"] == "prefix":
            pre[v["value"]] = None
    values = [{"kind": "exact", "value": v} for v in sorted(ex, key=u16key)]
    values += [{"kind": "prefix", "value": v} for v in sorted(pre, key=u16key)]
    values.append({"kind": "other", "value": "⊥"})
    return {"kind": "cat", "path": a["path"], "values": values}


def common_refinement(omegas: List[dict]) -> dict:
    """The union of the verbs; per verb the union of dimensions; per numeric dimension the union of cuts (domains must
    agree); per categorical dimension the union of the named values."""
    by_verb: Dict[str, dict] = {}
    approx: Dict[str, None] = {}
    for o in omegas:
        for x in o["approximate"]:
            approx[x] = None
        for vs in o["verbs"]:
            cur = by_verb.get(vs["verb"])
            if cur is None:
                by_verb[vs["verb"]] = {"verb": vs["verb"], "reversibility": vs["reversibility"], "weight": 0,
                                       "dims": [copy.deepcopy(d) for d in vs["dims"]]}
                continue
            if _sev(vs["reversibility"]) > _sev(cur["reversibility"]):
                cur["reversibility"] = vs["reversibility"]
            for d in vs["dims"]:
                i = next((k for k, x in enumerate(cur["dims"]) if x["path"] == d["path"]), -1)
                if i < 0:
                    cur["dims"].append(copy.deepcopy(d))
                else:
                    cur["dims"][i] = _merge_dim(cur["dims"][i], d)
    verbs = sorted(by_verb.values(), key=lambda v: u16key(v["verb"]))
    for v in verbs:
        v["dims"].sort(key=lambda d: u16key(d["path"]))
        v["weight"] = 1 / len(verbs)
    return {"v": 1, "verbs": verbs, "approximate": sorted(approx, key=u16key)}
