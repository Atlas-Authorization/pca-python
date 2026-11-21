"""Risk functional, threshold map and decaying trust budget (spec section 10): pure and deterministic, a port of the TypeScript
reference ``risk.ts``. Time is epoch milliseconds; ``lambda`` is budget drained PER SECOND. A non-finite input fails closed (it counts
as the worst case). Budgets are dicts ``{"B": float, "tau": float, "asOf"?: float}`` (the reference's TrustBudget)."""
import math
from typing import Any, Dict, List, Optional

DEFAULT_RISK_POLICY: Dict[str, Any] = {
    "weights": {"alpha": 0.25, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05},
    "theta1": 0.25,
    "theta2": 0.6,
    "kappa": 1,
    "lambda": 0.0005,
    "rho": 0.5,
    "bMax": 1,
}


def _fin(x: Any) -> bool:
    """JS Number.isFinite: a finite int or float (a bool is not a number)."""
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def validate_risk_policy(p: Any) -> Optional[str]:
    """An error string if the policy is not well formed, else None."""
    if not isinstance(p, dict):
        return "risk_policy must be an object"
    w = p.get("weights")
    if not isinstance(w, dict):
        return "risk_policy.weights missing"
    for k in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta"):
        if not _fin(w.get(k)) or w[k] < 0:
            return "risk_policy.weights.%s must be finite and >= 0" % k
    for k in ("theta1", "theta2", "kappa", "lambda", "rho", "bMax"):
        if not _fin(p.get(k)):
            return "risk_policy.%s must be finite" % k
    if p["theta1"] < 0 or p["theta2"] < p["theta1"]:
        return "risk_policy requires 0 <= theta1 <= theta2"
    if p["kappa"] <= 0:
        return "risk_policy.kappa must be > 0"
    if p["lambda"] < 0 or p["rho"] < 0 or p["bMax"] < 0:
        return "risk_policy lambda/rho/bMax must be >= 0"
    return None


def _clamp01(x: float) -> float:
    return 0 if x < 0 else 1 if x > 1 else x


def _unit(x: Any, worst: int) -> float:
    """Non-finite => worst; else clamp to [0, 1]. `worst` is 1 for risk-increasing inputs, 0 for reversibility / confidence."""
    return _clamp01(x) if _fin(x) else worst


def _wt(x: Any) -> float:
    return x if _fin(x) and x > 0 else 0


def risk_score(i: Dict[str, Any], w: Dict[str, Any]) -> float:
    """r = clamp(a*d + b*(1-rev) + g*bl + d*taint + e*(1-conf) + z*age, 0, 1). Monotone non-decreasing in distance, blast radius, taint and
    age and non-increasing in reversibility and confidence (weights below zero count as zero, which makes that hold for any policy)."""
    r = (_wt(w.get("alpha")) * _unit(i.get("semanticDistance"), 1)
         + _wt(w.get("beta")) * (1 - _unit(i.get("reversibility"), 0))
         + _wt(w.get("gamma")) * _unit(i.get("blastRadius"), 1)
         + _wt(w.get("delta")) * _unit(i.get("taint"), 1)
         + _wt(w.get("epsilon")) * (1 - _unit(i.get("confidence"), 0))
         + _wt(w.get("zeta")) * _unit(i.get("age"), 1))
    return _clamp01(r)


def required_threshold(r: Any, p: Dict[str, Any], irreversible: bool = False) -> Dict[str, Any]:
    """The piecewise map: r <= theta1 -> t=1 (claim, optimistic ok); theta1 < r <= theta2 -> t=2 (standard); r > theta2 -> t=3 (strong).
    Optimistic acceptance only at t=1 and never for an irreversible action. Monotone in r; a non-finite r is the worst."""
    x = r if _fin(r) else 1
    if x <= p["theta1"]:
        return {"t": 1, "proof": "claim", "optimisticAllowed": not irreversible}
    if x <= p["theta2"]:
        return {"t": 2, "proof": "standard", "optimisticAllowed": False}
    return {"t": 3, "proof": "strong", "optimisticAllowed": False}


_PROOF_FOR_T = {1: "claim", 2: "standard", 3: "strong"}
_PROOF_RANK = {"claim": 0, "standard": 1, "strong": 2}


def escalate_threshold(rt: Dict[str, Any], min_t: int) -> Dict[str, Any]:
    """Raise a required threshold to at least `min_t` and keep it coherent (t=2 -> proof >= standard, t=3 -> strong, never optimistic above
    t=1). Never lowers anything."""
    t = min_t if min_t > rt["t"] else rt["t"]
    floor = _PROOF_FOR_T[t]
    proof = rt["proof"] if _PROOF_RANK[rt["proof"]] >= _PROOF_RANK[floor] else floor
    return {"t": t, "proof": proof, "optimisticAllowed": False if t > 1 else rt["optimisticAllowed"]}


def _nz(x: Any) -> float:
    return x if _fin(x) and x > 0 else 0


def cost(r: Any, kappa: Any) -> float:
    """c(A) = kappa * r(A). A non-finite r costs as r = 1."""
    return _nz(kappa) * _clamp01(r if _fin(r) else 1)


def leak(b: Dict[str, Any], now: Any, lam: Any) -> Dict[str, Any]:
    """Passive leak dB/dt = -lambda since the last update. Idempotent for repeated calls at the same `now`; leak is not a human touch."""
    frm = b["asOf"] if b.get("asOf") is not None else b["tau"]
    dt = max(0, now - frm) if _fin(now) and _fin(frm) else 0
    big_b = max(0, b["B"] - _nz(lam) * (dt / 1000))
    return {"B": big_b, "tau": b["tau"], "asOf": max(now, frm) if _fin(now) else frm}


def debit(b: Dict[str, Any], c: Any) -> Dict[str, Any]:
    """B <- max(0, B - cost). Callers must check B >= cost first (`admit` does)."""
    return dict(b, B=max(0, b["B"] - _nz(c)))


def recharge(b: Dict[str, Any], rho: Any, b_max: Any, now: Any) -> Dict[str, Any]:
    """Human co-sign recharge: B <- min(bMax, B + rho), tau <- now. The ONLY way budget increases."""
    return {"B": min(_nz(b_max), b["B"] + _nz(rho)), "tau": now, "asOf": now}


def recharge_full(b: Dict[str, Any], b_max: Any, now: Any) -> Dict[str, Any]:
    """Full goal re-confirmation: B <- bMax, tau <- now."""
    return {"B": _nz(b_max), "tau": now, "asOf": now}


def age_since_touch(b: Dict[str, Any], now: Any, horizon_ms: Any = 3_600_000) -> float:
    """Normalized age since the last human touch: clamp((now - tau) / horizon, 0, 1)."""
    if not _fin(now) or not _fin(b.get("tau")) or not (_fin(horizon_ms) and horizon_ms > 0):
        return 1
    return _clamp01((now - b["tau"]) / horizon_ms)


def admit(r: Any, b: Dict[str, Any], p: Dict[str, Any]) -> Dict[str, Any]:
    """The machine-only band is t=1 AND t=2 (at t=2 the guardian auto-cosigns), so BOTH are metered: an action at t<3 proceeds only if
    B >= c(A) and is then debited kappa*r; when the budget cannot cover it the action escalates to t=3 (a human step-up). t=3 is never
    debited. The budget passed in must already be leaked up to the decision time."""
    t = required_threshold(r, p)["t"]
    c = cost(r, p["kappa"])
    if t < 3 and not b["B"] >= c:
        return {"admit": False, "needStepUp": True, "t": 3, "metered": False}
    if t == 1:
        return {"admit": True, "needStepUp": False, "t": 1, "metered": True}
    if t == 2:
        return {"admit": False, "needStepUp": True, "t": 2, "metered": True}
    return {"admit": False, "needStepUp": True, "t": 3, "metered": False}


def safety_bound(p: Dict[str, Any]) -> float:
    """Between two consecutive human recharges the total risk of machine-only actions is at most bMax / kappa."""
    return max(0, p["bMax"]) / p["kappa"] if p["kappa"] > 0 else 0


# ---- multi-agent budget algebra -------------------------------------------------------------------------------------------------------

def sub_budget(parent: Dict[str, Any], alloc: Any) -> Dict[str, Any]:
    """Allocate a sub-agent budget B_sub = alloc, guarded by 0 <= alloc <= parent.B (the parent's remaining)."""
    if not _fin(alloc) or alloc < 0:
        return {"ok": False, "reason": "allocation must be finite and >= 0"}
    if alloc > parent["B"]:
        return {"ok": False, "reason": "allocation exceeds parent remaining budget"}
    return {"ok": True, "sub": {"B": alloc, "tau": parent["tau"], "asOf": parent["asOf"] if parent.get("asOf") is not None else parent["tau"]}}


def debit_consolidated(parent: Dict[str, Any], sub: Dict[str, Any], c: Any) -> Dict[str, Any]:
    """A sub-agent's debit ALSO debits the parent, so a swarm of sub-agents cannot spend more than the parent's remaining budget. Fails with
    no state change when either cannot cover `c`."""
    x = _nz(c)
    if sub["B"] < x:
        return {"ok": False, "reason": "sub-agent budget insufficient"}
    if parent["B"] < x:
        return {"ok": False, "reason": "parent budget insufficient"}
    return {"ok": True, "parent": debit(parent, x), "sub": debit(sub, x)}


def debit_consolidated_path(path: List[Dict[str, Any]], c: Any) -> Dict[str, Any]:
    """Consolidated debit along a root-to-leaf budget path: every node (the acting leaf and each ancestor) must cover `c`; if ANY cannot,
    nothing is debited and the first offender is named. `path` is ordered root..leaf."""
    x = _nz(c)
    for i, node in enumerate(path):
        if not node["B"] >= x:
            return {"ok": False, "reason": "budget node at depth %d insufficient (need %s, have %s)" % (i, _num(x), _num(node["B"]))}
    return {"ok": True, "nodes": [debit(b, x) for b in path]}


def _num(v: Any) -> str:
    """JS number text for the reason strings: an integral float prints without a fraction."""
    return str(int(v)) if isinstance(v, float) and v.is_integer() and abs(v) < 1e21 else repr(v) if isinstance(v, float) else str(v)


# ---- plan geodesic --------------------------------------------------------------------------------------------------------------------

_PRE_KEYS = ("after", "depends_on", "requires", "nodes")
_POST_KEYS = ("before", "enables", "then", "next")


def _refs_of(x: Any, keys: Any) -> List[str]:
    out: List[str] = []

    def add(v: Any) -> None:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            out.extend(s for s in v if isinstance(s, str))

    add(x)
    if isinstance(x, dict):
        for k in keys:
            add(x.get(k))
    return out


def plan_geodesic(plan: Any, from_node_id: str, to_goal_node_id: str) -> float:
    """Normalized geodesic distance in the committed plan DAG, in [0, 1] (an approximation: edges come from node references in `pre` / `post`,
    BFS over the UNDIRECTED graph divided by n-1, unreachable = 1; no edges at all falls back to |i-j|/(n-1); an unknown node id = 1)."""
    if not isinstance(plan, list):
        return 1
    idx: Dict[str, int] = {}
    for i, n in enumerate(plan):
        idx[n["id"]] = i
    a, b = idx.get(from_node_id), idx.get(to_goal_node_id)
    if a is None or b is None:
        return 1
    if a == b:
        return 0
    n = len(plan)
    adj: List[set] = [set() for _ in plan]
    edges = [0]

    def link(i: int, j: int) -> None:
        if i == j:
            return
        if j not in adj[i]:
            edges[0] += 1
        adj[i].add(j)
        adj[j].add(i)

    for i, node in enumerate(plan):
        for rid in _refs_of(node.get("pre"), _PRE_KEYS):
            j = idx.get(rid)
            if j is not None:
                link(j, i)
        for rid in _refs_of(node.get("post"), _POST_KEYS):
            j = idx.get(rid)
            if j is not None:
                link(i, j)
    if edges[0] == 0:
        return _clamp01(abs(a - b) / (n - 1))
    dist = [-1] * n
    dist[a] = 0
    q = [a]
    h = 0
    while h < len(q):
        u = q[h]
        h += 1
        for v in sorted(adj[u]):
            if dist[v] == -1:
                dist[v] = dist[u] + 1
                q.append(v)
    return 1 if dist[b] < 0 else _clamp01(dist[b] / (n - 1))


# ---- the policy decision (risk, threshold, budget, release) -------------------------------------------------------------------------

WORST = {"semanticDistance": 1, "reversibility": 0, "blastRadius": 1, "taint": 1, "confidence": 0, "age": 1}
FAST_PATH_ELIGIBLE_CLASSES = ("reversible", "rate_limited", "costly")


def riskier(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The riskier of two risk-input sets per input: higher is riskier, except reversibility and confidence (lower is riskier). A
    non-finite value of `b` is ignored; neither source can lower the other."""
    if not a or not b:
        return a if a else b
    out = dict(a)
    for k, y in b.items():
        if not _fin(y):
            continue
        x = a.get(k)
        if not _fin(x):
            out[k] = y
        else:
            out[k] = min(x, y) if k in ("reversibility", "confidence") else max(x, y)
    return out


def decide_risk(pol: Dict[str, Any], risk: Optional[Dict[str, Any]], budget: Dict[str, Any], now: Any, release: bool,
                reversibility_class: Any = None, plan: Any = None, node_id: Any = None, goal_node_id: Any = None,
                age_horizon_ms: Any = None, r_floor: Any = None) -> Dict[str, Any]:
    """Steps 3-5 of the reference policy VM, given whether the envelope predicates and caveats released the share (`release`):

    r = max(risk_score(inputs), r_floor) over the server-supplied inputs (a missing or non-finite input is assumed at its worst case and
    named in the reasons; the plan geodesic fills `semanticDistance`, the age since the last human touch fills `age`); the threshold
    band (never optimistic for an action whose class is not a recognized non-irreversible one) and the budget admission; the escalation,
    and the release / admit / debit decision. Returns {"r", "release", "threshold", "admit", "needStepUp", "reasons", "budget"}."""
    leaked = leak(budget, now, pol["lambda"])
    inputs = dict(WORST)
    inputs.update({k: v for k, v in (risk or {}).items() if k in WORST and _fin(v)})
    missing = [k for k in WORST if k != "age" and not _fin((risk or {}).get(k))]
    reasons: List[str] = []
    if plan is not None and (risk or {}).get("semanticDistance") is None:
        goal = goal_node_id if goal_node_id is not None else (plan[-1]["id"] if isinstance(plan, list) and plan else None)
        inputs["semanticDistance"] = plan_geodesic(plan, node_id, goal) if node_id is not None and goal is not None else 1
        if "semanticDistance" in missing:
            missing.remove("semanticDistance")
    if (risk or {}).get("age") is None:
        inputs["age"] = age_since_touch(leaked, now, age_horizon_ms if age_horizon_ms is not None else 3_600_000)
    if missing:
        reasons.append("risk input(s) missing, assumed worst case: %s" % ", ".join(missing))
    floor = min(1, max(0, r_floor)) if _fin(r_floor) else 0
    r = max(risk_score(inputs, pol["weights"]), floor)
    irreversible = not (isinstance(reversibility_class, str) and reversibility_class in FAST_PATH_ELIGIBLE_CLASSES)
    rt = required_threshold(r, pol, irreversible)
    adm = admit(r, leaked, pol)
    if adm["needStepUp"]:
        reasons.append("trust budget depleted: human recharge required" if rt["t"] < 3 and adm["t"] == 3
                       else "risk %s exceeds auto threshold: step-up to t=%d" % (_to_fixed3(r), adm["t"]))
    return {
        "r": r,
        "release": release,
        "threshold": escalate_threshold(rt, adm["t"]),
        "admit": release and adm["admit"],
        "needStepUp": adm["needStepUp"] if release else True,
        "reasons": reasons,
        "budget": debit(leaked, cost(r, pol["kappa"])) if release and adm["metered"] else leaked,
    }


def _to_fixed3(x: float) -> str:
    """JS Number.toFixed(3)."""
    return "%.3f" % x
