"""Policy simulation and linting: what a compiled policy (``atlas_pca.facade.compile_policy``) will do before it is enabled.

``simulate`` replays hypothetical actions in time order, threading the trust budget as the server would (leak between actions, a debit of
``kappa * r`` on every metered admit, a step-up when the budget cannot cover a machine-band action) and reports ``auto`` / ``step_up`` /
``deny`` per action. ``lint_policy`` is a set of static lints for the classic authoring mistakes. Both are pure and offline: a planning
tool, the resource server's verifier stays the authority at run time. Reports are dicts with the reference member names."""
from __future__ import annotations

from ._fin import fin
import math
from typing import Any, Dict, List, Optional, Sequence

from .catalog import DEFAULT_CATALOG, Catalog
from .facade import _to_number
from .pca import REVERSIBILITY_ORDER, evaluate_caveats
from .predicates import _js_number_string, evaluate_predicates
from .risk import admit, cost, leak

__all__ = ["simulate", "lint_policy"]


def _finite(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


def _clamp01(x: Any) -> Any:
    return x if x != x else max(0, min(1, x))


def _risk_of(policy: Dict[str, Any], spec: Optional[Dict[str, Any]], params: Any) -> Any:
    kappa = policy["riskPolicy"]["kappa"]
    if policy.get("budgetModel") == "dollars" and spec and spec.get("amountField"):
        amt = _to_number(params if isinstance(params, dict) else {}, spec["amountField"])
        if fin(amt) and kappa > 0:
            return _clamp01(amt / kappa)
    return _clamp01(spec["blastRadius"] if spec else 0.8)


def simulate(policy: Dict[str, Any], actions: Sequence[Dict[str, Any]], catalog: Optional[Catalog] = None, start: Any = None) -> Dict[str, Any]:
    """Replay ``actions`` (``{"verb", "resource", "params"?, "at"?}``) against ``policy``. ``start`` is the start time in epoch ms
    (default 0): an action without ``at`` occurs at ``start + index``; the budget starts at the policy's ``bMax``. An action whose time
    is not a finite number is reported as denied, never skipped. A verb the catalog does not know is treated as irreversible.

    Returns ``{"results": [{"action", "outcome", "t"?, "r", "reason"?, "budgetAfter"}], "auto", "stepUp", "deny", "endBudget",
    "peakRisk", "autonomousRisk"}``."""
    cat = DEFAULT_CATALOG if catalog is None else catalog
    start = 0 if start is None else start
    rp = policy["riskPolicy"]
    timed = [(a, a["at"] if a.get("at") is not None else start + i) for i, a in enumerate(actions)]
    ordered = sorted((x for x in timed if _finite(x[1])), key=lambda x: x[1])  # stable, as the reference's sort
    budget: Dict[str, Any] = {"B": rp["bMax"], "tau": start, "asOf": start}
    recent: List[Any] = []
    results: List[Dict[str, Any]] = []
    peak: Any = 0
    autonomous: Any = 0
    for a, at in timed:
        if not _finite(at):
            results.append({"action": a, "outcome": "deny", "r": 1, "reason": "action has no finite time", "budgetAfter": budget["B"]})
    for a, at in ordered:
        spec = cat.get(a.get("verb"))
        params = a["params"] if a.get("params") is not None else {}
        cls = spec["reversibility"] if spec and spec.get("reversibility") is not None else "irreversible"
        r = _risk_of(policy, spec, a.get("params"))
        peak = math.nan if (peak != peak or r != r) else max(peak, r)
        pred = evaluate_predicates(policy["predicates"], {"action": {"verb": a.get("verb"), "resource": a.get("resource"), "params": params,
                                                                      "reversibility_class": cls}})
        ok, failed = (False, [])
        if pred["allowed"]:
            ok, failed = evaluate_caveats(policy["caveats"], {"now": at, "blast_radius": spec["blastRadius"] if spec and spec.get("blastRadius") is not None else 1,
                                                              "reversibility_class": cls, "recent_action_times": list(recent)})
        budget = leak(budget, at, rp["lambda"])
        if not pred["allowed"]:
            reason = pred.get("reason")
            results.append({"action": a, "outcome": "deny", "r": r, "reason": reason if reason is not None else "no predicate permits this action",
                            "budgetAfter": budget["B"]})
            continue
        if not ok:
            results.append({"action": a, "outcome": "deny", "r": r, "reason": "caveat(s) failed: %s" % ", ".join(failed), "budgetAfter": budget["B"]})
            continue
        adm = admit(r, budget, rp)
        if adm["t"] == 1 and adm["admit"]:
            budget = dict(budget, B=budget["B"] - cost(r, rp["kappa"]))
            autonomous += r
            recent.append(at)
            results.append({"action": a, "outcome": "auto", "t": 1, "r": r, "budgetAfter": budget["B"]})
        else:  # t=2 (guardian auto-cosign) and t=3 (human) are both a step-up in the planning view
            res = {"action": a, "outcome": "step_up", "t": adm["t"], "r": r, "budgetAfter": budget["B"]}
            if adm["needStepUp"]:
                res["reason"] = "requires tier %d" % adm["t"]
            results.append(res)
    count = lambda o: sum(1 for x in results if x["outcome"] == o)  # noqa: E731
    return {"results": results, "auto": count("auto"), "stepUp": count("step_up"), "deny": count("deny"), "endBudget": budget["B"],
            "peakRisk": peak, "autonomousRisk": autonomous}


def _sev(c: Any) -> int:
    return REVERSIBILITY_ORDER.index(c) if isinstance(c, str) and c in REVERSIBILITY_ORDER else -1


def lint_policy(policy: Dict[str, Any], catalog: Optional[Catalog] = None) -> List[Dict[str, str]]:
    """Static lints over a compiled policy, as ``[{"level", "code", "message"}]``: ``error`` is almost certainly a mistake (a limit that
    matches no granted action), ``warn`` a real risk worth a second look, ``info`` a notable but intentional property."""
    cat = DEFAULT_CATALOG if catalog is None else catalog
    lints: List[Dict[str, str]] = []
    granted = set()
    for s in policy["actions"]:
        granted.update([s.get("verb"), s.get("action")] + list(s.get("aliases") or []))
    for key in policy["inputLimits"]:
        if key not in granted:
            lints.append({"level": "error", "code": "limit-unmatched", "message": "limit for '%s' matches no granted action" % key})
    for spec in policy["actions"]:
        verb = spec.get("verb")
        pred = next((p for p in policy["predicates"] if p.get("verb") == verb), None)
        broad = not (pred and pred.get("resource")) or pred["resource"] == "*"
        if spec.get("amountField") and not policy["limits"].get(verb):
            lints.append({"level": "warn", "code": "money-unbounded",
                          "message": "money action '%s' has no per-call limit — spend is bounded only by the trust budget" % verb})
        if broad and _sev(spec.get("reversibility")) >= _sev("rate_limited"):
            lints.append({"level": "warn", "code": "broad-resource",
                          "message": "'%s' (%s) matches ANY resource — consider a resource prefix" % (verb, spec.get("reversibility"))})
        if not cat.get(verb):
            lints.append({"level": "info", "code": "uncatalogued",
                          "message": "'%s' is not in the catalog — treated conservatively (irreversible, high blast radius)" % verb})
    rp = policy["riskPolicy"]
    theta2, b_max, kappa = rp["theta2"], rp["bMax"], rp["kappa"]
    if theta2 >= 1:
        irrev = any(_sev(s.get("reversibility")) >= _sev("irreversible") for s in policy["actions"])
        lints.append({"level": "warn" if irrev else "info", "code": "no-step-up-band",
                      "message": "theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted%s"
                                 % (" — including irreversible actions" if irrev else "")})
    if kappa > 0 and b_max / kappa > 100:
        lints.append({"level": "warn", "code": "large-autonomy",
                      "message": "autonomous bound is %s× a max-risk action between human co-signs"
                                 % _js_number_string(float(math.floor(b_max / kappa + 0.5)))})
    return lints
