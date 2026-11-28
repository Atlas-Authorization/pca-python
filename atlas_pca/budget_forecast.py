"""Budget forecaster and policy recommender: how the trust budget drains over a planned action sequence under a compiled policy, when the
first human co-sign is forced and how many the plan needs; and, inversely, the ``kappa`` / ``bMax`` for a target level of autonomy.
Composes the simulator (``atlas_pca.policy_sim``) and the budget algebra. Pure."""
from __future__ import annotations

from ._fin import fin
from typing import Any, Dict, Optional, Sequence

from .analyzer_js import to_fixed
from .catalog import Catalog
from .policy_sim import simulate
from .predicates import _js_number_string
from .risk import safety_bound

__all__ = ["forecast", "recommend_policy", "autonomy_bound_of"]


def forecast(policy: Dict[str, Any], plan: Sequence[Dict[str, Any]], start: Any = None, catalog: Optional[Catalog] = None) -> Dict[str, Any]:
    """Forecast ``plan`` (``[{"verb", "resource", "params"?, "at"?}]``) against ``policy``: ``{"steps": [{"verb", "resource", "outcome",
    "r", "budgetAfter"}], "firstStepUpAt"?, "autonomousRisk", "forcesCosign", "cosignsNeeded", "endBudget"}``. A verb unknown to a
    given ``catalog`` fails closed; it does not fall back to the default catalog."""
    rep = simulate(policy, plan, catalog=catalog, start=start)
    steps = [{"verb": r["action"].get("verb"), "resource": r["action"].get("resource"), "outcome": r["outcome"], "r": r["r"],
              "budgetAfter": r["budgetAfter"]} for r in rep["results"]]
    out: Dict[str, Any] = {"steps": steps}
    first = next((i for i, s in enumerate(steps) if s["outcome"] == "step_up"), -1)
    if first >= 0:
        out["firstStepUpAt"] = first
    out.update(autonomousRisk=rep["autonomousRisk"], forcesCosign=rep["stepUp"] > 0, cosignsNeeded=rep["stepUp"], endBudget=rep["endBudget"])
    return out


def _finite(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


def recommend_policy(target_actions: Any, per_action_risk: Any, kappa: Any = None) -> Dict[str, Any]:
    """``kappa`` / ``bMax`` so an agent can take ``target_actions`` autonomous actions of typical risk ``per_action_risk`` (clamped to
    [1e-6, 1]) between human co-signs: ``bMax = target_actions * per_action_risk * kappa`` (``kappa`` defaults to 1). Returns
    ``{"kappa", "bMax", "autonomousBound", "rationale"}``; raises ValueError on a non-finite input or a non-positive ``kappa``."""
    kappa = 1 if kappa is None else kappa
    if not _finite(kappa) or kappa <= 0:
        raise ValueError("recommendPolicy: kappa must be a positive finite number")
    if not _finite(target_actions) or not _finite(per_action_risk):
        raise ValueError("recommendPolicy: targetActions and perActionRisk must be finite numbers")
    r = max(1e-6, min(1, per_action_risk))
    n = max(0, target_actions)
    b_max = n * r * kappa
    return {"kappa": kappa, "bMax": b_max, "autonomousBound": b_max / kappa,
            "rationale": "Σr ≤ bMax/κ = %s ≥ %s×%s actions before a human co-sign"
                         % (to_fixed(b_max / kappa, 3), _js_number_string(float(n)), to_fixed(r, 3))}


def autonomy_bound_of(p: Dict[str, Any]) -> Any:
    """The proven autonomous bound of a risk policy (``bMax / kappa`` risk units; 0 without a positive ``kappa``)."""
    kappa = p.get("kappa")
    if isinstance(kappa, bool) or not isinstance(kappa, (int, float)) or not kappa > 0:
        return 0
    return safety_bound(p)
