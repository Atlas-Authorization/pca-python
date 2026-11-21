"""A replayable debugger over the pure decision core (``atlas_pca.policy_vm.decide``): ``explain_risk`` decomposes the risk score into its
six weighted terms, ``explain_decision`` explains a decide input, ``apply_delta`` / ``counterfactual`` re-run the core under edits and
report which edits flip the outcome, ``audit_pcactn`` re-verifies a proof-carrying action and attaches the explanation.

Nothing here decides anything: every number comes from the same ``decide`` the verifier runs. Inputs and reports are dicts with the
reference member names. This ``explain_decision`` explains a Policy VM decide input; it is not ``atlas_pca.explain.explain_decision``."""
from __future__ import annotations

from ._fin import fin
from typing import Any, Dict, List, Optional

from .analyzer_js import js_json
from .authorize import read_envelope
from .pca import ts_check_name, ts_reason, verify_pcactn_core
from .policy_vm import _js_truthy, decide
from .predicates import _js_string
from .risk import DEFAULT_RISK_POLICY, WORST, age_since_touch, cost, leak, plan_geodesic, recharge, recharge_full, safety_bound

__all__ = ["explain_risk", "explain_decision", "apply_delta", "counterfactual", "audit_pcactn"]

_TERMS = (("semanticDistance", "alpha", False), ("reversibility", "beta", True), ("blastRadius", "gamma", False), ("taint", "delta", False),
          ("confidence", "epsilon", True), ("age", "zeta", False))
_ZERO_WEIGHTS = {"alpha": 0, "beta": 0, "gamma": 0, "delta": 0, "epsilon": 0, "zeta": 0}
_NOT_GIVEN: Any = object()


def _fin(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


def _clamp01(x: Any) -> Any:
    return 0 if x < 0 else 1 if x > 1 else x


def _wt(x: Any) -> Any:
    return x if _fin(x) and x > 0 else 0


def explain_risk(inputs: Dict[str, Any], weights: Dict[str, Any], r_floor: Any = 0) -> Dict[str, Any]:
    """The risk score as its six terms, in the fixed order semanticDistance, reversibility, blastRadius, taint, confidence, age:
    ``{"inputs", "weights", "terms": [{"term", "weight", "input", "effective", "contribution", "inverted"}], "rawSum", "rScore", "rFloor",
    "r"}`` with ``r = max(rScore, rFloor)``. A missing or non-finite input counts as its worst value, a non-positive weight as 0."""
    floor = r_floor if _fin(r_floor) else 0
    terms = []
    raw: Any = 0
    for name, wname, inverted in _TERMS:
        v = inputs.get(name)
        x = _clamp01(v) if _fin(v) else WORST[name]
        w = _wt(weights.get(wname))
        eff = 1 - x if inverted else x
        terms.append({"term": name, "weight": w, "input": x, "effective": eff, "contribution": w * eff, "inverted": inverted})
        raw = raw + w * eff
    score = _clamp01(raw)
    return {"inputs": inputs, "weights": weights, "terms": terms, "rawSum": raw, "rScore": score, "rFloor": _clamp01(floor),
            "r": max(score, _clamp01(floor))}


def _resolve(inp: Dict[str, Any], env: Dict[str, Any]) -> tuple:
    """The risk inputs, floor and leaked budget exactly as ``decide`` resolves them."""
    leaked = leak(inp["budget"], inp.get("now"), env["risk_policy"]["lambda"])
    given = inp.get("risk") if isinstance(inp.get("risk"), dict) else {}
    inputs = dict(WORST)
    inputs.update({k: given[k] for k in WORST if _fin(given.get(k))})
    plan = inp.get("plan")
    if isinstance(plan, list) and "semanticDistance" not in given:
        goal = inp["goalNodeId"] if inp.get("goalNodeId") is not None else (plan[-1].get("id") if plan and isinstance(plan[-1], dict) else None)
        inputs["semanticDistance"] = plan_geodesic(plan, inp["nodeId"], goal) if "nodeId" in inp and goal is not None else 1
    if "age" not in given:
        inputs["age"] = age_since_touch(leaked, inp.get("now"), inp["ageHorizonMs"]) if "ageHorizonMs" in inp else \
            age_since_touch(leaked, inp.get("now"))
    floor = inp.get("rFloor")
    return inputs, (min(1, max(0, floor)) if _fin(floor) else 0), leaked


def explain_decision(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Explain one decide input: ``{"decision", "risk", "requiredThreshold", "t", "autoAllow", "needStepUp", "releaseGuardianShare",
    "budget": {"before", "leaked", "after", "cost", "safetyBound"}, "reasons", "envelopeValid"}``. Without a readable envelope the risk
    explanation has no terms and carries the (worst) score the decision reports."""
    decision = decide(inp)
    env = read_envelope(inp["grant"])
    pol = env["risk_policy"] if env else DEFAULT_RISK_POLICY
    if env:
        inputs, floor, leaked = _resolve(inp, env)
        risk = explain_risk(inputs, pol["weights"], floor)
    else:
        leaked = inp.get("budget")
        r = decision["r"]
        risk = {"inputs": dict(WORST), "weights": dict(_ZERO_WEIGHTS), "terms": [], "rawSum": r, "rScore": r, "rFloor": 0, "r": r}
    return {"decision": decision, "risk": risk, "requiredThreshold": decision["requiredThreshold"], "t": decision["requiredThreshold"]["t"],
            "autoAllow": decision["admit"], "needStepUp": decision["needStepUp"], "releaseGuardianShare": decision["releaseGuardianShare"],
            "budget": {"before": inp.get("budget"), "leaked": leaked, "after": decision["budget"], "cost": cost(decision["r"], pol["kappa"]),
                       "safetyBound": safety_bound(pol)},
            "reasons": decision["reasons"], "envelopeValid": env is not None}


# ---- counterfactuals --------------------------------------------------------------------------------------------------------

def _describe(d: Dict[str, Any]) -> str:
    if _js_truthy(d.get("label")):
        return d["label"]
    parts: List[str] = []
    cosign = d.get("humanCosign")
    if _js_truthy(cosign):
        parts.append("human re-confirms goal (B←Bmax)" if isinstance(cosign, dict) and cosign.get("full") else "human co-signs (B+ρ)")
    for member, prefix in (("risk", ""), ("budget", "budget.")):
        if isinstance(d.get(member), dict):
            parts.extend("%s%s=%s" % (prefix, k, _js_string(v)) for k, v in d[member].items())
    if "rFloor" in d:
        parts.append("caution=%s" % _js_string(d["rFloor"]))
    if "now" in d:
        parts.append("now=%s" % _js_string(d["now"]))
    if isinstance(d.get("caveatContext"), dict):
        parts.extend("ctx.%s=%s" % (k, js_json(v)) for k, v in d["caveatContext"].items())
    return ", ".join(parts) if parts else "no-op"


def apply_delta(inp: Dict[str, Any], d: Dict[str, Any]) -> Dict[str, Any]:
    """The decide input after a counterfactual edit ``{"label"?, "risk"?, "budget"?, "rFloor"?, "now"?, "caveatContext"?,
    "humanCosign"?: True | {"full"?: bool}}``: members of ``risk`` / ``budget`` / ``caveatContext`` override the input's, and a human
    co-sign recharges the budget (``+rho``, or to ``bMax`` when ``full``) at the edited time. The input is not changed."""
    now = d["now"] if d.get("now") is not None else inp.get("now")
    budget = dict(inp.get("budget") or {}, **(d.get("budget") or {}))
    cosign = d.get("humanCosign")
    if _js_truthy(cosign):
        env = read_envelope(inp["grant"])
        pol = env["risk_policy"] if env else DEFAULT_RISK_POLICY
        full = isinstance(cosign, dict) and cosign.get("full") is True
        budget = recharge_full(budget, pol["bMax"], now) if full else recharge(budget, pol["rho"], pol["bMax"], now)
    nxt = dict(inp)
    if now is not None or "now" in inp:
        nxt["now"] = now
    nxt["budget"] = budget
    nxt["risk"] = dict(inp.get("risk") or {}, **(d.get("risk") or {}))
    nxt["caveatContext"] = dict(inp.get("caveatContext") or {}, **(d.get("caveatContext") or {}))
    if "rFloor" in d:
        nxt["rFloor"] = d["rFloor"]
    return nxt


def counterfactual(inp: Dict[str, Any], deltas: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Re-run the decision under each edit: ``{"baseline", "outcomes": [{"label", "delta", "explanation", "flipsAllow", "allow",
    "thresholdDirection": raised | lowered | same, "changesThreshold", "t", "rDelta"}], "flipping": [label], "thresholdChanging": [label]}``."""
    baseline = explain_decision(inp)
    outcomes = []
    for d in deltas:
        ex = explain_decision(apply_delta(inp, d))
        direction = "raised" if ex["t"] > baseline["t"] else "lowered" if ex["t"] < baseline["t"] else "same"
        outcomes.append({"label": _describe(d), "delta": d, "explanation": ex, "flipsAllow": ex["autoAllow"] != baseline["autoAllow"],
                         "allow": ex["autoAllow"], "thresholdDirection": direction, "changesThreshold": direction != "same", "t": ex["t"],
                         "rDelta": ex["risk"]["r"] - baseline["risk"]["r"]})
    return {"baseline": baseline, "outcomes": outcomes, "flipping": [o["label"] for o in outcomes if o["flipsAllow"]],
            "thresholdChanging": [o["label"] for o in outcomes if o["changesThreshold"]]}


# ---- audit -------------------------------------------------------------------------------------------------------------------

_NO_AUDIENCE = "PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)"
_HOOK_CHECKS = ("taint_gate", "attestation", "threshold", "revocation")


def _verify_result(v: Any, p: Any, audience: Any) -> Dict[str, Any]:
    """A core verdict in the reference's report form: every check ``pass`` / ``fail`` / ``not-enforced`` under the reference's names."""
    checks = {ts_check_name(k): "pass" if ok is True else "fail" for k, ok in v.checks.items()}
    reason = ts_reason(v.reason)
    if set(checks) != {"wire"}:
        for name in v.not_enforced:
            checks[name] = "not-enforced"
        if audience is None and checks.get("audience") == "pass":
            checks["audience"] = "not-enforced"  # the explicit opt-out accepts any audience: reported, never a pass
        if audience is _NOT_GIVEN and checks.get("audience") == "fail" and isinstance(reason, str) and reason.startswith("audience: "):
            reason = "audience: " + _NO_AUDIENCE
        for name in _HOOK_CHECKS:
            checks.setdefault(name, "not-enforced")
        if isinstance(p, dict) and "bond_ref" in p:
            checks.setdefault("bond", "not-enforced")
    out: Dict[str, Any] = {"allow": v.allow, "checks": checks}
    if reason is not None:
        out["reason"] = reason
    return out


def audit_pcactn(p: Any, inp: Dict[str, Any], grant: Dict[str, Any], now_epoch: Optional[int] = None, audience: Any = _NOT_GIVEN,
                 insecure_skip_plan_root_check: bool = False, attestation_hook: Any = None, zk_hook: Any = None) -> Dict[str, Any]:
    """Re-verify a proof-carrying action with the core verifier and attach the explanation of its decide input: ``{"verify":
    {"allow", "checks", "reason"?}, "explanation"}``. ``audience``: this verifier's id; an explicit None accepts any audience (reported
    ``not-enforced``); not given, a PCActn that carries a signed ``aud`` fails the audience check."""
    verdict = verify_pcactn_core(p, grant, now=now_epoch, audience=None if audience is _NOT_GIVEN else audience,
                                 accept_any_audience=audience is None, insecure_skip_plan_root_check=insecure_skip_plan_root_check,
                                 attestation_hook=attestation_hook, zk_hook=zk_hook)
    return {"verify": _verify_result(verdict, p, audience), "explanation": explain_decision(inp)}
