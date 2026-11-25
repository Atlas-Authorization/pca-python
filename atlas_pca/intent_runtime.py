"""Runtime intent conformance: routing an admitted action by the map's posterior and the verb's reversibility, the judge
panel input, the intent-conformance attestation (IC-Att) and just-in-time consent. Native port of the TypeScript
reference (@atlasauth/pca-intent). A "learner" is any object with .omega, .harm, .acceptance(o), .admits_outcome(o) and
.is_vetoed(o); the signed-verdict threshold check is injected (the core has no semantic-threshold verifier)."""
from __future__ import annotations

from ._fin import fin, pow_eighths
import math
from typing import Any, Callable, Dict, List, Optional

from .intent_omega import DEFAULT_HARM, cell_of, harm_max, harm_of, js_max, js_min
from .intent_policy import outcome_to_action
from .intent_render import render_action
from .intent_v2 import _UNDEF
from .pca import hash_canonical, params_digest

IC_ATT_DOMAIN = "atlas-pca/intent-ic-att/v1"

DEFAULT_BOND_POLICY = {"floor": 1, "k": 1, "maxOpenClaims": 100, "maxOpenAmount": math.inf}
_MICROS = 1000000
_MAX_SAFE_MICROS = 1e15


def _quantize_up(x: float) -> float:
    if not fin(x) or x <= 0:
        return x
    scaled = x * _MICROS
    if scaled > _MAX_SAFE_MICROS:
        return x
    r = math.floor(scaled + 0.5)
    m = r if (r / _MICROS == x or abs(scaled - r) <= 1e-3) else math.ceil(scaled)
    return m / _MICROS


def _curve_component(curve: Any, k: float, e: float) -> float:
    kind = curve.get("kind") if isinstance(curve, dict) else None
    if not curve or kind == "linear":
        return k * e
    if kind == "power":
        g = curve.get("gamma")
        if not (isinstance(g, (int, float)) and fin(g) and g >= 1):
            raise ValueError("bondAmount: power curve requires finite gamma >= 1")
        return k * pow_eighths(e, g)
    tiers = curve.get("tiers")
    if not isinstance(tiers, list) or len(tiers) == 0:
        raise ValueError("bondAmount: piecewise curve requires at least one tier")
    acc = 0.0
    prev_up = 0
    prev_marginal = 0
    for t in tiers:
        up, mk = t["upTo"], t["marginalK"]
        if not (fin(up) and up > prev_up) and up != math.inf:
            raise ValueError("bondAmount: piecewise tier `upTo` must be strictly increasing")
        if not (fin(mk) and mk >= 0):
            raise ValueError("bondAmount: piecewise `marginalK` must be a finite number >= 0")
        if mk < prev_marginal:
            raise ValueError("bondAmount: piecewise marginal rates must be non-decreasing (convex)")
        width = min(e, up) - prev_up
        if width > 0:
            acc += width * mk
        prev_up = up
        prev_marginal = mk
        if e <= up:
            break
    if e > prev_up:
        acc += (e - prev_up) * prev_marginal
    return k * acc


def bond_amount(policy: dict, exposure: float) -> float:
    """max(floor, curve(k, exposure)) snapped up onto the micro grid; a non-finite or non-positive exposure gives the floor."""
    e = exposure if fin(exposure) and exposure > 0 else 0
    return _quantize_up(js_max(policy["floor"], _curve_component(policy.get("curve"), policy["k"], e)))


def _vs(l: Any, verb: str) -> Optional[dict]:
    return next((v for v in l.omega["verbs"] if v["verb"] == verb), None)


def route_action(l: Any, o: dict, opts: Optional[dict] = None) -> dict:
    """deny / allow / optimistic / jit-consent for an action the grant already admits."""
    opts = opts or {}
    vs = _vs(l, o["verb"])
    if vs is None or cell_of(vs, o) is None:
        return {"route": "deny", "p": 0, "inGrant": False, "vetoed": False, "reversibility": vs["reversibility"] if vs else "unknown",
                "harm": 0, "risk": 1, "judges": False, "reason": "outside the Intent Map's outcome space"}
    p = l.acceptance(o)
    in_grant = l.admits_outcome(o)
    vetoed = l.is_vetoed(o)
    harm = harm_of(vs, o, l.harm)
    h_max = opts.get("hMax")
    if h_max is None:
        h_max = harm_max(l.omega, l.harm)
    risk = min(1, max(0, ((1 - p) * harm) / (h_max if h_max > 0 else 1)))
    theta2 = opts.get("theta2")
    if theta2 is None:
        theta2 = 0.5
    base = {"p": p, "inGrant": in_grant, "vetoed": vetoed, "reversibility": vs["reversibility"], "harm": harm, "risk": risk}
    if not in_grant:
        return {**base, "route": "deny", "judges": False,
                "reason": "the cell was vetoed by a runtime divergence" if vetoed else "outside the conservative grant (p_n < τ)"}
    judges = vs["reversibility"] == "irreversible" or p < 1 - 1e-12 or risk >= theta2
    if vs["reversibility"] == "irreversible":
        return {**base, "route": "jit-consent", "judges": judges, "reason": "irreversible: just-in-time consent on the rendered action"}
    if judges:
        return {**base, "route": "optimistic", "judges": judges, "bond": bond_amount(opts.get("bondPolicy") or DEFAULT_BOND_POLICY, harm),
                "reason": "unconfirmed region (p_n < 1): bonded claim + judges" if p < 1 - 1e-12 else "risk ≥ θ₂: bonded claim + judges"}
    return {**base, "route": "allow", "judges": False, "reason": "confirmed region, reversible, low risk"}


# ---- L3: the judge panel input and the IC-Att ---------------------------------------------------------------------

def pcactn_action_of(vs: dict, o: dict) -> dict:
    a = outcome_to_action(vs, o)
    return {"verb": a["verb"], "resource": a["resource"], "params_digest": params_digest(a.get("params") or {}), "reversibility_class": vs["reversibility"]}


def action_digest(action: dict) -> str:
    return hash_canonical(action)


def judge_input_of(l: Any, o: dict, ctx: dict) -> dict:
    vs = _vs(l, o["verb"])
    if vs is None:
        raise ValueError("judgeInputOf: no verb %s in Ω" % o["verb"])
    return {**ctx, "renderedAction": render_action(vs, o["values"]), "p": l.acceptance(o), "reversibility": vs["reversibility"],
            "actionDigest": action_digest(pcactn_action_of(vs, o))}


def calibration_digest(c: dict) -> str:
    return hash_canonical({"d": "atlas-pca/intent-calibration/v1", "alpha": c["alpha"],
                           "samples": [{"score": s["score"], "faithful": s["faithful"]} for s in c["samples"]]})


def _to_ppm(x: float) -> Optional[int]:
    return int(math.floor(x * 1000000 + 0.5)) if isinstance(x, (int, float)) and fin(x) else None


def intent_conformance_attestation(input_: dict, verdicts: List[dict], opts: dict, verify: Callable[[List[dict], dict], dict],
                                   verdict_digest: Callable[[dict], str] = hash_canonical) -> dict:
    """Verify a panel's verdicts for one action with the injected threshold verifier and produce the IC-Att. The verifier
    takes (verdicts, {judgeKeys, k, goalCommitment, actionDigest, calibration?, attestation?}) and returns
    {ok, agreeCount, aggregateScore, cutoff?, reason?}."""
    vo = {"judgeKeys": opts["judgeKeys"], "k": opts["k"], "goalCommitment": input_["goalCommitment"], "actionDigest": input_["actionDigest"]}
    if opts.get("calibration"):
        vo["calibration"] = opts["calibration"]
    if opts.get("attestation"):
        vo["attestation"] = opts["attestation"]
    r = verify(verdicts, vo)
    att = {"v": 1, "kind": "pca-ic-att", "intent_ref": input_["intentRef"], "map_digest": input_["mapDigest"],
           "action_digest": input_["actionDigest"], "goal_commitment": input_["goalCommitment"],
           "verdict_digests": sorted(verdict_digest(v) for v in verdicts),
           "calibration_digest": calibration_digest(opts["calibration"]) if opts.get("calibration") else None,
           "k": opts["k"], "ok": r["ok"], "agree_count": r["agreeCount"],
           "aggregate_score_ppm": _to_ppm(r["aggregateScore"]) or 0,
           "cutoff_ppm": None if r.get("cutoff") is None else _to_ppm(r["cutoff"])}
    if r.get("reason"):
        att["reason"] = r["reason"]
    return att


def ic_att_digest(a: dict) -> str:
    return hash_canonical({"d": IC_ATT_DOMAIN, "a": a})


def verify_ic_att(att: dict, input_: dict, verdicts: List[dict], opts: dict, verify: Callable[[List[dict], dict], dict]) -> dict:
    """Re-verify an IC-Att from the verdicts it names (a relying party never trusts the ok bit)."""
    again = intent_conformance_attestation(input_, verdicts, opts, verify)
    problems: List[str] = []
    if ic_att_digest(again) != ic_att_digest(att):
        problems.append("IC-Att does not match the recomputation from its verdicts")
    if not again["ok"]:
        problems.append("panel does not pass: %s" % (again.get("reason") or "unknown"))
    return {"ok": len(problems) == 0, "problems": problems}


def semantic_risk_contribution(score: float) -> float:
    if not (isinstance(score, (int, float)) and fin(score)):
        return 1
    r = 1 - score
    return 0 if r < 0 else 1 if r > 1 else r


def fold_semantic_risk(r: float, att: dict) -> float:
    """The monotone risk fold: r := max(r, 1 - aggregateScore). Never lowers r."""
    ppm = att.get("aggregate_score_ppm", _UNDEF)
    score = ppm / 1000000 if isinstance(ppm, (int, float)) and not isinstance(ppm, bool) else math.nan
    return js_max(r, semantic_risk_contribution(score))


# ---- L4: just-in-time consent -------------------------------------------------------------------------------------

def jit_consent_request(l: Any, o: dict, ctx: dict) -> dict:
    vs = _vs(l, o["verb"])
    if vs is None:
        raise ValueError("jitConsentRequest: no verb %s in Ω" % o["verb"])
    p = l.acceptance(o)
    return {"v": 1, "kind": "pca-intent-jit", "intent_ref": ctx["intentRef"], "map_digest": ctx["mapDigest"], "verb": o["verb"],
            "values": dict(o["values"]), "reversibility": vs["reversibility"], "p_ppm": int(math.floor(p * 1000000 + 0.5)),
            "text": "%s This cannot be undone. Approve?" % render_action(vs, o["values"])}


def jit_consent_digest(r: dict) -> str:
    return hash_canonical({"d": "atlas-pca/intent-jit/v1", "r": r})


def record_jit_decision(l: Any, req: dict, decision: str) -> Dict[str, Any]:
    """Record the principal's JIT decision as a runtime observation: approve -> y = 1 (widens the grant only through the
    posterior), deny -> y = 0 and the cell is vetoed."""
    from .intent_mapkit import apply_divergence
    return apply_divergence(l, {"verb": req["verb"], "values": req["values"]}, 1 if decision == "approve" else 0)


def check_intent_conformance(panel: Any, input_: dict, opts: dict, verify: Callable[[List[dict], dict], dict]) -> dict:
    """Ask the panel (``panel.verdicts(input)``) and attest (the hook form): ``{"att", "verdicts"}``."""
    verdicts = panel.verdicts(input_)
    return {"att": intent_conformance_attestation(input_, verdicts, opts, verify), "verdicts": verdicts}


async def check_intent_conformance_async(panel: Any, input_: dict, opts: dict, verify: Callable[[List[dict], dict], dict]) -> dict:
    """:func:`check_intent_conformance` for a panel whose ``verdicts`` is a coroutine function."""
    verdicts = panel.verdicts(input_)
    if hasattr(verdicts, "__await__"):
        verdicts = await verdicts
    return {"att": intent_conformance_attestation(input_, verdicts, opts, verify), "verdicts": verdicts}
