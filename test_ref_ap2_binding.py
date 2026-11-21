"""Differential replay of atlas_pca.ap2.verify_pca_binding against vectors generated from the TypeScript reference (@atlasauth/pca-ap2).
The policy engine is injected: `ref_decide` below runs the reference decision steps (envelope predicates, caveats, risk, budget) over the
native predicate, caveat and risk modules."""
import math

from atlas_pca import ap2
from atlas_pca.authorize import evaluate_agent_caveats, read_envelope
from atlas_pca.pca import verify_chain
from atlas_pca.predicates import evaluate_predicates
from atlas_pca.risk import decide_risk
from base_oracle import load_ref, run

COUNT, CASES = load_ref("ap2-java-extra")


def _denied(reason, budget):
    return {"releaseGuardianShare": False, "requiredThreshold": {"t": 3, "proof": "strong", "optimisticAllowed": False}, "r": 1, "admit": False,
            "needStepUp": True, "reasons": [reason], "budget": budget}


def ref_decide(inp):
    grant, action, risk, budget, now = inp["grant"], inp["action"], inp["risk"], inp["budget"], inp["now"]
    env = read_envelope(grant)
    if env is None:
        return _denied("grant carries no valid envelope", budget)
    if not isinstance(now, (int, float)) or not math.isfinite(now):
        return _denied("invalid decision time", budget)
    ok, why = verify_chain([grant], grant.get("issuer"))
    if not ok:
        return _denied("capability chain unverified: %s" % why, budget)
    cc = inp.get("caveatContext") or {}
    cctx = {"now": now, "blast_radius": risk.get("blastRadius"), "reversibility_class": cc.get("reversibilityClass")}
    if cc.get("recentActionTimes") is not None:
        cctx["recent_action_times"] = cc["recentActionTimes"]
    reasons = []
    pr = evaluate_predicates(env["predicates"], action)
    if not pr.get("allowed"):
        reasons.append(pr.get("reason") or "action not permitted by envelope predicates")
    ok1, failed1 = evaluate_agent_caveats(env["caveats"], cctx, action)
    if not ok1:
        reasons.append("caveat(s) not satisfied: %s" % ", ".join(failed1))
    root = [c for c in grant["caveats"] if not (isinstance(c, dict) and c.get("type") == "envelope")]
    ok2, failed2 = evaluate_agent_caveats(root, cctx, action)
    if not ok2:
        reasons.append("root caveat(s) not satisfied: %s" % ", ".join(failed2))
    d = decide_risk(env["risk_policy"], risk, budget, now, pr.get("allowed") is True and ok1 and ok2,
                    reversibility_class=cctx["reversibility_class"])
    return {"releaseGuardianShare": d["release"], "requiredThreshold": d["threshold"], "r": d["r"], "admit": d["admit"],
            "needStepUp": d["needStepUp"], "reasons": reasons + d["reasons"], "budget": d["budget"]}


def _hook(v):
    return lambda _ctx: v


def verify_pca_binding(i):
    i = dict(i)
    if "hooks" in i and i["hooks"] is not None:
        i["hooks"] = {k: _hook(v) for k, v in i["hooks"].items()}
    fr = (i.get("enforce") or {}).get("freshness")
    if fr is not None:
        i["enforce"] = {"freshness": {"max_age_ms": fr.get("maxAgeMs")}}
    return ap2.verify_pca_binding(i, ref_decide)


def test_ap2_pca_binding_matches_reference():
    assert set(CASES) == {"verifyPcaBinding"}
    ran, _ = run(CASES["verifyPcaBinding"], verify_pca_binding)
    assert ran == COUNT
