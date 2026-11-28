"""The policy VM entry point (the TypeScript ``policy-vm``): :func:`decide` turns one action, the grant and its delegation chain, the risk
inputs and the trust budget into a release decision. :func:`authorize` runs the same steps inside its pipeline; this is the standalone
function for hosts that decide outside it (``atlas_pca.authzen``, ``atlas_pca.mpc`` party policies, ``atlas_pca.payments`` take it as their
injected ``decide``).

The input is a dict with the reference's member names: ``grant``, ``action`` (``{"action": {"verb", "resource", "params"?,
"reversibility_class"?}, "subject"?, "env"?}``), ``chain``?, ``plan``?, ``nodeId``?, ``goalNodeId``?, ``risk``?, ``budget``, ``now``,
``caveatContext``?, ``ageHorizonMs``?, ``rFloor``?, ``trustedRoot``?, ``pqPins``?, ``chainVerified``? and ``k1``?. The decision is
``{"releaseGuardianShare", "requiredThreshold", "r", "admit", "needStepUp", "reasons", "budget", "k1Bound"?}``. FAILS CLOSED: an unverified
chain, a missing envelope or any error is a denial."""
from ._fin import fin
from typing import Any, Dict, List, Optional

from .authorize import evaluate_agent_caveats, read_envelope, root_caveats
from .caveat_lang import evaluate_k1, is_k1_caveat
from .pca import DecideInputGrantRequired, verify_chain
from .predicates import evaluate_predicates
from .risk import decide_risk
from .safe_regex import with_regex_budget

__all__ = ["decide", "derive_decide_input", "resolve_reversibility_class", "DecideInputGrantRequired"]


_CAVEAT_CTX = {"blastRadius": "blast_radius", "reversibilityClass": "reversibility_class", "recentActionTimes": "recent_action_times",
                "delegationDepth": "delegation_depth"}


def _denied(reason: str, budget: Any) -> Dict[str, Any]:
    return {"releaseGuardianShare": False, "requiredThreshold": {"t": 3, "proof": "strong", "optimisticAllowed": False}, "r": 1, "admit": False,
            "needStepUp": True, "reasons": [reason], "budget": budget}


def resolve_reversibility_class(action: Any, plan: Any, node_id: Any) -> Optional[str]:
    """The action's own class, else its plan node's (never a guess: with no node named, no class)."""
    own = ((action or {}).get("action") or {}).get("reversibility_class") if isinstance(action, dict) else None
    if own is not None:
        return own
    if not isinstance(node_id, str) or not isinstance(plan, list):
        return None
    return next((n.get("reversibility_class") for n in plan if isinstance(n, dict) and n.get("id") == node_id), None)


def decide(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Decide one action (see the module doc). Total: never raises."""
    fallback = (inp.get("budget") if isinstance(inp, dict) else None) or {"B": 0, "tau": 0}
    try:
        return with_regex_budget(lambda: _decide(inp))
    except Exception as e:  # noqa: BLE001 - fail closed
        return _denied("policy evaluation error (fail closed): %s" % (str(e) or "unknown"), fallback)


def _decide(inp: Dict[str, Any]) -> Dict[str, Any]:
    grant, action, plan, risk, budget, now = inp["grant"], inp["action"], inp.get("plan"), inp.get("risk"), inp.get("budget"), inp.get("now")
    env = read_envelope(grant)
    if env is None:
        return _denied("grant carries no valid envelope", budget)
    if isinstance(now, bool) or not isinstance(now, (int, float)) or not fin(now):
        return _denied("invalid decision time", budget)
    if inp.get("chainVerified") is not True:
        chain_in = inp.get("chain")
        to_verify = chain_in if isinstance(chain_in, list) and len(chain_in) > 0 else [grant]
        ok, reason = verify_chain(to_verify, grant.get("issuer"), pq_pins=inp.get("pqPins"),
                                  trusted_root=inp.get("trustedRoot") if "trustedRoot" in inp else None)
        if not ok:
            return _denied("capability chain unverified: %s" % (reason or "invalid"), budget)
    pol = env["risk_policy"]
    reasons: List[str] = []
    pr = evaluate_predicates(env["predicates"], action)
    if not pr.get("allowed"):
        reasons.append(pr.get("reason") or "action not permitted by envelope predicates")
    node_id = inp.get("nodeId")
    chain = inp.get("chain")
    cctx: Dict[str, Any] = {"now": now, "action": action.get("action")}
    if isinstance(risk, dict) and risk.get("blastRadius") is not None:
        cctx["blast_radius"] = risk["blastRadius"]
    rev = resolve_reversibility_class(action, plan, node_id)
    if rev is not None:
        cctx["reversibility_class"] = rev
    for k, v in (inp.get("caveatContext") or {}).items():  # the reference's camelCase caveat context, overriding what was derived
        cctx[_CAVEAT_CTX.get(k, k)] = v
    rev = cctx.get("reversibility_class")
    chain_ok, extra = True, []
    if "chain" in inp:  # a null chain is present (and malformed), only an absent one is skipped
        if not isinstance(chain, list) or len(chain) == 0:
            chain_ok = False
            reasons.append("delegation chain is empty or malformed")
        else:
            cctx["delegation_depth"] = len(chain) - 1
            extra = chain[-1]["caveats"][len(grant["caveats"]):]
    ok, failed = evaluate_agent_caveats(env["caveats"], cctx, action)
    if not ok:
        reasons.append("caveat(s) not satisfied: %s" % ", ".join(failed))
    env_ok = ok
    leaf_src = chain[-1] if isinstance(chain, list) and chain else grant
    leaf_cv = leaf_src.get("caveats") if isinstance(leaf_src, dict) else None
    k1_in = inp.get("k1")
    use_k1 = (isinstance(leaf_cv, list) and any(is_k1_caveat(c) for c in leaf_cv)) or (isinstance(k1_in, dict) and "narrow" in k1_in)
    k1r = evaluate_k1(grant, chain, k1_in, {"now": now, "action": action.get("action")}) if use_k1 else None
    rc = root_caveats(grant)
    ok, failed = evaluate_agent_caveats([c for c in rc if not is_k1_caveat(c)] if isinstance(rc, list) else rc, cctx, action)
    if not ok:
        reasons.append("root caveat(s) not satisfied: %s" % ", ".join(failed))
    cv_ok = env_ok and ok
    ex = [c for c in extra if not is_k1_caveat(c)] + (k1r["plain"] if k1r else [])
    dok, failed = evaluate_agent_caveats(ex, cctx, action)
    if not dok:
        reasons.append("delegated caveat(s) not satisfied: %s" % ", ".join(failed))
    if k1r is not None and not k1r["ok"]:
        dok = False
        reasons.extend("caveat language: %s: %s" % (k1r["failed"][i], r) for i, r in enumerate(k1r["reasons"]))
    release = bool(pr.get("allowed")) and cv_ok and dok and chain_ok
    d = decide_risk(pol, risk, budget, now, release, reversibility_class=rev, plan=plan, node_id=node_id, goal_node_id=inp.get("goalNodeId"),
                    age_horizon_ms=inp.get("ageHorizonMs"), r_floor=inp.get("rFloor"))
    out = {"releaseGuardianShare": d["release"], "requiredThreshold": d["threshold"], "r": d["r"], "admit": d["admit"],
           "needStepUp": d["needStepUp"], "reasons": reasons + d["reasons"], "budget": d["budget"]}
    if k1r is not None:
        out["k1Bound"] = k1r["bound"]
    return out


def _js_truthy(v: Any) -> bool:
    return not (v is None or v is False or (isinstance(v, (int, float, str)) and (not v or v != v)))


def derive_decide_input(p: Dict[str, Any], *, grant: Any = None, risk: Any = None, budget: Any = None, now: Any = None, plan: Any = None,
                        params: Optional[dict] = None, chain: Any = None, pq_pins: Any = None, goal_node_id: Any = None, subject: Any = None,
                        env: Any = None, caveat_context: Any = None, age_horizon_ms: Any = None) -> Dict[str, Any]:
    """Assemble a decide input from a PCActn plus the resource server's context, so the caller and the verifier derive the action, node and
    chain identically. `grant` is REQUIRED: the grant from the verifier's OWN store (also the chain's trusted root); it is never defaulted
    from the presented chain. `params` must already be checked against ``action.params_digest``."""
    if not isinstance(grant, (dict, list)):  # an array is an object to the reference too; decide then denies it
        raise DecideInputGrantRequired()
    if p is None:
        raise TypeError("deriveDecideInput: no PCActn")
    p = p if isinstance(p, dict) else {}  # a scalar has none of the members read here
    a = p.get("action") if isinstance(p.get("action"), dict) else {}
    # an absent member stays absent (undefined in the reference, so the deny reason reads "undefined", not "null")
    inner: Dict[str, Any] = {k: a[k] for k in ("verb", "resource") if k in a}
    inner["params"] = params if params is not None else {}
    if "reversibility_class" in a:
        inner["reversibility_class"] = a["reversibility_class"]
    action: Dict[str, Any] = {"action": inner}
    if _js_truthy(subject):  # as the reference: an empty object counts, null / 0 / "" do not
        action["subject"] = subject
    if _js_truthy(env):
        action["env"] = env
    out: Dict[str, Any] = {"grant": grant, "trustedRoot": grant, "action": action,
                           "plan": plan, "nodeId": (p.get("plan") or {}).get("node_id") if isinstance(p.get("plan"), dict) else None,
                           "goalNodeId": goal_node_id, "risk": risk, "budget": budget, "now": now, "caveatContext": caveat_context,
                           "ageHorizonMs": age_horizon_ms}
    if chain is not None:
        out["chain"] = chain
    elif "cap_chain" in p:  # a null cap_chain is a present, malformed chain; an absent one leaves the member undefined
        out["chain"] = p["cap_chain"]
    if pq_pins is not None:
        out["pqPins"] = pq_pins
    return out
