"""Fraud proofs and one-shot dispute adjudication for bonded optimistic claims (the TypeScript ``optimistic``): :func:`verify_fraud_proof`
RE-RUNS the policy VM on the server-held frozen open-time snapshot under the grant the verifier trusts, and :func:`adjudicate_dispute`
re-adjudicates with an objective oracle's authoritative value substituted for the single disputed input. A slash is never authorized by a
challenger's assertion. Both are total (never raise) and FAIL CLOSED. Snapshots are decide inputs (:mod:`atlas_pca.policy_vm`)."""
from ._fin import fin
import copy
import json
from typing import Any, Dict, Optional

from .optimistic import IRREVERSIBLE_CLASS
from .policy_vm import decide

__all__ = ["DEFAULT_R_MARGIN", "file_fraud_proof", "verify_fraud_proof", "adjudicate_dispute", "freeze_open_snapshot"]

DEFAULT_R_MARGIN = 1e-9
_INPUTS = ("reversibility_class", "reversibility", "blastRadius", "semanticDistance")


def _fin(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)


def _fixed3(x: float) -> str:
    from .analyzer_js import to_fixed
    return to_fixed(x, 3)


def _num_s(x: Any) -> str:
    from .predicates import _js_number_string
    return _js_number_string(float(x)) if _fin(x) else str(x)


def verify_fraud_proof(claim: dict, proof: Any, grant: dict, open_snapshot: Any) -> Dict[str, Any]:
    """Independently verify a fraud proof against a bonded claim: ``{"fraudulent", "slashBondRef"?, "reason"}``."""
    try:
        if not isinstance(proof, dict):
            return {"fraudulent": False, "reason": "malformed fraud proof"}
        if proof.get("pcactn_digest") != claim.get("pcactn_digest"):
            return {"fraudulent": False, "reason": "fraud proof targets a different PCActn than the claim"}
        if proof.get("bond_ref") != claim.get("bond_ref"):
            return {"fraudulent": False, "reason": "fraud proof names a different bond than the claim"}
        if not isinstance(open_snapshot, dict):
            return {"fraudulent": False, "reason": "no frozen open-time snapshot supplied; cannot judge the claim"}
        rec = decide(dict(open_snapshot, grant=grant))
        summary = {"releaseGuardianShare": rec["releaseGuardianShare"], "r": rec["r"], "optimisticAllowed": rec["requiredThreshold"]["optimisticAllowed"]}
        d = proof.get("decision") if isinstance(proof.get("decision"), dict) else {}
        if summary["releaseGuardianShare"] != d.get("releaseGuardianShare") or summary["optimisticAllowed"] != d.get("optimisticAllowed") \
                or not (abs(summary["r"] - d["r"]) <= 1e-9):
            return {"fraudulent": False, "reason": "proof decision does not match an independent recomputation"}
        margin = max(0, proof["r_margin"]) if _fin(proof.get("r_margin")) else DEFAULT_R_MARGIN
        snap_class = (((open_snapshot.get("action") or {}).get("action")) or {}).get("reversibility_class")
        irreversible = claim.get("reversibility_class") == IRREVERSIBLE_CLASS or snap_class == IRREVERSIBLE_CLASS
        ref = claim.get("bond_ref")
        if irreversible:
            return {"fraudulent": True, "slashBondRef": ref, "reason": "irreversible action is ineligible for the optimistic path"}
        if not summary["releaseGuardianShare"]:
            return {"fraudulent": True, "slashBondRef": ref, "reason": "Policy VM denies the action: %s" % ("; ".join(rec["reasons"]) or "not compliant")}
        if not summary["optimisticAllowed"]:
            return {"fraudulent": True, "slashBondRef": ref, "reason": "optimistic path not allowed at real r=%s" % _fixed3(summary["r"])}
        if summary["r"] > claim["claimed_r"] + margin:
            return {"fraudulent": True, "slashBondRef": ref,
                    "reason": "risk understated: claimed %s, real %s" % (_num_s(claim["claimed_r"]), _fixed3(summary["r"]))}
        return {"fraudulent": False, "reason": "claim is compliant under independent recomputation; bond stands"}
    except Exception as e:  # noqa: BLE001
        return {"fraudulent": False, "reason": "fraud-proof verification error: %s" % (str(e) or "unknown")}


def _summarize(d: dict) -> dict:
    return {"releaseGuardianShare": d["releaseGuardianShare"], "r": d["r"], "optimisticAllowed": d["requiredThreshold"]["optimisticAllowed"]}


def _fast_path_admits(s: dict, claimed_r: float, margin: float) -> bool:
    return s["releaseGuardianShare"] and s["optimisticAllowed"] and s["r"] <= claimed_r + margin


def _snapshot_value(snap: dict, input_: str) -> Any:
    if input_ == "reversibility_class":
        v = (snap.get("caveatContext") or {}).get("reversibilityClass")
        return v if v is not None else (((snap.get("action") or {}).get("action")) or {}).get("reversibility_class")
    return (snap.get("risk") or {}).get(input_)


def _substitute(snap: dict, res: dict) -> dict:
    if res["input"] == "reversibility_class":
        if not isinstance(res.get("class"), str) or len(res["class"]) == 0:
            raise ValueError("oracle reversibility_class resolution carries no class")
        out = dict(snap)
        act = dict(snap.get("action") or {})
        act["action"] = dict(act.get("action") or {}, reversibility_class=res["class"])
        out["action"] = act
        if (snap.get("caveatContext") or {}).get("reversibilityClass") is not None:
            out["caveatContext"] = dict(snap["caveatContext"], reversibilityClass=res["class"])
        return out
    if not _fin(res.get("value")):
        raise ValueError("oracle %s resolution carries no finite value" % res["input"])
    out = dict(snap, risk=dict(snap.get("risk") or {}, **{res["input"]: res["value"]}))
    if res["input"] == "blastRadius" and (snap.get("caveatContext") or {}).get("blastRadius") is not None:
        out["caveatContext"] = dict(snap["caveatContext"], blastRadius=res["value"])
    return out


def _js(v: Any) -> str:
    from .analyzer_js import js_json
    return "undefined" if v is None else js_json(v)


def adjudicate_dispute(claim: dict, dispute: Any, grant: dict, open_snapshot: Any, oracle: Any, r_margin: Any = None) -> Dict[str, Any]:
    """Adjudicate a contestable dispute: RE-RUN the policy VM on the frozen open-time snapshot with the ORACLE's authoritative value
    substituted for the single disputed input (``oracle.resolve(input, snapshot)`` returns ``{input, value?, class?, valid, reason?}``).
    ``outcome``: ``agent-fraud`` (slash the agent's bond), ``claim-upheld`` (slash the challenger's counter-bond) or ``indeterminate``
    (slash neither). The challenger's asserted value is never read for the verdict."""
    margin = max(0, r_margin) if _fin(r_margin) else DEFAULT_R_MARGIN
    worst = {"releaseGuardianShare": False, "r": 1, "optimisticAllowed": False}

    def indeterminate(input_: str, reason: str, **extra: Any) -> Dict[str, Any]:
        return dict({"outcome": "indeterminate", "fraudulent": False, "slashCounterBond": False, "input": input_, "agentValue": None,
                     "oracleValue": None, "baseline": worst, "adjudicated": worst, "reason": reason}, **extra)
    try:
        if not isinstance(dispute, dict):
            return indeterminate("reversibility_class", "malformed dispute")
        input_ = dispute.get("input")
        if input_ not in _INPUTS:
            return indeterminate("reversibility_class", "unknown disputed input: %s" % ("undefined" if input_ is None else input_))
        if dispute.get("pcactn_digest") != claim.get("pcactn_digest"):
            return indeterminate(input_, "dispute targets a different PCActn than the claim")
        if dispute.get("bond_ref") != claim.get("bond_ref"):
            return indeterminate(input_, "dispute names a different bond than the claim")
        if not isinstance(open_snapshot, dict):
            return indeterminate(input_, "no frozen open-time snapshot supplied; cannot adjudicate")
        if oracle is None or not callable(getattr(oracle, "resolve", None)):
            return indeterminate(input_, "no objective oracle supplied")
        snap = dict(open_snapshot, grant=grant)
        baseline = _summarize(decide(snap))
        agent_value = _snapshot_value(snap, input_)
        res = oracle.resolve(input_, snap)
        if not isinstance(res, dict) or res.get("input") != input_ or not res.get("valid"):
            return indeterminate(input_, "objective oracle could not authoritatively resolve %s%s" % (
                input_, ": %s" % res["reason"] if isinstance(res, dict) and res.get("reason") else ""), baseline=baseline, agentValue=agent_value)
        oracle_value = res["class"] if res.get("class") is not None else res.get("value")
        adjudicated = _summarize(decide(_substitute(snap, res)))
        if not _fast_path_admits(adjudicated, claim["claimed_r"], margin):
            if not adjudicated["releaseGuardianShare"]:
                why = "the Policy VM denies the action"
            elif not adjudicated["optimisticAllowed"]:
                why = "the optimistic path is not allowed (higher threshold) at r=%s" % _fixed3(adjudicated["r"])
            else:
                why = "the real r=%s exceeds the claimed r=%s" % (_fixed3(adjudicated["r"]), _num_s(claim["claimed_r"]))
            return {"outcome": "agent-fraud", "fraudulent": True, "slashBondRef": claim.get("bond_ref"), "slashCounterBond": False, "input": input_,
                    "agentValue": agent_value, "oracleValue": oracle_value, "baseline": baseline, "adjudicated": adjudicated,
                    "reason": "understated %s: agent relied on %s, oracle says %s — %s" % (input_, _js(agent_value), _js(oracle_value), why)}
        return {"outcome": "claim-upheld", "fraudulent": False, "slashCounterBond": True, "input": input_, "agentValue": agent_value,
                "oracleValue": oracle_value, "baseline": baseline, "adjudicated": adjudicated,
                "reason": "the objective oracle upholds the agent's %s (%s); fast-path admission survives — the dispute is frivolous" % (input_, _js(oracle_value))}
    except Exception as e:  # noqa: BLE001
        d_in = dispute.get("input") if isinstance(dispute, dict) and dispute.get("input") in _INPUTS else "reversibility_class"
        return indeterminate(d_in, "dispute adjudication error (fail closed): %s" % (str(e) or "unknown"))


def freeze_open_snapshot(inp: dict) -> dict:
    """A deep, JSON-normalized copy of a decide input captured at claim open (store it with the claim, grant stripped)."""
    return json.loads(json.dumps(copy.deepcopy(inp)))


def file_fraud_proof(claim: dict, pcactn: Any, grant: dict, open_snapshot: Any, r_margin: Any = None) -> Optional[Dict[str, Any]]:
    """File a fraud proof against `claim` for `pcactn`: the policy VM is re-run on the frozen open-time snapshot under `grant` (a caller
    decision is never trusted). Returns None for a compliant claim, a claim for another action, or a missing snapshot."""
    from .pca import pcactn_digest
    if not isinstance(open_snapshot, dict):
        return None
    actual = decide(dict(open_snapshot, grant=grant))
    if claim.get("pcactn_digest") != pcactn_digest(pcactn):
        return None
    margin = max(0, r_margin) if _fin(r_margin) else DEFAULT_R_MARGIN
    optimistic = actual["requiredThreshold"]["optimisticAllowed"]
    evidence = {k: v for k, v in open_snapshot.items() if k != "grant"}
    rc = ((pcactn.get("action") or {}) if isinstance(pcactn, dict) else {}).get("reversibility_class")
    if claim.get("reversibility_class") == IRREVERSIBLE_CLASS or rc == IRREVERSIBLE_CLASS:
        kind, reason = "irreversible", "irreversible action took the optimistic path"
    elif not actual["releaseGuardianShare"]:
        kind, reason = "policy-denied", "Policy VM denied the action: %s" % ("; ".join(actual["reasons"]) or "not compliant")
    elif not optimistic:
        kind, reason = "optimistic-not-allowed", "optimistic path not allowed at real r=%s (t=%s)" % (_fixed3(actual["r"]), _num_s(actual["requiredThreshold"]["t"]))
    elif actual["r"] > claim["claimed_r"] + margin:
        kind, reason = "risk-understated", "claimed r=%s but real r=%s" % (_num_s(claim["claimed_r"]), _fixed3(actual["r"]))
    else:
        return None
    return {
        "pcactn_digest": claim["pcactn_digest"], "bond_ref": claim["bond_ref"], "claimed_r": claim["claimed_r"],
        "decision": {"releaseGuardianShare": actual["releaseGuardianShare"], "r": actual["r"], "optimisticAllowed": optimistic},
        "evidence": evidence, "r_margin": margin, "kind": kind, "reason": reason,
    }
