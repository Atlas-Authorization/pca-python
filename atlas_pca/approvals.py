"""Approval and step-up model (the TypeScript ``approvals``): the HEADLESS core an approval inbox renders. Given an intended action it
decides whether it auto-admits, is a hard deny or needs a human, and if so produces a step-up request carrying goal lineage, the risk tier
and a stable id; plus batching, "approve this class for N hours" standing approvals and the human co-sign budget recharge.

Pure and offline: it composes the agent handle's non-authoritative ``dry_run`` and the budget algebra. It signs nothing except where a
grant is time-boxed (:func:`time_box`). The resource server stays the authority at run time. Records are dicts with the reference's
member names (``goalCommit``, ``requestedAt``, ``renderDigest``, ...)."""
import functools
import json
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from ._fin import fin, to_float
from .adapters import js_json, js_string
from .agent import attenuate, goal_commit_of
from .approval import approval_render_digest
from .authorize import read_envelope
from .intent_v2 import compare_utf8
from .pca import hash_canonical
from .risk import recharge, recharge_full

__all__ = ["build_goal_lineage", "describe_goal_lineage", "review_action", "batch_review", "pending_requests", "approve_class",
           "class_approval_covers", "covered_by_any", "record_decision", "apply_cosign", "time_box"]


def _fmt_num(n: Any) -> str:
    return js_string(n)


def _format_limit(limit: Dict[str, Any]) -> str:
    base = "$" + _fmt_num(limit["amount"]) if limit.get("unit") == "usd" else _fmt_num(limit["amount"])
    if limit.get("periodMs") is None:
        return base
    hours = limit["periodMs"] / 3_600_000
    if hours % 24 == 0 and hours >= 24:
        period = "%sd" % _fmt_num(hours / 24)
    elif hours >= 1:
        period = "%sh" % _fmt_num(hours)
    else:
        period = "%sm" % _fmt_num(int(limit["periodMs"] / 60_000 + 0.5))
    return "%s/%s" % (base, period)


def _show(v: Any) -> str:
    return js_json(v) if isinstance(v, (dict, list)) or v is None else js_string(v)


def _summarize_params(params: Optional[dict], amount_field: Optional[str]) -> Optional[str]:
    if params is None:
        return None
    if amount_field is not None and params.get(amount_field) is not None:
        return "%s=%s" % (amount_field, js_string(params[amount_field]))
    keys = list(params)
    if not keys:
        return None
    return ", ".join("%s=%s" % (k, _show(params[k])) for k in keys[:4])


def build_goal_lineage(agent: Any, verb: str, resource: str, params: Optional[dict] = None, goal: Optional[str] = None) -> Dict[str, Any]:
    """The goal lineage of one intended action ("you approved X because you asked to Y"), derived from the grant envelope's
    ``goal_commit``, the compiled policy and the optional revealed goal, which is checked against the commitment with the agent's goal
    salt (``goalVerified``). `agent` is an ``atlas_pca.facade.AgentHandle``. Pure; signs nothing."""
    env = read_envelope(agent.grant)
    goal_commit = (env or {}).get("goal_commit") or ""
    salt = getattr(agent, "goal_salt", None)
    verified = goal is not None and goal_commit != "" and isinstance(salt, str) and len(salt) > 0 and goal_commit_of(goal, salt) == goal_commit
    spec = next((s for s in agent.policy["actions"] if s["verb"] == verb), None)
    limit = (agent.policy.get("limits") or {}).get(verb)
    goal_label = "Pursue the goal: “%s”" % goal if goal is not None else "Pursue the grant’s committed goal"
    if goal is not None:
        goal_detail = ("verified: this goal opens the signed grant commitment" if verified
                       else "unverified: the revealed goal does not open the grant commitment")
    else:
        goal_detail = "committed as %s" % goal_commit if goal_commit != "" else None
    authority = "Delegated authority to %s%s" % (verb, " (up to %s)" % _format_limit(limit) if limit else "")
    action_detail = _summarize_params(params, spec.get("amountField") if spec else None)
    g: Dict[str, Any] = {"kind": "goal", "label": goal_label}
    if goal_detail is not None:
        g["detail"] = goal_detail
    a: Dict[str, Any] = {"kind": "authority", "label": authority}
    if spec and spec.get("description"):
        a["detail"] = spec["description"]
    c: Dict[str, Any] = {"kind": "action", "label": "%s %s" % (verb, resource)}
    if action_detail is not None:
        c["detail"] = action_detail
    because = ("Approving %s on %s because you asked to “%s”." % (verb, resource, goal) if goal is not None
               else "Approving %s on %s, authorized under the grant’s committed goal." % (verb, resource))
    out: Dict[str, Any] = {}
    if goal is not None:
        out["goal"] = goal
    out.update({"goalCommit": goal_commit, "goalVerified": verified, "chain": [g, a, c], "because": because})
    return out


def describe_goal_lineage(lineage: Dict[str, Any]) -> List[str]:
    """Flatten a lineage to plain text lines (SMS, plain email, Slack fallback)."""
    return ["%s — %s" % (n["label"], n["detail"]) if n.get("detail") else n["label"] for n in lineage["chain"]]


def _risk_for_review(agent: Any, verb: str, params: Optional[dict]) -> float:
    spec = next((s for s in agent.policy["actions"] if s["verb"] == verb), None)
    if agent.policy["budgetModel"] == "dollars" and spec and spec.get("amountField"):
        try:
            amt = to_float((params or {}).get(spec["amountField"]))
        except (TypeError, ValueError):
            amt = float("nan")
        if fin(amt) and agent.policy["riskPolicy"]["kappa"] > 0:
            return max(0.0, min(1.0, amt / agent.policy["riskPolicy"]["kappa"]))
    return max(0.0, min(1.0, spec["blastRadius"] if spec else 0.8))


def review_action(agent: Any, verb: str, resource: str, params: Optional[dict] = None, *, now: Optional[int] = None,
                  goal: Optional[str] = None, standing: Optional[Sequence[dict]] = None,
                  renderer: Optional[Callable[[str, str, Optional[dict]], Any]] = None,
                  insecure_unbound_approval: bool = False) -> Dict[str, Any]:
    """Review an intended action against the agent's grant: ``{"kind": "auto"}`` (no human needed), ``{"kind": "deny", "reason"}`` (the
    grant forbids it; no approval fixes that offline) or ``{"kind": "step_up", "request"}`` (admissible but needs a tier-2/3 co-sign,
    unless a standing class approval covers it).

    A step-up request is created only together with its canonical approval render (`renderer(verb, resource, params)`): what the approver
    sees is what is signed. Without a renderer the review is a ``deny`` unless `insecure_unbound_approval` is True (a DOCUMENTED INSECURE
    opt-out). A renderer that raises makes the review a ``deny``: an action that cannot be shown completely is never put to a human."""
    at = int(time.time() * 1000) if now is None else now
    dr = agent.dry_run(verb, resource, params, at)
    if not dr["allowed"]:
        return {"kind": "deny", "reason": dr.get("reason") or "denied by policy"}
    t = dr.get("t")
    if t == 1 or t is None:
        return {"kind": "auto"}
    if standing and covered_by_any(standing, verb, resource, at):
        return {"kind": "auto"}
    render = digest = None
    if renderer is None and insecure_unbound_approval is not True:
        return {"kind": "deny", "reason": "approval render required: pass a renderer (renderers_from_defs from the pinned action "
                                          "definitions), or insecure_unbound_approval=True"}
    if renderer is not None:
        try:
            render = renderer(verb, resource, params)
            digest = approval_render_digest(render)
        except Exception as err:  # noqa: BLE001 - fail closed
            return {"kind": "deny", "reason": "approval render failed (fail closed): %s" % (str(err) or "unknown")}
    env = read_envelope(agent.grant)
    request: Dict[str, Any] = {
        "id": hash_canonical({"d": "atlas-pca/stepup/v1", "verb": verb, "resource": resource, "params": params, "at": at}),
        "verb": verb, "resource": resource}
    if params is not None:
        request["params"] = params
    request.update({"tier": t, "reason": dr.get("reason") or "requires tier %s co-sign" % t, "goalCommit": (env or {}).get("goal_commit") or ""})
    if goal is not None:
        request["goal"] = goal
    request["lineage"] = build_goal_lineage(agent, verb, resource, params, goal)
    request["r"] = _risk_for_review(agent, verb, params)
    request["requestedAt"] = at
    if render is not None and digest is not None:
        request["render"], request["renderDigest"] = render, digest
    return {"kind": "step_up", "request": request}


def batch_review(agent: Any, calls: Sequence[Dict[str, Any]], **opts: Any) -> List[Dict[str, Any]]:
    """Review a batch of intended actions ``{"verb", "resource", "params"?}`` (the inbox's "N actions waiting")."""
    return [review_action(agent, c["verb"], c["resource"], c.get("params"), **opts) for c in calls]


def pending_requests(reviews: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Just the step-up requests from a batch of reviews (what the approver actually sees)."""
    return [r["request"] for r in reviews if r["kind"] == "step_up"]


def approve_class(verbs: Sequence[str], *, ttl_ms: int, by: str, now: Optional[int] = None, resource: Optional[str] = None) -> Dict[str, Any]:
    """Mint a standing class approval ("approve stripe.refund + gmail.send for the next 4 hours")."""
    granted = int(time.time() * 1000) if now is None else now
    out: Dict[str, Any] = {"id": hash_canonical({"d": "atlas-pca/class-approval/v1", "verbs": sorted(verbs, key=functools.cmp_to_key(compare_utf8)),
                                                 "resource": resource, "grantedAt": granted, "by": by}),
                           "verbs": list(verbs)}
    if resource is not None:
        out["resource"] = resource
    out.update({"grantedAt": granted, "ttlMs": ttl_ms, "by": by})
    return out


def _resource_matches(pattern: Optional[str], resource: str) -> bool:
    if pattern is None or pattern == "*":
        return True
    if pattern.endswith("*"):
        return resource.startswith(pattern[:-1])
    return pattern == resource


def class_approval_covers(a: Dict[str, Any], verb: str, resource: str, now: int) -> bool:
    """Does this standing approval still cover (verb, resource) at `now`?"""
    if not (fin(now, a["grantedAt"], a["ttlMs"]) and now >= a["grantedAt"] and now < a["grantedAt"] + a["ttlMs"]):
        return False
    return verb in a["verbs"] and _resource_matches(a.get("resource"), resource)


def covered_by_any(approvals: Sequence[Dict[str, Any]], verb: str, resource: str, now: int) -> bool:
    """Is (verb, resource) covered by ANY active standing approval?"""
    return any(class_approval_covers(a, verb, resource, now) for a in approvals)


def record_decision(request: Dict[str, Any], decision: str, by: str, at: Optional[int] = None) -> Dict[str, Any]:
    """Record a human's decision (``approve`` | ``deny``) on a request (pure data for the audit trail)."""
    return {"requestId": request["id"], "decision": decision, "by": by, "at": int(time.time() * 1000) if at is None else at}


def apply_cosign(budget: Dict[str, Any], policy: Dict[str, Any], now: int, full: bool = False) -> Dict[str, Any]:
    """Apply a human co-sign to the trust budget: a partial recharge (rho per co-sign), or a full recharge to bMax with `full`. The
    ONLY thing that raises the budget, so the safety bound holds between two co-signs."""
    return recharge_full(budget, policy["bMax"], now) if full else recharge(budget, policy["rho"], policy["bMax"], now)


def time_box(parent: Dict[str, Any], holder_secret: Any, ttl_ms: int, now: Optional[int] = None) -> Dict[str, Any]:
    """Narrow a capability to expire `ttl_ms` from `now` by appending an ``expires`` caveat signed by the holder (`holder_secret` is the
    holder's KeyPair). Caveats are conjunctive and append-only, so this only ever restricts."""
    at = int(time.time() * 1000) if now is None else now
    return attenuate(parent, [{"type": "expires", "at": at + ttl_ms}], holder_secret)
