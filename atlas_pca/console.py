"""The principal's agent console, data layer: projects a stream of activity events into a per-agent view with a threat read (the
behavioural immune system of ``atlas_pca.immune``) and models the local kill switch.

Pure and offline: a projection over the records it is fed. The freeze set is a LOCAL kill-switch list a client or gateway consults before
dispatching; authoritative revocation is the ledger's revocation epoch. Events, views and freeze sets are dicts with the reference
member names (an event: ``{"at", "agent", "verb", "resource", "outcome": auto | step_up | deny | executed, "r"?, "taint"?, "digest"?,
"goalCommit"?}``; a freeze set: ``{"frozen": [agent, ...]}``)."""
from __future__ import annotations

from ._fin import fin
from typing import Any, Dict, List, Optional

from .immune import INITIAL_IMMUNE_STATE, assess, observe
from .pca import pcactn_digest
from .predicates import _js_string

__all__ = ["EMPTY_FREEZE", "event_from_pcactn", "build_console", "anomalies", "freeze_agent", "unfreeze_agent", "is_frozen"]

EMPTY_FREEZE: Dict[str, List[str]] = {"frozen": []}


def _finite(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


def event_from_pcactn(p: Dict[str, Any], outcome: str, at: Optional[Any] = None) -> Dict[str, Any]:
    """The activity event of a PCActn and the verifier's outcome: the agent is the leaf holder of the capability chain (``unknown``
    when the chain names none), the time is ``at`` or the PCActn's ``iat``. Raises on a PCActn without a chain or an action, or one
    that has no canonical form."""
    chain, action = p["cap_chain"], p["action"]
    if not isinstance(chain, list) or not isinstance(action, dict):
        raise TypeError("eventFromPCActn: the PCActn needs a cap_chain and an action")
    leaf = chain[-1] if chain else None
    holder = leaf.get("holder") if isinstance(leaf, dict) else None
    ev: Dict[str, Any] = {}
    when = at if at is not None else p.get("iat")
    if when is not None:
        ev["at"] = when
    ev["agent"] = holder if holder is not None else "unknown"
    if "verb" in action:
        ev["verb"] = action["verb"]
    if "resource" in action:
        ev["resource"] = action["resource"]
    ev["outcome"] = outcome
    risk, prov = p.get("risk_claim"), p.get("provenance")
    if isinstance(risk, dict) and "r" in risk:
        ev["r"] = risk["r"]
    if isinstance(prov, dict) and "taint_level" in prov:
        ev["taint"] = prov["taint_level"]
    ev["digest"] = pcactn_digest(p)
    return ev


def build_console(events: List[Any]) -> Dict[str, Any]:
    """Project activity events into ``{"agents": [summary], "totals", "window": {"from", "to"}, "dropped"}``. A summary is ``{"agent",
    "actions", "autos", "stepUps", "denies", "executed", "totalRisk", "firstSeen", "lastSeen", "threat"}``, most threatening first (then
    most recently seen). An event without a finite time or an agent id cannot be placed or attributed: it is counted in ``dropped``."""
    by_agent: Dict[str, List[Dict[str, Any]]] = {}
    kept = [e for e in events if isinstance(e, dict) and _finite(e.get("at")) and isinstance(e.get("agent"), str) and e["agent"]]
    for e in kept:
        by_agent.setdefault(e["agent"], []).append(e)
    agents = []
    for agent, evs in by_agent.items():
        ordered = sorted(evs, key=lambda e: e["at"])
        immune = INITIAL_IMMUNE_STATE
        counts = {"auto": 0, "step_up": 0, "deny": 0, "executed": 0}
        total: Any = 0
        for e in ordered:
            r = e.get("r") if e.get("r") is not None else 0
            total += r
            outcome = e.get("outcome")
            if isinstance(outcome, str) and outcome in counts:
                counts[outcome] += 1
            immune = observe(immune, {"r": r, "at": e["at"], "stepUp": outcome == "step_up", "denied": outcome == "deny"})
        agents.append({"agent": agent, "actions": len(ordered), "autos": counts["auto"], "stepUps": counts["step_up"], "denies": counts["deny"],
                       "executed": counts["executed"], "totalRisk": total, "firstSeen": ordered[0]["at"], "lastSeen": ordered[-1]["at"],
                       "threat": assess(immune)})
    agents.sort(key=lambda a: (-a["threat"]["score"], -a["lastSeen"]))
    totals = {k: sum(a[k] for a in agents) for k in ("actions", "autos", "stepUps", "denies", "executed")}
    ats = [e["at"] for e in kept]
    return {"agents": agents, "totals": totals, "window": {"from": min(ats) if ats else 0, "to": max(ats) if ats else 0},
            "dropped": len(events) - len(kept)}


def anomalies(view: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The agents of a console view whose threat read is not calm."""
    return [a for a in view["agents"] if a["threat"]["level"] != "calm"]


# ---- freeze (the kill switch) ---------------------------------------------------------------------------------------------

def _same(a: Any, b: Any) -> bool:
    """Strict equality of two JSON scalars (a boolean is never a number)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def _frozen_of(fs: Any) -> Any:
    if not isinstance(fs, dict) or not isinstance(fs.get("frozen"), (list, str)):
        raise TypeError("the freeze set has no frozen list")
    return fs["frozen"]


def freeze_agent(fs: Dict[str, Any], agent: str) -> Dict[str, Any]:
    """The set with ``agent`` frozen: the SAME set when it already is, else a new set whose list is sorted (never mutates). Raises
    TypeError on an empty or non-string agent."""
    if not isinstance(agent, str) or len(agent) == 0:
        raise TypeError("freezeAgent: agent must be a non-empty string")
    frozen = _frozen_of(fs)
    if (agent in frozen) if isinstance(frozen, str) else any(_same(a, agent) for a in frozen):
        return fs
    return {"frozen": sorted(list(frozen) + [agent], key=lambda a: _js_string(a).encode("utf-16-be", "surrogatepass"))}


def unfreeze_agent(fs: Dict[str, Any], agent: Any) -> Dict[str, Any]:
    """A new set without ``agent`` (never mutates)."""
    frozen = _frozen_of(fs)
    if not isinstance(frozen, list):
        raise TypeError("the freeze set has no frozen list")
    return {"frozen": [a for a in frozen if not _same(a, agent)]}


def is_frozen(fs: Any, agent: Any) -> bool:
    """Fail closed: an action with no identifiable agent, or a malformed set, is frozen."""
    if not isinstance(agent, str) or len(agent) == 0 or not isinstance(fs, dict) or not isinstance(fs.get("frozen"), list):
        return True
    return any(_same(a, agent) for a in fs["frozen"])
