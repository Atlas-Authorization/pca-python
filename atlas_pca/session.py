"""Multi-agent session: a root agent and the sub-agents it delegates to, grouped under the ONE signed goal they share, so a principal
sees the whole team and the console can be scoped to it. Composes the facade's sub-agent delegation and the console projection. Pure.

A session is a dict ``{"root": agent, "members": [agent, ...], "goalCommit": str}`` (root first, then each sub-agent in delegation
order); the agents are :class:`atlas_pca.facade.AgentHandle`."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .agent import KeyPair
from .authorize import read_envelope
from .console import build_console

__all__ = ["SESSION_MAX_DEPTH", "start_session", "add_member", "session_agents", "session_console", "shares_goal", "session_depth"]

#: Deepest delegation chain a session accepts.
SESSION_MAX_DEPTH = 32


def _goal_commit(agent: Any) -> str:
    env = read_envelope(agent.grant)
    gc = env.get("goal_commit") if env else None
    return "" if gc is None else gc


def start_session(root: Any) -> Dict[str, Any]:
    """A session of the root agent alone; its goal commitment is the root grant's (``""`` without a readable envelope)."""
    return {"root": root, "members": [root], "goalCommit": _goal_commit(root)}


def add_member(session: Dict[str, Any], holder: Optional[KeyPair] = None, added_caveats: Sequence[dict] = ()) -> Dict[str, Any]:
    """Add a sub-agent: one attenuated delegation hop under the session's current leaf. Returns ``{"session": the new session,
    "member": the sub-agent}`` (the given session is not changed). Raises ValueError past ``SESSION_MAX_DEPTH`` hops."""
    members = session["members"]
    if len(members) > SESSION_MAX_DEPTH:
        raise ValueError("addMember: a session is limited to %d delegation hops" % SESSION_MAX_DEPTH)
    member = members[-1].sub_agent(holder=holder, added_caveats=added_caveats)
    return {"session": dict(session, members=list(members) + [member]), "member": member}


def session_agents(session: Dict[str, Any]) -> List[str]:
    """The holder ids (base64url public keys) of every agent in the session."""
    return [m.holder.public for m in session["members"]]


def session_console(session: Dict[str, Any], events: List[Any]) -> Dict[str, Any]:
    """A console view of just this session's agents. Raises TypeError on a null event (it has no agent to read)."""
    ids = set(session_agents(session))
    if not isinstance(events, list):
        raise TypeError("sessionConsole: events must be a list")
    if any(e is None for e in events):
        raise TypeError("sessionConsole: an event is null")
    return build_console([e for e in events if isinstance(e, dict) and isinstance(e.get("agent"), str) and e["agent"] in ids])


def shares_goal(session: Dict[str, Any]) -> bool:
    """True iff every member shares the session's goal commitment. Members that all lack one do not share a goal: False."""
    return session["goalCommit"] != "" and all(_goal_commit(m) == session["goalCommit"] for m in session["members"])


def session_depth(session: Dict[str, Any]) -> int:
    """Depth of the delegation tree (0 = the root only)."""
    return len(session["members"]) - 1
