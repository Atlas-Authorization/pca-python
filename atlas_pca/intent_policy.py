"""Policy plumbing for the intent layer: an outcome as the analyzer's concrete action, and the real evaluator as an
admission oracle. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

ANY_RESOURCE = "resource:any"


def normalize_policy(p: Any) -> Dict[str, Any]:
    """{predicates, caveats}: a non-array member counts as empty."""
    if isinstance(p, (str, int, float)) and p and p == p:  # `'caveats' in p` throws for a truthy primitive (a string, a non-zero number, true)
        raise TypeError("Cannot use 'in' operator to search for 'caveats' in %s" % _js_string(p))
    preds = p.get("predicates") if isinstance(p, dict) else None
    cavs = p.get("caveats") if isinstance(p, dict) else None
    return {"predicates": preds if isinstance(preds, list) else [], "caveats": cavs if isinstance(cavs, list) else []}


def _set_path(root: dict, segs: List[str], value: Any) -> None:
    cur = root
    for k in segs[:-1]:
        nxt = cur.get(k)
        if not isinstance(nxt, dict):
            cur[k] = {}
        cur = cur[k]
    cur[segs[-1]] = value


def _js_string(v: Any) -> str:
    from .intent_v2 import _js_string as js
    return js(v)


def outcome_to_action(vs: dict, o: dict) -> dict:
    """The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the verb space)."""
    params: Dict[str, Any] = {}
    env: Dict[str, Any] = {}
    subject: Dict[str, Any] = {}
    resource = ANY_RESOURCE
    for path, value in (o.get("values") or {}).items():
        segs = path.split(".")
        if path == "action.resource":
            resource = _js_string(value)
        elif segs[0] == "action" and len(segs) > 1 and segs[1] == "params" and len(segs) > 2:
            _set_path(params, segs[2:], value)
        elif segs[0] == "env" and len(segs) > 1:
            _set_path(env, segs[1:], value)
        elif segs[0] == "subject" and len(segs) > 1:
            _set_path(subject, segs[1:], value)
    a: Dict[str, Any] = {"verb": o["verb"], "resource": resource, "params": params, "reversibilityClass": vs.get("reversibility")}
    if env:
        a["env"] = env
    if subject:
        a["subject"] = subject
    return a


class Admitter:
    """A compiled admission oracle for one policy (compile once, query many times)."""

    def __init__(self, policy: Any):
        from .analyzer_core import to_model
        self._model = to_model(policy)

    def admits(self, vs: dict, o: dict) -> bool:
        from .analyzer_core import admits_action
        return admits_action(self._model, outcome_to_action(vs, o))


def admitter(policy: Any) -> Admitter:
    return Admitter(policy)


def vs_of(omega: dict, o: dict) -> Optional[dict]:
    for v in omega["verbs"]:
        if v["verb"] == o["verb"]:
            return v
    return None
