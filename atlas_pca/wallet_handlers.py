"""Framework-neutral handlers for the two wallet endpoints named in the session root (3.3 item 3, 3.14): the question endpoint (a
site delivers, or an agent relays unchanged, a site-signed intent_required plus the raw action) and the clarification endpoint. The HTTP
routes live with the session store of the host; these functions are what such a route calls, so the wire behaviour is fixed here.
Neither response carries p or any map content. Native port of the TypeScript reference (@atlasauth/pca-wallet, handlers.ts)."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from .wallet import is_obj

_STATUS_OF_REFUSAL = {
    "bad_site_signature": 401, "wrong_session": 409, "stale_map": 409, "action_mismatch": 422, "cell_mismatch": 422, "not_uncertain": 409,
    "already_asked": 409, "frozen": 429, "cap_session": 429, "cap_hour": 429, "cell_too_large": 422, "bad_request": 400, "render_failed": 422,
}
_ACTION_KEYS = ("verb", "resource", "params", "reversibility_class")


def _action_of(v: Any) -> Optional[Dict[str, Any]]:
    if not is_obj(v) or not isinstance(v.get("verb"), str) or not isinstance(v.get("resource"), str) or not isinstance(v.get("reversibility_class"), str) \
            or not is_obj(v.get("params")):
        return None
    for k in v:
        if k not in _ACTION_KEYS:
            return None
    return {"verb": v["verb"], "resource": v["resource"], "params": v["params"], "reversibility_class": v["reversibility_class"]}


def question_handler(resolve: Callable[[str], Any]) -> Callable[[str, Any], Dict[str, Any]]:
    """The question endpoint: resolve(session_id) -> a TrustedChannel or None."""
    def handle(session_id: str, body: Any) -> Dict[str, Any]:
        ch = resolve(session_id)
        if not ch:
            return {"status": 404, "body": {"error": "unknown_session"}}
        if not is_obj(body):
            return {"status": 400, "body": {"error": "bad_request"}}
        for k in body:
            if k != "intent_required" and k != "action":
                return {"status": 400, "body": {"error": "bad_request", "detail": 'unknown member "%s"' % k}}
        action = _action_of(body.get("action"))
        if not action or not is_obj(body.get("intent_required")):
            return {"status": 400, "body": {"error": "bad_request"}}
        r = ch.receive(body["intent_required"], {"action": action})
        if r["ok"]:
            return {"status": 202, "body": {"question_id": r["questionId"], "friction": r["friction"]}}
        return {"status": _STATUS_OF_REFUSAL.get(r["code"], 400), "body": {"error": r["code"]}}
    return handle


def clarify_handler(resolve: Callable[[str], Any]) -> Callable[[str, Any], Dict[str, Any]]:
    """The clarification endpoint (3.14)."""
    def handle(session_id: str, body: Any) -> Dict[str, Any]:
        ch = resolve(session_id)
        if not ch:
            return {"status": 404, "body": {"error": "unknown_session"}}
        r = ch.clarify(body)
        if r.get("error") is not None:
            return {"status": 400, "body": {"error": "bad_request", "detail": r["error"]}}
        out: Dict[str, Any] = {"verdicts": r["verdicts"]}
        if r.get("questionId") is not None:
            out["question_id"] = r["questionId"]
        if r.get("refused") is not None:
            out["refused"] = r["refused"]
        return {"status": r["status"], "body": out}
    return handle
