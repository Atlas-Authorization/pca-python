"""Approval channels (the TypeScript ``approval-channels``): where a step-up request (see :mod:`atlas_pca.approvals`) reaches a human. Slack
(Block Kit over an incoming webhook), a signed-style JSON webhook, and text channels (email, sms, push) over an injected sender share one
port; a dispatcher fans a request out to every ENABLED channel. Transports are injected (``fetch(url, init) -> object with ok and status``)
so channels stay offline-testable; ``notify`` never raises and returns the delivery record (``kind``, ``requestId``, ``delivered``, ``payload``,
``status``?, ``reason``?). Every channel shows the same lines: the action summary, the goal lineage and the canonical render with its match code."""
import unicodedata
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

from .analyzer_js import js_json, to_fixed
from .approval import binding_words
from .approvals import describe_goal_lineage

__all__ = ["action_summary", "lineage_lines", "render_lines", "build_slack_message", "slack_approval_channel", "build_webhook_body",
           "webhook_approval_channel", "build_text_body", "text_approval_channel", "create_approval_dispatcher"]


def action_summary(request: dict) -> str:
    """One-line action summary: ``verb on resource (tier N, risk R)``."""
    return "%s on %s (tier %s, risk %s)" % (request["verb"], request["resource"], request["tier"], to_fixed(request["r"], 2))


def _escape(s: str) -> str:
    return "".join("\\u{%x}" % ord(ch) if unicodedata.category(ch) in ("Cc", "Cf") or ch in "  " else ch for ch in s)


def render_lines(request: dict) -> List[str]:
    """The canonical render, one line per field (nothing omitted), the banner for an unreviewed action and the speakable match code of H(R).
    Empty when the request carries no render."""
    r = request.get("render")
    if r is None or request.get("renderDigest") is None:
        return []
    out: List[str] = []
    if r.get("unreviewed"):
        out.append("UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.")
    for f in r["fields"]:
        u = f.get("unit")
        unit = " %s (minor units, exponent %s)" % (u["ccy"], u["exp"]) if isinstance(u, dict) and u.get("kind") == "money" else ""
        out.append("%s [%s]: %s%s" % (f["id"], f["class"], _escape(js_json(f.get("value"))), unit))
    out.append("Match code: %s" % binding_words(request["renderDigest"]))
    return out


def lineage_lines(request: dict) -> List[str]:
    """The lines a human reads to understand WHY: the "because you asked to ..." sentence, the goal, authority and action chain, the render."""
    return [request["lineage"]["because"]] + describe_goal_lineage(request["lineage"]) + render_lines(request)


def _append_query(url: str, params: Dict[str, str]) -> str:
    """Add query parameters before any ``#fragment`` (an approval link may carry its token in the fragment, which must stay last)."""
    query = "&".join("%s=%s" % (quote(k, safe="-_.!~*'()"), quote(v, safe="-_.!~*'()")) for k, v in params.items())
    i = url.find("#")
    base, frag = (url, "") if i == -1 else (url[:i], url[i:])
    return "%s%s%s%s" % (base, "&" if "?" in base else "?", query, frag)


def build_slack_message(request: dict, ctx: Optional[dict] = None) -> Dict[str, Any]:
    """The Block Kit message for a step-up: action summary, goal lineage and an approve / deny affordance."""
    ctx = ctx or {}
    blocks: List[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": "Approval needed · tier %s" % request["tier"], "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "*%s* on `%s`\n_%s_" % (request["verb"], request["resource"], request["reason"])}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "*Why this is requested*\n%s" % "\n".join("• %s" % l for l in lineage_lines(request))}},
    ]
    inbox = ctx.get("inboxUrl")
    if inbox:
        approve = _append_query(inbox, {"stepup": request["id"], "decision": "approve"})
        deny = _append_query(inbox, {"stepup": request["id"], "decision": "deny"})
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Approve", "emoji": True}, "url": approve, "style": "primary", "action_id": "pca_approve"},
            {"type": "button", "text": {"type": "plain_text", "text": "Deny", "emoji": True}, "url": deny, "style": "danger", "action_id": "pca_deny"}]})
    else:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": "Approve or deny step-up `%s` in your Atlas inbox." % request["id"]}]})
    return {"text": "Approval needed: %s" % action_summary(request), "blocks": blocks}


class _Channel:
    def __init__(self, kind: str, enabled: bool, notify: Callable[..., dict]) -> None:
        self.kind, self.enabled, self._notify = kind, enabled, notify

    def notify(self, request: dict, ctx: Optional[dict] = None) -> dict:
        return self._notify(request, ctx or {})


def _post(kind: str, request: dict, payload: Any, url: str, transport: Callable[..., Any], headers: dict, label: str) -> dict:
    try:
        res = transport(url, {"method": "POST", "headers": headers, "body": js_json(payload)})
        if res.ok:
            return {"kind": kind, "requestId": request["id"], "delivered": True, "payload": payload, "status": res.status}
        return {"kind": kind, "requestId": request["id"], "delivered": False, "payload": payload, "status": res.status,
                "reason": "%s returned %s" % (label, res.status)}
    except Exception as e:  # noqa: BLE001 - notify never raises
        return {"kind": kind, "requestId": request["id"], "delivered": False, "payload": payload, "reason": str(e) or "%s transport error" % kind}


def slack_approval_channel(webhook_url: Optional[str] = None, fetch: Optional[Callable[..., Any]] = None) -> _Channel:
    """The Slack channel (Block Kit over an incoming webhook). Disabled, and a no-op, unless a webhook URL is configured."""
    enabled = isinstance(webhook_url, str) and len(webhook_url) > 0

    def notify(request: dict, ctx: dict) -> dict:
        message = build_slack_message(request, ctx)
        if not enabled:
            return {"kind": "slack", "requestId": request["id"], "delivered": False, "payload": message, "reason": "slack channel not configured"}
        if fetch is None:
            return {"kind": "slack", "requestId": request["id"], "delivered": False, "payload": message,
                    "reason": "no fetch available: pass a transport to the channel"}
        return _post("slack", request, message, webhook_url, fetch, {"content-type": "application/json"}, "slack webhook")
    return _Channel("slack", enabled, notify)


def build_webhook_body(request: dict, ctx: Optional[dict] = None) -> Dict[str, Any]:
    """The webhook JSON body: the step-up plus its pre-formatted human summary and lineage."""
    ctx = ctx or {}
    out: Dict[str, Any] = {"type": "pca.step_up.created", "stepup": request, "summary": action_summary(request), "lineage": lineage_lines(request)}
    if ctx.get("inboxUrl"):
        out["inbox_url"] = ctx["inboxUrl"]
    return out


def webhook_approval_channel(url: Optional[str] = None, fetch: Optional[Callable[..., Any]] = None, headers: Optional[dict] = None) -> _Channel:
    """The generic webhook channel. Disabled unless a URL is configured; `headers` carry e.g. a caller-computed signature (never logged)."""
    enabled = isinstance(url, str) and len(url) > 0
    hdr = {"content-type": "application/json", **(headers or {})}

    def notify(request: dict, ctx: dict) -> dict:
        body = build_webhook_body(request, ctx)
        if not enabled:
            return {"kind": "webhook", "requestId": request["id"], "delivered": False, "payload": body, "reason": "webhook channel not configured"}
        if fetch is None:
            return {"kind": "webhook", "requestId": request["id"], "delivered": False, "payload": body, "reason": "no fetch available: pass a transport to the channel"}
        return _post("webhook", request, body, url, fetch, hdr, "webhook")
    return _Channel("webhook", enabled, notify)


def build_text_body(request: dict, ctx: Optional[dict] = None) -> Dict[str, str]:
    """The plain-text body (subject and text) shared by the email, sms and push surfaces."""
    ctx = ctx or {}
    lines = [action_summary(request), ""] + lineage_lines(request)
    if ctx.get("inboxUrl"):
        lines += ["", "Approve or deny: %s" % _append_query(ctx["inboxUrl"], {"stepup": request["id"]})]
    return {"subject": "Approval needed: %s on %s" % (request["verb"], request["resource"]), "text": "\n".join(lines)}


def text_approval_channel(kind: str, send: Optional[Callable[[dict], Any]] = None) -> _Channel:
    """A text channel (``email``, ``sms`` or ``push``) over an injected sender ``send({"subject", "text"})`` (raises on failure). Disabled
    when no sender is configured."""
    if kind not in ("email", "sms", "push"):
        raise ValueError("textApprovalChannel: kind must be email, sms or push")
    enabled = callable(send)

    def notify(request: dict, ctx: dict) -> dict:
        body = build_text_body(request, ctx)
        if not enabled:
            return {"kind": kind, "requestId": request["id"], "delivered": False, "payload": body, "reason": "%s channel not configured" % kind}
        try:
            send(body)  # type: ignore[misc]
            return {"kind": kind, "requestId": request["id"], "delivered": True, "payload": body}
        except Exception as e:  # noqa: BLE001
            return {"kind": kind, "requestId": request["id"], "delivered": False, "payload": body, "reason": str(e) or "%s send error" % kind}
    return _Channel(kind, enabled, notify)


class _Dispatcher:
    def __init__(self, channels: List[Any]) -> None:
        self.channels = channels

    def notify_all(self, request: dict, ctx: Optional[dict] = None) -> List[dict]:
        """Fan a step-up out to every ENABLED channel: one delivery record per channel."""
        return [c.notify(request, ctx) for c in self.channels if c.enabled]


def create_approval_dispatcher(channels: List[Any]) -> _Dispatcher:
    """Register a set of channels behind one dispatcher. Disabled channels are skipped at ``notify_all``."""
    return _Dispatcher(list(channels))
