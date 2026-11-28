"""Question delivery over the existing approval-channel transports (a webhook with an injected fetch, and email / sms / push through an
injected sender). A delivery only tells the principal's device that a question is waiting and hands it the SIGNED question: never a
rendered card, agent text, the map or p. Text surfaces use one fixed template. Native port of the TypeScript reference
(@atlasauth/pca-wallet, delivery.ts). The transports are injected sync callables: `fetch(url, init) -> {ok, status}` and
`send({subject, text})`; with no fetch configured a webhook delivery reports "no fetch available" instead of touching the network."""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

from .intent_required import verify_intent_required
from .wallet_card import clean_text


def site_question_notice(ir: dict, ctx: dict) -> Dict[str, Any]:
    """A notice for a site-signed question. Raises when the signature or expiry does not verify (nothing unsigned leaves)."""
    v = verify_intent_required(ir, ctx.get("keys"), ctx.get("now"))
    if not v["ok"]:
        raise ValueError("siteQuestionNotice: %s" % v["reason"])
    out: Dict[str, Any] = {"type": "pca.intent.question", "session": ir["session"], "question_id": ir["question_id"], "site": ctx.get("site"),
                           "friction": ir["friction"], "expires_at": ir["expires_at"], "intent_required": ir}
    if ctx.get("inboxUrl"):
        out["inbox_url"] = ctx["inboxUrl"]
    return out


def clarification_notice(session: str, question_id: str, inbox_url: Optional[str] = None) -> Dict[str, Any]:
    """A notice for a wallet-originated question (clarification): ids only."""
    out: Dict[str, Any] = {"type": "pca.intent.clarification", "session": session, "question_id": question_id}
    if inbox_url:
        out["inbox_url"] = inbox_url
    return out


def question_text(notice: dict, site_name: str) -> Dict[str, str]:
    """The fixed text of a text-surface notice."""
    is_q = notice["type"] == "pca.intent.question"
    who = (clean_text(site_name, 64) or "A site") if is_q else "Your agent"
    subject = "%s has a question about your request" % who if is_q else "%s needs a decision about your request" % who
    inbox = notice.get("inbox_url")
    link = None
    if inbox:
        link = "%s%squestion=%s" % (inbox, "&" if "?" in inbox else "?", quote(notice["question_id"], safe="-_.!~*'()"))
    return {"subject": subject, "text": "\n".join([subject, "", "Open your wallet to answer: %s" % link if link else "Open your wallet to answer."])}


class QuestionChannel:
    """One delivery channel: `kind`, `enabled` and `notify(notice) -> delivery`."""

    def __init__(self, kind: str, enabled: bool, notify: Callable[[dict], Dict[str, Any]]):
        self.kind = kind
        self.enabled = enabled
        self.notify = notify


def _no_fetch(_url: Any, _init: Any) -> Any:
    raise RuntimeError("no fetch available: pass a FetchLike transport")


def question_webhook_channel(config: Optional[dict] = None) -> QuestionChannel:
    """Webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question included."""
    config = config if config is not None else {}
    url = config.get("url")
    enabled = isinstance(url, str) and len(url) > 0
    transport = config.get("fetch") or _no_fetch
    headers = {"content-type": "application/json", **(config.get("headers") or {})}

    def notify(notice: dict) -> Dict[str, Any]:
        base = {"kind": "webhook", "questionId": notice["question_id"], "payload": notice}
        if not enabled or url is None:
            return {**base, "delivered": False, "reason": "webhook channel not configured"}
        try:
            res = transport(url, {"method": "POST", "headers": headers, "body": json.dumps(notice, separators=(",", ":"), ensure_ascii=False)})
            if res["ok"]:
                return {**base, "delivered": True, "status": res["status"]}
            return {**base, "delivered": False, "status": res["status"], "reason": "webhook returned %s" % res["status"]}
        except Exception as err:  # noqa: BLE001 - a transport failure is a failed delivery, not an exception
            return {**base, "delivered": False, "reason": str(err) or "webhook transport error"}

    return QuestionChannel("webhook", enabled, notify)


def question_text_channel(kind: str, config: dict) -> QuestionChannel:
    """Email / SMS / push delivery through the per-instance sender port (fixed text only)."""
    send = config.get("send")
    enabled = callable(send)

    def notify(notice: dict) -> Dict[str, Any]:
        body = question_text(notice, config["siteName"])
        base = {"kind": kind, "questionId": notice["question_id"], "payload": body}
        if not enabled or send is None:
            return {**base, "delivered": False, "reason": "%s channel not configured" % kind}
        try:
            send(body)
            return {**base, "delivered": True}
        except Exception as err:  # noqa: BLE001
            return {**base, "delivered": False, "reason": str(err) or "%s send error" % kind}

    return QuestionChannel(kind, enabled, notify)


class QuestionDispatcher:
    def __init__(self, channels: List[QuestionChannel]):
        self.channels = channels

    def notify_all(self, notice: dict) -> List[Dict[str, Any]]:
        """Fan a notice out to every enabled channel (disabled channels are skipped)."""
        return [c.notify(notice) for c in self.channels if c.enabled]


def create_question_dispatcher(channels: List[QuestionChannel]) -> QuestionDispatcher:
    return QuestionDispatcher(channels)
