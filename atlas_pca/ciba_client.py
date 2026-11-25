"""A network client for a real OpenID Provider's CIBA endpoints (OpenID CIBA Core 1.0): start a backchannel authentication request
and wait for the human's decision by POLL or PING. Mirrors the TypeScript reference (@atlasauth/pca-ciba).

Poll discipline follows CIBA Core 7.3 / 11: never faster than the ``interval`` the OP returned, at least 5 seconds more on every
``slow_down``, stop at ``expires_in``. A terminal answer is cached, so a settled flow is never re-sent to the token endpoint (an
approved ``auth_req_id`` is single-use at real providers). The client authenticates with ``client_secret_basic``; the returned
tokens are the OP's response, not verified here.

HTTP is an injected callable ``fetch(url, headers, body, timeout_ms) -> {"status": int, "body": str}`` (a POST of a form body; a
default over ``urllib`` is used when omitted), ``sleep(ms)`` and ``now() -> ms`` are injectable too. To cancel a wait, pass a
``threading.Event`` as ``signal`` and set it. Results are dicts: ``{"status": "pending", "interval_sec"}``,
``{"status": "approved", "tokens"}``, ``{"status": "denied", "error"}`` or ``{"status": "expired"}``."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

from ._fin import fin
from .ciba import to_ciba_auth_request

CIBA_GRANT = "urn:openid:params:grant-type:ciba"
SLOW_DOWN_STEP_SEC = 5
MIN_NOTIFICATION_TOKEN_CHARS = 22
MAX_NOTIFICATION_TOKEN_CHARS = 1024
DEFAULT_TIMEOUT_MS = 30000
MAX_BACKOFF_MS = 60000
MAX_CONSECUTIVE_TRANSIENT = 5
_WS = "\t\n\v\f\r    -     　﻿"
_BEARER = re.compile(r"bearer +([^" + _WS + r"]+)", re.I | re.A)
_PRINTABLE = re.compile(r"[\x21-\x7E]+")


class CibaProviderError(Exception):
    """An error response from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply. ``retryable`` is true for network errors,
    timeouts, 5xx and non-JSON replies, false for a definitive OP answer."""

    def __init__(self, status: int, error: str, error_description: Optional[str] = None, retryable: bool = False) -> None:
        super().__init__("ciba: provider returned %d %s%s" % (status, error, " (%s)" % error_description if error_description is not None else ""))
        self.status = status
        self.error = error
        self.error_description = error_description
        self.retryable = retryable


class CibaWaitAborted(Exception):
    pass


@dataclass
class CibaFlow:
    auth_req_id: str
    expires_in_sec: int
    interval_sec: int
    started_at: float
    delivery: str
    request: Dict[str, Any]
    client_notification_token: Optional[str] = None


def _form_encode(pairs: List[Tuple[str, str]]) -> str:
    """URLSearchParams.toString(): space is '+', letters, digits and *-._ stay, everything else is %XX over UTF-8."""
    def enc(s: str) -> str:
        out = []
        for b in s.encode("utf-8", "replace"):
            c = chr(b)
            out.append(c if (c.isascii() and c.isalnum()) or c in "*-._" else "+" if c == " " else "%%%02X" % b)
        return "".join(out)
    return "&".join("%s=%s" % (enc(k), enc(v)) for k, v in pairs)


def _default_fetch(url: str, headers: Dict[str, str], body: str, timeout_ms: float) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=body.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000) as r:
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", "replace")}


def _no_const(c: str) -> Any:
    raise ValueError(c)


def _read_json(res: Dict[str, Any]) -> Dict[str, Any]:
    status = res["status"]
    try:
        parsed = json.loads(res.get("body") or "", parse_constant=_no_const)
    except ValueError:
        raise CibaProviderError(status, "invalid_response", "the provider reply was not JSON", True)
    if not isinstance(parsed, dict):
        raise CibaProviderError(status, "invalid_response", "the provider reply was not a JSON object")
    return parsed


def _provider_error(status: int, body: Dict[str, Any]) -> CibaProviderError:
    err = body.get("error")
    desc = body.get("error_description")
    return CibaProviderError(status, err if isinstance(err, str) else "invalid_response", desc if isinstance(desc, str) else None)


def _positive_int(value: Any, name: str, status: int) -> int:
    ok = not isinstance(value, bool) and ((isinstance(value, int) and abs(value) <= 2 ** 53 - 1) or (isinstance(value, float) and value.is_integer() and abs(value) <= 2 ** 53 - 1))
    if not ok or value <= 0:
        raise CibaProviderError(status, "invalid_response", "%s must be a positive integer" % name)
    return int(value)


def _check_endpoint(name: str, value: Any, allow_insecure: bool) -> None:
    p = urlparse(value) if isinstance(value, str) else None
    if p is None or not p.scheme or (p.scheme.lower() in ("http", "https", "ftp", "ws", "wss") and not p.hostname):
        raise ValueError("ciba: %s is not a valid URL" % name)
    if p.scheme.lower() == "https" or (p.scheme.lower() == "http" and allow_insecure):
        return
    raise ValueError("ciba: %s must be an https:// URL (set allowInsecureHttp only for a local test provider)" % name)


def new_client_notification_token() -> str:
    """A fresh ``client_notification_token`` (CIBA Core 7.1: at least 128 bits of entropy, at most 1024 characters)."""
    return secrets.token_urlsafe(32)


def _sec(ms: float) -> Any:
    v = ms / 1000
    return int(v) if v == int(v) else v


class CibaPoller:
    def __init__(self, client: "CibaClient", flow: CibaFlow) -> None:
        self._c = client
        self._flow = flow
        self._interval_ms = flow.interval_sec * 1000
        self._next_at = flow.started_at + self._interval_ms
        self._deadline = flow.started_at + flow.expires_in_sec * 1000
        self._settled: Optional[Dict[str, Any]] = None
        self._failures = 0
        self._wake: Optional[threading.Event] = None
        self._lock = threading.Lock()
        self._inflight: Optional[Dict[str, Any]] = None

    def interval_sec(self) -> Any:
        """Current poll interval in seconds (grows on ``slow_down``)."""
        return _sec(self._interval_ms)

    def notify(self) -> None:
        """A PING arrived: the next ``poll`` may go out immediately, and a ``poll`` / ``wait`` that is sleeping wakes now."""
        self._next_at = self._c._clock()
        w = self._wake
        if w is not None:
            w.set()

    def _pause(self, ms: float, signal: Optional[threading.Event]) -> None:
        wake = threading.Event()
        self._wake = wake
        try:
            if self._c._sleep is not None:
                self._c._sleep(ms)
            else:
                end = time.monotonic() + ms / 1000
                while not wake.is_set() and not (signal is not None and signal.is_set()):
                    left = end - time.monotonic()
                    if left <= 0:
                        break
                    wake.wait(min(left, 0.05))
        finally:
            self._wake = None
        if signal is not None and signal.is_set():
            raise CibaWaitAborted("ciba: wait aborted")

    def _backoff(self) -> None:
        self._failures += 1
        self._next_at = self._c._clock() + min(MAX_BACKOFF_MS, self._interval_ms * 2 ** min(self._failures, 6))

    def _do_poll(self, signal: Optional[threading.Event]) -> Dict[str, Any]:
        c = self._c
        if self._settled is not None:
            return self._settled
        wait = self._next_at - c._clock()
        if wait > 0:
            self._pause(wait, signal)
        if self._settled is not None:
            return self._settled
        if c._clock() >= self._deadline:
            self._settled = {"status": "expired"}
            return self._settled
        try:
            res = c._post(c._token_endpoint, [("grant_type", CIBA_GRANT), ("auth_req_id", self._flow.auth_req_id)], signal)
            if res["status"] >= 500:
                raise CibaProviderError(res["status"], "server_error", "the provider answered with a server error", True)
            body = _read_json(res)
        except CibaProviderError as e:
            if e.retryable:
                self._backoff()
            raise
        self._failures = 0
        self._next_at = c._clock() + self._interval_ms
        status = res["status"]
        if 200 <= status < 300:
            if not isinstance(body.get("access_token"), str) or not isinstance(body.get("token_type"), str):
                raise CibaProviderError(status, "invalid_response", "token response lacks access_token / token_type")
            self._settled = {"status": "approved", "tokens": body}
            return self._settled
        err = _provider_error(status, body)
        if err.error == "authorization_pending":
            return {"status": "pending", "interval_sec": _sec(self._interval_ms)}
        if err.error == "slow_down":
            self._interval_ms += SLOW_DOWN_STEP_SEC * 1000
            self._next_at = c._clock() + self._interval_ms
            return {"status": "pending", "interval_sec": _sec(self._interval_ms)}
        if err.error == "access_denied":
            self._settled = {"status": "denied", "error": err.error}
            return self._settled
        if err.error == "expired_token":
            self._settled = {"status": "expired"}
            return self._settled
        raise err

    def poll(self, signal: Optional[threading.Event] = None) -> Dict[str, Any]:
        """Sleep until the interval allows it, then ask the token endpoint once. Concurrent callers share one in-flight request:
        an approved auth_req_id is single-use at real OPs."""
        with self._lock:
            f = self._inflight
            leader = f is None
            if leader:
                f = self._inflight = {"done": threading.Event()}
        if leader:
            try:
                f["result"] = self._do_poll(signal)
            except BaseException as e:
                f["exc"] = e
            finally:
                with self._lock:
                    self._inflight = None
                f["done"].set()
        else:
            f["done"].wait()
        if "exc" in f:
            raise f["exc"]
        return f["result"]

    def wait(self, signal: Optional[threading.Event] = None) -> Dict[str, Any]:
        """Poll until the flow settles (approved / denied / expired); honours ``signal``."""
        transient = 0
        while True:
            if signal is not None and signal.is_set():
                raise CibaWaitAborted("ciba: wait aborted")
            try:
                r = self.poll(signal)
                transient = 0
                if r["status"] != "pending":
                    return r
            except CibaProviderError as e:
                transient += 1
                if not e.retryable or transient >= MAX_CONSECUTIVE_TRANSIENT:
                    raise


class CibaClient:
    def __init__(self, backchannel_authentication_endpoint: str, token_endpoint: str, client_id: str, client_secret: str,
                 fetch: Optional[Callable[..., Dict[str, Any]]] = None, sleep: Optional[Callable[[float], Any]] = None,
                 now: Optional[Callable[[], float]] = None, timeout_ms: float = DEFAULT_TIMEOUT_MS, allow_insecure_http: bool = False) -> None:
        self._fetch = fetch or _default_fetch
        self._sleep = sleep
        self._clock = now or (lambda: int(time.time() * 1000))
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, (int, float)) or not fin(timeout_ms) or timeout_ms <= 0:
            raise ValueError("ciba: timeoutMs must be a positive number")
        self._timeout_ms = timeout_ms
        _check_endpoint("backchannelAuthenticationEndpoint", backchannel_authentication_endpoint, allow_insecure_http is True)
        _check_endpoint("tokenEndpoint", token_endpoint, allow_insecure_http is True)
        self._bc_endpoint = backchannel_authentication_endpoint
        self._token_endpoint = token_endpoint
        enc = lambda s: quote(s, safe="-_.!~*'()")
        self._basic = "Basic " + base64.b64encode(("%s:%s" % (enc(client_id), enc(client_secret))).encode("utf-8")).decode("ascii")

    def _post(self, url: str, form: List[Tuple[str, str]], signal: Optional[threading.Event] = None) -> Dict[str, Any]:
        if signal is not None and signal.is_set():
            raise CibaWaitAborted("ciba: wait aborted")
        headers = {"authorization": self._basic, "content-type": "application/x-www-form-urlencoded", "accept": "application/json"}
        try:
            return self._fetch(url, headers, _form_encode(form), self._timeout_ms)
        except Exception as e:
            if signal is not None and signal.is_set():
                raise CibaWaitAborted("ciba: wait aborted")
            raise CibaProviderError(0, "network_error", str(e) or "request failed", True)

    def initiate(self, step_up: Dict[str, Any], opts: Optional[Dict[str, Any]] = None) -> CibaFlow:
        """Start a backchannel request. Options are the request options of ``to_ciba_auth_request`` plus ``login_hint_token``,
        ``id_token_hint``, ``delivery`` ("poll" default | "ping"), ``client_notification_token``, ``acr_values``, ``user_code``."""
        o = opts or {}
        hints = [o.get(k) for k in ("login_hint", "login_hint_token", "id_token_hint") if o.get(k) is not None]
        if len(hints) != 1:
            raise ValueError("ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)")
        delivery = o["delivery"] if o.get("delivery") is not None else "poll"
        given = o.get("client_notification_token")
        token = (given if given is not None else new_client_notification_token()) if delivery == "ping" else None
        if given is not None and (len(given) < MIN_NOTIFICATION_TOKEN_CHARS or len(given) > MAX_NOTIFICATION_TOKEN_CHARS or _PRINTABLE.fullmatch(given) is None):
            raise ValueError("ciba: clientNotificationToken must be %d..%d printable characters (>= 128 bits, CIBA Core 7.1)" % (MIN_NOTIFICATION_TOKEN_CHARS, MAX_NOTIFICATION_TOKEN_CHARS))
        request = to_ciba_auth_request(step_up, o)
        form: Dict[str, str] = {"scope": request["scope"], "binding_message": request["binding_message"], "requested_expiry": str(request["requested_expiry"])}
        for key in ("login_hint", "login_hint_token", "id_token_hint", "acr_values", "user_code"):
            if o.get(key) is not None:
                form[key] = o[key]
        if token is not None:
            form["client_notification_token"] = token
        res = self._post(self._bc_endpoint, list(form.items()))
        body = _read_json(res)
        if not 200 <= res["status"] < 300:
            raise _provider_error(res["status"], body)
        auth_req_id = body.get("auth_req_id")
        if not isinstance(auth_req_id, str) or len(auth_req_id) == 0:
            raise CibaProviderError(res["status"], "invalid_response", "auth_req_id missing")
        expires = _positive_int(body.get("expires_in"), "expires_in", res["status"])
        interval = 5 if "interval" not in body else _positive_int(body["interval"], "interval", res["status"])  # CIBA Core 7.3: default 5 s
        return CibaFlow(auth_req_id, expires, interval, self._clock(), delivery, request, token)

    def poller(self, flow: CibaFlow) -> CibaPoller:
        return CibaPoller(self, flow)


def create_ciba_client(**cfg: Any) -> CibaClient:
    return CibaClient(**cfg)


def verify_ping_callback(inp: Dict[str, Any], flow: Any) -> str:
    """Validate a PING callback (CIBA Core 10.2): ``Authorization: Bearer <client_notification_token>`` and a JSON body
    ``{"auth_req_id": ...}`` (``inp`` = ``{"authorization", "body"}``). Returns the ``auth_req_id`` only when the bearer matches the
    token sent for that flow (constant time); raises otherwise. The callback carries no decision: ``notify`` then ``poll``."""
    get = (lambda k: flow.get(k)) if isinstance(flow, dict) else (lambda k: getattr(flow, k, None))
    token = get("client_notification_token")
    if token is None:
        raise ValueError("ciba: flow was not started in ping mode")
    auth = inp.get("authorization")
    m = _BEARER.fullmatch(auth if isinstance(auth, str) else "")
    if m is None:
        raise ValueError("ciba: ping callback lacks a bearer token")
    digest = lambda v: hashlib.sha256(v.encode("utf-8", "replace")).digest()
    if not hmac.compare_digest(digest(m.group(1)), digest(token)):
        raise ValueError("ciba: ping callback bearer does not match the client_notification_token")
    body = inp.get("body")
    id_ = body.get("auth_req_id") if isinstance(body, dict) else None
    if not isinstance(id_, str) or id_ != get("auth_req_id"):
        raise ValueError("ciba: ping callback auth_req_id does not match this flow")
    return id_
