"""Typed step-up lifecycle events and signed webhooks (the TypeScript reference, @atlasauth/pca-events).

A step-up ceremony creates a grant, then approves, denies, or lets it expire; this turns those four moments into small
content-addressed events you can serialize, HMAC-sign and ship to your own inbox, then verify on the way in. It decides nothing:
it is a transport contract (a stable event shape plus a Stripe-style signature so a receiver can tell a real delivery from a forged
or replayed one). Events are plain dicts: ``{id, type, at, grant_ref, action: {verb, resource}, tier, actor?}``."""
from __future__ import annotations

from ._fin import fin
import hashlib
import hmac
import json
import math
import re
import struct
import time
from decimal import Decimal
from typing import Any, Dict, List, Optional

from .pca import b64u, hash_canonical

EVENT_TYPES = ("step_up.created", "step_up.approved", "step_up.denied", "step_up.expired")
#: smallest secret accepted: a short or empty HMAC key makes every signature guessable
MIN_SECRET_BYTES = 16
MAX_HEADER_CHARS = 2048
_ID_DOMAIN = "atlas-pca/stepup-event/v1"
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")
# the characters JavaScript's String.prototype.trim removes (not Python's strip set)
_JS_SPACE = "\t\n\x0b\x0c\r \xa0                　﻿"


def _finite(v: Any) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    try:
        return fin(float(v))
    except OverflowError:
        return False


def _wf(x: Any) -> bool:
    """A string with no lone surrogate (the reference's well-formed test)."""
    return isinstance(x, str) and not any(0xD800 <= ord(c) <= 0xDFFF for c in x)


def _check_event_fields(who: str, e: Any, with_id: bool) -> None:
    """The fields every event carries, checked the same way at build and at serialize time (fail closed on anything else)."""
    def bad(m: str) -> None:
        raise TypeError("%s: %s" % (who, m))
    if not isinstance(e, dict):
        bad("not an object")
    if e.get("type") not in EVENT_TYPES or not isinstance(e.get("type"), str) or isinstance(e.get("tier"), bool) or e.get("tier") not in (2, 3):
        bad("unknown event type or tier")
    if "at" in e and not _finite(e["at"]):
        bad("at must be a finite number")
    if not _wf(e.get("grant_ref")):
        bad("grant_ref must be a well-formed string")
    a = e.get("action")
    if not isinstance(a, dict) or not _wf(a.get("verb")) or not _wf(a.get("resource")):
        bad("action must carry well-formed verb and resource strings")
    if "actor" in e and not _wf(e["actor"]):
        bad("actor must be a well-formed string")
    if with_id and not _wf(e.get("id")):
        bad("id must be a well-formed string")


def _event_id(e: Dict[str, Any]) -> str:
    body = {"d": _ID_DOMAIN, "type": e["type"], "at": e["at"], "grant_ref": e["grant_ref"],
            "action": {"verb": e["action"]["verb"], "resource": e["action"]["resource"]}, "tier": e["tier"]}
    if "actor" in e:
        body["actor"] = e["actor"]
    return hash_canonical(body)


def build_step_up_event(type: Any, data: Any) -> Dict[str, Any]:
    """Build a step-up event, filling ``at`` (default: the clock, ms) and deriving a content-addressed ``id`` from every other
    field. ``data``: ``{at?, grant_ref, action: {verb, resource}, tier, actor?}``; a missing member raises."""
    if not isinstance(data, dict) or not isinstance(data.get("action"), dict):
        raise TypeError("buildStepUpEvent: data and data.action must be objects")
    _check_event_fields("buildStepUpEvent", {**data, "type": type}, False)
    at = data.get("at")
    base: Dict[str, Any] = {
        "type": type,
        "at": int(time.time() * 1000) if at is None else at,
        "grant_ref": data["grant_ref"],
        "action": {"verb": data["action"]["verb"], "resource": data["action"]["resource"]},
        "tier": data["tier"],
    }
    if "actor" in data:
        base["actor"] = data["actor"]
    return {**base, "id": _event_id(base)}


# ---- JSON.stringify -----------------------------------------------------------------------------------------------

def _js_str(s: str) -> str:
    out = ['"']
    names = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    for ch in s:
        o = ord(ch)
        if ch in names:
            out.append(names[ch])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:  # a lone surrogate is escaped, as well-formed JSON.stringify does
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _js_num(v: Any) -> str:
    """Number::toString for a JSON number (NaN and infinities print as null, -0 as 0)."""
    if isinstance(v, int):
        if abs(v) < 2 ** 53:
            return str(v)
        try:
            v = float(v)
        except OverflowError:
            return "null"
    if not fin(v):
        return "null"
    if v == 0:
        return "0"
    d = Decimal(repr(abs(v))).normalize()
    digits = "".join(map(str, d.as_tuple().digits))
    k = len(digits)
    n = k + d.as_tuple().exponent
    sign = "-" if v < 0 else ""
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        body = digits + "e" + es if k == 1 else digits[0] + "." + digits[1:] + "e" + es
    return sign + body


def _is_index(k: str) -> bool:
    return k.isascii() and k.isdigit() and (k == "0" or k[0] != "0") and len(k) <= 10 and int(k) < 4294967295


def _stringify(v: Any, out: List[str]) -> None:
    if v is None:
        out.append("null")
    elif isinstance(v, bool):
        out.append("true" if v else "false")
    elif isinstance(v, str):
        out.append(_js_str(v))
    elif isinstance(v, (int, float)):
        out.append(_js_num(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _stringify(x, out)
        out.append("]")
    elif isinstance(v, dict):
        # JavaScript orders integer-like keys first (ascending), then the rest in insertion order
        idx = sorted((k for k in v if _is_index(k)), key=int)
        keys = idx + [k for k in v if not _is_index(k)]
        out.append("{")
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            out.append(_js_str(k) + ":")
            _stringify(v[k], out)
        out.append("}")
    else:
        raise TypeError("serializeEvent: unsupported value")


def serialize_event(e: Any) -> str:
    """The JSON wire form (what JSON.stringify gives: members in insertion order, integer-like keys first)."""
    _check_event_fields("serializeEvent", e, True)
    if "at" not in e:
        raise TypeError("serializeEvent: at must be a finite number")
    out: List[str] = []
    _stringify(e, out)
    return "".join(out)


def _no_constant(name: str) -> Any:
    raise ValueError("non-JSON constant " + name)


def _parse_float(s: str) -> Any:
    # JavaScript has one number type: 1700000000000.0 and 17e11 are the integer a digest sees
    f = float(s)
    return int(f) if f.is_integer() and abs(f) < 2 ** 53 else f


def parse_event(s: Any) -> Dict[str, Any]:
    """Parse and validate a JSON step-up event. Raises ``ValueError`` on anything that is not a well-formed event, including an id
    that is not the digest of the fields (the event was edited or forged)."""
    if not isinstance(s, str):
        raise ValueError("JSON.parse: not a string")
    try:
        raw = json.loads(s, parse_constant=_no_constant, parse_float=_parse_float)
    except (ValueError, RecursionError) as e:
        raise ValueError("JSON.parse: %s" % e)
    if not isinstance(raw, (dict, list)):
        raise ValueError("parseEvent: not an object")
    o = raw if isinstance(raw, dict) else {}
    if not isinstance(o.get("id"), str) or len(o["id"]) == 0:
        raise ValueError("parseEvent: bad id")
    if not isinstance(o.get("type"), str) or o["type"] not in EVENT_TYPES:
        raise ValueError("parseEvent: bad type")
    if not _finite(o.get("at")):
        raise ValueError("parseEvent: bad at")
    if not isinstance(o.get("grant_ref"), str):
        raise ValueError("parseEvent: bad grant_ref")
    action = o.get("action")
    if not isinstance(action, (dict, list)):
        raise ValueError("parseEvent: bad action")
    a = action if isinstance(action, dict) else {}
    if not isinstance(a.get("verb"), str) or not isinstance(a.get("resource"), str):
        raise ValueError("parseEvent: bad action fields")
    tier = o.get("tier")
    if isinstance(tier, bool) or tier not in (2, 3):
        raise ValueError("parseEvent: bad tier")
    event: Dict[str, Any] = {"id": o["id"], "type": o["type"], "at": o["at"], "grant_ref": o["grant_ref"],
                             "action": {"verb": a["verb"], "resource": a["resource"]}, "tier": int(tier)}
    if "actor" in o:
        if not isinstance(o["actor"], str):
            raise ValueError("parseEvent: bad actor")
        event["actor"] = o["actor"]
    try:
        digest = _event_id(event)
    except (TypeError, ValueError, OverflowError, RecursionError) as e:
        raise ValueError("canonicalize: %s" % e)
    if digest != event["id"]:
        raise ValueError("parseEvent: id does not match the event content")
    return event


# ---- signed webhooks ----------------------------------------------------------------------------------------------

def _utf8(s: str) -> bytes:
    # TextEncoder writes U+FFFD for a lone surrogate (Python's strict encoder refuses it)
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def _secret_bytes(secret: Any) -> Optional[bytes]:
    b = _utf8(secret) if isinstance(secret, str) else bytes(secret) if isinstance(secret, (bytes, bytearray)) else None
    return b if b is not None and len(b) >= MIN_SECRET_BYTES else None


def _js_trim(s: str) -> str:
    return s.strip(_JS_SPACE)


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _parse_signature_header(h: Any) -> Optional[Dict[str, Any]]:
    """Parse ``t=<digits>,v1=<hex>[,v1=<hex>...]``. Several ``v1`` are allowed (secret rotation); two different ``t`` are not."""
    if not isinstance(h, str) or _utf16_len(h) > MAX_HEADER_CHARS:
        return None
    t: Optional[int] = None
    v1: List[str] = []
    for part in h.split(","):
        eq = part.find("=")
        if eq < 0:
            continue
        key, val = _js_trim(part[:eq]), _js_trim(part[eq + 1:])
        if key == "t":
            if not (val.isascii() and val.isdigit() and 1 <= len(val) <= 15):
                return None
            n = int(val)
            if t is not None and t != n:
                return None
            t = n
        elif key == "v1":
            v1.append(val)
    if t is None or not v1:
        return None
    return {"t": t, "v1": v1}


def _mac(key: bytes, t: int, payload: str) -> bytes:
    return hmac.new(key, _utf8("%d.%s" % (t, payload)), hashlib.sha256).digest()


def sign_webhook(secret: Any, payload: str, timestamp: Any = None) -> str:
    """Stripe-style signature for a webhook payload: ``t=<unixSeconds>,v1=<hex HMAC-SHA256 of "<t>.<payload>">``. ``timestamp`` pins
    the second count (default: the clock). Raises ``ValueError`` on a secret shorter than :data:`MIN_SECRET_BYTES` bytes and on a
    timestamp that is not a non-negative safe integer; the error never contains the secret."""
    key = _secret_bytes(secret)
    if key is None:
        raise ValueError("signWebhook: the secret must be at least %d bytes" % MIN_SECRET_BYTES)
    t = int(time.time()) if timestamp is None else timestamp
    ok = isinstance(t, (int, float)) and not isinstance(t, bool) and fin(t) and float(t) == math.floor(t) and 0 <= t <= 2 ** 53 - 1
    if not ok:
        raise ValueError("signWebhook: timestamp must be a non-negative integer (unix seconds)")
    t = int(t)
    return "t=%d,v1=%s" % (t, _mac(key, t, payload).hex())


def verify_webhook(secret: Any, payload: str, signature_header: Any, tolerance_sec: Any = None, now: Any = None) -> bool:
    """Verify a signature header against the payload: recompute the HMAC, compare constant-time, and enforce the timestamp tolerance
    (default 300 s). Returns False, never raises, on a malformed header, a bad signature, a stale timestamp, a secret that is too
    short, or a tolerance / clock that is not a finite non-negative number. With several ``v1`` entries any one may match. ``now`` is
    unix seconds. A valid signature is not proof of freshness beyond the window: use :func:`verify_delivery` to also refuse a replay."""
    try:
        key = _secret_bytes(secret)
        if key is None:
            return False
        parsed = _parse_signature_header(signature_header)
        if parsed is None:
            return False
        tol = 300 if tolerance_sec is None else tolerance_sec
        clock = int(time.time()) if now is None else now
        if not _finite(tol) or tol < 0 or not _finite(clock):
            return False
        if abs(clock - parsed["t"]) > tol:
            return False
        expected = _mac(key, parsed["t"], payload)
        match = False
        for v in parsed["v1"]:
            if _HEX.fullmatch(v) is None:
                continue
            if hmac.compare_digest(expected, bytes.fromhex(v)):
                match = True  # no early exit: every candidate costs the same
        return match
    except Exception:  # noqa: BLE001 - a verifier answers False, never raises
        return False


def replay_key(namespace: str, *parts: str) -> str:
    """A length-prefixed, injective key over the parts, hashed to a fixed size; a part that is not a string or holds a lone surrogate raises."""
    buf = b""
    for p in (namespace,) + parts:
        if not isinstance(p, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in p):
            raise TypeError("replayKey: every part must be a well-formed string (no lone surrogates)")
        b = p.encode("utf-8")
        buf += struct.pack(">I", len(b)) + b
    return "%s:%s" % (namespace, b64u(hashlib.sha256(buf).digest()))


def verify_delivery(secret: Any, payload: str, signature_header: Any, replay: Any = None, tolerance_sec: Any = None,
                    now: Any = None) -> Dict[str, Any]:
    """Accept one webhook delivery: signature and freshness (:func:`verify_webhook`), a well-formed event whose id matches its content
    (:func:`parse_event`), and a first sight of that event id (``replay.consume_once(key, retain_until_ms, now_ms)``, e.g. a
    :class:`atlas_pca.MemoryStateStore`). A store that raises refuses. Never raises, and no reason contains the secret or the payload.
    Returns ``{"ok": True, "event"}`` or ``{"ok": False, "reason"}``."""
    def no(why: str) -> Dict[str, Any]:
        return {"ok": False, "reason": why}

    try:
        if not callable(getattr(replay, "consume_once", None)):
            return no("a replay store is required")
        if not verify_webhook(secret, payload, signature_header, tolerance_sec, now):
            return no("bad signature")
        try:
            event = parse_event(payload)
        except Exception as e:  # noqa: BLE001 - the reason is the validation message
            return no(str(e))
        sig = _parse_signature_header(signature_header)
        now_sec = int(time.time()) if now is None else now
        tol = 300 if tolerance_sec is None else tolerance_sec
        try:
            # a fractional horizon rounds toward longer retention (ceil for the horizon, floor for the clock)
            first = replay.consume_once(replay_key("pca-stepup-event/v1", event["id"]), math.ceil((sig["t"] + tol) * 1000 + 1), math.floor(now_sec * 1000))
            if not first:
                return no("replayed delivery")
        except Exception:  # noqa: BLE001 - an unavailable store refuses
            return no("replay store unavailable")
        return {"ok": True, "event": event}
    except Exception:  # noqa: BLE001 - never raises
        return no("bad signature")


def webhook_headers(secret: Any, payload: str, timestamp: Any = None) -> Dict[str, str]:
    """The headers to attach to an outbound webhook POST."""
    return {"PCA-Signature": sign_webhook(secret, payload, timestamp), "content-type": "application/json"}


__all__ = ["EVENT_TYPES", "MIN_SECRET_BYTES", "build_step_up_event", "parse_event", "replay_key", "serialize_event", "sign_webhook",
           "verify_delivery", "verify_webhook", "webhook_headers"]
