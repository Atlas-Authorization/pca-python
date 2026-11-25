"""A CIBA on-ramp for PCA's FROST step-up: turn a step-up request into an OpenID CIBA backchannel authentication request
(binding message, scope, expiry, interval) with risk-adaptive gating. Mirrors the TypeScript reference (@atlasauth/pca-ciba).

A step-up is a dict with the reference's field names (``id``, ``verb``, ``resource``, ``params``, ``tier``, ``goalCommit``,
``goal``, ``render``, ``renderDigest``). Request options are a dict with snake_case keys: ``expires_in_sec``, ``auth_req_id``,
``step_up_scope``, ``login_hint``, ``binding_message`` (``{"max_chars", "token_only"}``), ``interval``, ``acts_for``. Every
refusal raises ``ValueError`` (the reference's RangeError) or ``TypeError``; the produced request dict keeps the reference's
(wire and store) key names so a record written here is readable by the reference and the other way round.

This module authorises nothing on its own: the resource server's verifier and the FROST cosigners remain the authority."""
from __future__ import annotations
from ._fin import fin

import re
import unicodedata
from typing import Any, Dict, List, Optional, Set

from .approval import approval_render_digest, binding_words
from .idna_host import domain_to_ascii
from .pca import hash_canonical
from .risk import recharge, recharge_full
from .sdjwt_jws import js_num

DEFAULT_EXPIRY_SEC = 300
DEFAULT_INTERVAL_SEC = 5
MIN_AUTH_REQ_ID_LEN = 22
MAX_GOAL_CHARS = 100
MAX_PAYEE_CHARS = 64
PAYEE_KEYS = ("payee", "to", "recipient", "beneficiary", "destination")
DISPLAYED_PARAM_KEYS = frozenset(("amount", "currency") + PAYEE_KEYS)

# JavaScript's \s, spelled out (Python's differs: it also covers \x1c-\x1f and \x85).
_WS = "\t\n\v\f\r    -     　﻿"
_WS_RUN = re.compile("[" + _WS + "]+")
_WS_TWO = re.compile("[" + _WS + "]{2,}")
_FORGED_CLAUSE = re.compile("because[" + _WS + "]+you[" + _WS + "]+asked", re.I | re.A)
_AUTH_REQ_ID = re.compile(r"[A-Za-z0-9._-]+")
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,63}")
_PLAIN_AMOUNT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
_CURRENCY = re.compile(r"[A-Za-z]{3}")
_ASCII_PRINTABLE = re.compile(r"[\x20-\x7E]*")


def _js_trim(s: str) -> str:
    return re.sub("^[" + _WS + "]+|[" + _WS + "]+\\Z", "", s)


def _js_str(v: Any) -> str:
    """String(v) for a JSON value."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return js_num(v)
    return v if isinstance(v, str) else str(v)


def _safe_int(v: Any) -> bool:
    """Number.isSafeInteger."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) <= 2 ** 53 - 1
    return isinstance(v, float) and v == v and v not in (float("inf"), float("-inf")) and v.is_integer() and abs(v) <= 2 ** 53 - 1


def _u16_prefix(s: str, n: int) -> str:
    return s.encode("utf-16-le", "surrogatepass")[: 2 * n].decode("utf-16-le", "surrogatepass")


def plain_text(value: str) -> str:
    """Control, format (bidi, zero-width) and line-separator characters become spaces; whitespace runs collapse."""
    if not isinstance(value, str):
        raise TypeError("ciba: expected a string")
    s = "".join(" " if (unicodedata.category(c) in ("Cc", "Cf") or c in "  ") else c for c in value)
    return _js_trim(_WS_RUN.sub(" ", s))


def clip(value: str, max_chars: float) -> str:
    return value if len(value) <= max_chars else value[: int(max_chars) - 1] + "…"


def _identifier(value: Any, what: str) -> str:
    if not isinstance(value, str) or _IDENT.fullmatch(value) is None:
        raise ValueError("ciba: the step-up %s must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message" % what)
    if _FORGED_CLAUSE.search(value):
        raise ValueError("ciba: the step-up %s contains an approval-explanation clause" % what)
    return value


# ---- scripts (the payee homograph check) ------------------------------------------------------------------------------------

_SCRIPT_PREFIXES = (
    ("latin", ("LATIN",)),
    ("cyrillic", ("CYRILLIC",)),
    ("greek", ("GREEK",)),
    ("armenian", ("ARMENIAN",)),
    ("hebrew", ("HEBREW",)),
    ("arabic", ("ARABIC",)),
    ("cjk", ("CJK", "HIRAGANA", "KATAKANA", "HANGUL", "BOPOMOFO", "IDEOGRAPHIC ITERATION")),
    ("indic-thai", ("DEVANAGARI", "BENGALI", "TAMIL", "THAI", "GEORGIAN")),
)
# Letters whose name starts like a script but whose Script property is Common; and Han letters with other names.
_COMMON_LETTERS = {0x0640, 0x30FC, 0x303C} | set(range(0x3031, 0x3036))
_HAN_EXTRA = {0x3005, 0x3006, 0x3007} | set(range(0x3021, 0x302A)) | set(range(0x3038, 0x303C))
# shortcut: script groups come from Unicode character names, not the Script property (stdlib has none); upgrade with a script table.


def _scripts_of(t: str) -> Set[str]:
    found: Set[str] = set()
    for ch in t:
        if not unicodedata.category(ch).startswith("L"):
            continue
        cp = ord(ch)
        group = None
        if cp in _HAN_EXTRA:
            group = "cjk"
        elif cp not in _COMMON_LETTERS:
            name = unicodedata.name(ch, "")
            for g, prefixes in _SCRIPT_PREFIXES:
                if name.startswith(prefixes):
                    group = g
                    break
        found.add(group if group is not None else "other:" + ch)
    return found


def _payee_text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("ciba: the payee must be a string (a nested value cannot be shown to the approver)")
    t = unicodedata.normalize("NFC", value)
    if len(t) == 0 or _js_trim(t) != t or _WS_TWO.search(t):
        raise ValueError("ciba: the payee must be non-empty without leading, trailing or repeated whitespace")
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn") or c in "  " or "￹" <= c <= "�" for c in t):
        raise ValueError("ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed")
    if '"' in t or "\\" in t:
        raise ValueError("ciba: the payee must not contain quote or backslash characters")
    if len(t) > MAX_PAYEE_CHARS:
        raise ValueError("ciba: the payee is longer than %d characters; refusing to truncate what the person approves" % MAX_PAYEE_CHARS)
    if _FORGED_CLAUSE.search(t):
        raise ValueError("ciba: the payee contains an approval-explanation clause")
    if any(unicodedata.category(c).startswith("M") for c in t):
        raise ValueError("ciba: the payee contains combining marks and cannot be shown unambiguously")
    if unicodedata.normalize("NFKC", t) != t:
        raise ValueError("ciba: the payee contains compatibility/fullwidth characters that imitate plain ones")
    if len(_scripts_of(t)) > 1:
        raise ValueError("ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike")
    return t


def _domain_to_ascii(w: str) -> str:
    """WHATWG domainToASCII (see idna_host); '' when a label cannot be encoded."""
    return domain_to_ascii(w)


def ascii_form(payee: str) -> str:
    """Plain-ASCII rendering of a payee: itself when ASCII, else the punycode of each word (or \\u escapes when IDNA refuses)."""
    if _ASCII_PRINTABLE.fullmatch(payee):
        return payee
    words = []
    for w in payee.split(" "):
        if _ASCII_PRINTABLE.fullmatch(w):
            words.append(w)
        else:
            words.append(_domain_to_ascii(w) or "".join("\\u{%x}" % ord(c) if ord(c) > 0x7E else c for c in w))
    return " ".join(words)


def ciba_action_from_step_up(step_up: Dict[str, Any]) -> Dict[str, Any]:
    """The canonical action shown to the approver; fails loud (unknown params, a nested or malformed amount, a missing currency or
    payee next to an amount, two payee fields, a non-identifier verb / resource)."""
    params = step_up.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError("ciba: step-up params must be an object")
    unknown = [k for k in params if k not in DISPLAYED_PARAM_KEYS]
    if unknown:
        raise ValueError("ciba: step-up params field(s) %s are not displayed in the approval message (displayable: amount, currency, %s); refusing so the person never approves a hidden field" % (", ".join(unknown), "/".join(PAYEE_KEYS)))
    action: Dict[str, Any] = {"verb": _identifier(step_up.get("verb"), "verb"), "resource": _identifier(step_up.get("resource"), "resource")}
    payee_keys = [k for k in PAYEE_KEYS if params.get(k) is not None]
    if len(payee_keys) > 1:
        raise ValueError("ciba: more than one payee field (%s) in params; the approver would see only one" % ", ".join(payee_keys))
    if params.get("amount") is not None:
        amt = params["amount"]
        if isinstance(amt, bool):
            text = ""
        elif isinstance(amt, (int, float)):
            text = js_num(amt) if fin(amt) else ""
        else:
            text = amt if isinstance(amt, str) else ""
        if _PLAIN_AMOUNT.fullmatch(text) is None:
            raise ValueError("ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)")
        cur = params.get("currency")
        if not isinstance(cur, str) or _CURRENCY.fullmatch(cur) is None:
            raise ValueError("ciba: the binding message needs a 3-letter currency code next to the amount")
        if not payee_keys:
            raise ValueError("ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it")
        action["amount"] = text
        action["currency"] = cur.upper()
    elif params.get("currency") is not None:
        raise ValueError("ciba: a currency without an amount cannot be displayed")
    if len(payee_keys) == 1:
        action["payee"] = _payee_text(params[payee_keys[0]])
    return action


def _binding_message(step_up: Dict[str, Any], acts_for: str, max_chars: Optional[int] = None) -> str:
    a = ciba_action_from_step_up(step_up)
    head = "Approve " + a["verb"]
    if "amount" in a:
        head += " %s %s" % (a["amount"], a["currency"])
    if "payee" in a:
        head += ' to "%s"' % a["payee"]
        if not _ASCII_PRINTABLE.fullmatch(a["payee"]):
            head += " [non-ASCII name; ASCII form: %s]" % ascii_form(a["payee"])
    head += " on " + a["resource"]
    limit = float("inf") if max_chars is None else max_chars
    if len(head) > limit:
        raise ValueError("ciba: the binding message needs %d characters but bindingMessage.maxChars is %s; refusing to truncate what the person approves" % (len(head), _js_str(max_chars)))
    plain_goal = re.sub("['‘’]", "′", plain_text(step_up["goal"])) if "goal" in step_up else ""
    if len(plain_goal) > 0:
        goal_text: Optional[str] = clip(plain_goal, MAX_GOAL_CHARS)
    else:
        commit = step_up.get("goalCommit")
        if not isinstance(commit, str):
            raise TypeError("ciba: step-up goalCommit must be a string")
        goal_text = "goal %s…" % _u16_prefix(commit, 10) if len(commit) > 0 else None
    if goal_text is None:
        return head
    prefix = " — because you asked %s to '" % acts_for
    room = limit - len(head + prefix) - 1
    if room >= len(goal_text):
        return "%s%s%s'" % (head, prefix, goal_text)
    if room >= 8:
        return "%s%s%s'" % (head, prefix, clip(goal_text, room))
    return head


def _tokenise(value: str) -> str:
    return re.sub(r"^[-.]+|[-.]+\Z", "", re.sub(r"-{2,}", "-", re.sub(r"[^A-Za-z0-9._-]+", "-", value)))


def _compact_binding_message(step_up: Dict[str, Any], max_chars: int) -> str:
    a = ciba_action_from_step_up(step_up)
    if "payee" in a and not (len(a["payee"]) > 0 and _ASCII_PRINTABLE.fullmatch(a["payee"])):
        raise ValueError("ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)")
    raw = ["Approve", a["verb"]] + ([a["amount"], a["currency"]] if "amount" in a else []) + (["to", a["payee"]] if "payee" in a else []) + [a["resource"]]
    parts = [_tokenise(p) for p in raw]
    if any(len(p) == 0 for p in parts):
        raise ValueError("ciba: tokenOnly binding message cannot represent the verb, payee or resource")
    out = "-".join(parts)
    if len(out) > max_chars:
        raise ValueError("ciba: the binding message needs %d characters but bindingMessage.maxChars is %s; refusing to truncate what the person approves" % (len(out), _js_str(max_chars)))
    return out


def to_ciba_auth_request(step_up: Dict[str, Any], opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Map a step-up to a CIBA auth request. Pure: derives a stable ``auth_req_id`` from the step-up id (unless one is given),
    renders the binding message and carries scope, expiry and poll interval. Starts nothing and notifies nobody."""
    o = opts or {}
    acts_for = clip(plain_text(o["acts_for"]), 40) if "acts_for" in o and len(plain_text(o["acts_for"])) > 0 else "your agent"
    expiry = o["expires_in_sec"] if "expires_in_sec" in o else DEFAULT_EXPIRY_SEC
    if not _safe_int(expiry) or expiry <= 0:
        raise ValueError("ciba: requested_expiry must be a positive integer number of seconds, got %s" % _js_str(expiry))
    step_scope = "urn:atlas:pca:stepup:" + _js_str(step_up.get("verb"))
    if _SCOPE_TOKEN.fullmatch(step_scope) is None:
        raise ValueError("ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)")
    scope = "openid" if o.get("step_up_scope") is False else "openid " + step_scope
    interval = o["interval"] if "interval" in o else DEFAULT_INTERVAL_SEC
    if not _safe_int(interval) or interval <= 0:
        raise ValueError("ciba: interval must be a positive integer number of seconds, got %s" % _js_str(interval))
    auth_req_id = o["auth_req_id"] if o.get("auth_req_id") is not None else hash_canonical({"d": "atlas-pca/ciba/auth_req_id/v1", "stepUp": step_up.get("id")})
    if isinstance(auth_req_id, (bool, int, float)):
        # JS: RegExp.test coerces to a string, and a number has no .length, so only the character class is enforced
        if _AUTH_REQ_ID.fullmatch(_js_str(auth_req_id)) is None:
            raise ValueError("ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)")
    elif not isinstance(auth_req_id, str) or _AUTH_REQ_ID.fullmatch(auth_req_id) is None or len(auth_req_id) < MIN_AUTH_REQ_ID_LEN or len(auth_req_id) > 1024:
        raise ValueError("ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)")
    bm = o.get("binding_message") or {}
    if "max_chars" in bm and (not _safe_int(bm["max_chars"]) or bm["max_chars"] < 1):
        raise ValueError("ciba: bindingMessage.maxChars must be a positive integer")
    max_chars = bm["max_chars"] if "max_chars" in bm else 50
    # The binding message is advisory; the canonical render is what the approval commits to. A word-string of H(R) rides in it.
    words = None
    if "render" in step_up or "renderDigest" in step_up:
        if "render" not in step_up or "renderDigest" not in step_up or approval_render_digest(step_up["render"]) != step_up["renderDigest"]:
            raise ValueError("ciba: the step-up render and its digest do not agree; refusing to send an approval that commits to something else")
        words = binding_words(step_up["renderDigest"])
    reserve = 0 if words is None else len(words) + 14
    token_only = bm.get("token_only") is True
    if token_only:
        msg = _compact_binding_message(step_up, max_chars - reserve)
    else:
        msg = _binding_message(step_up, acts_for, bm["max_chars"] - reserve if "max_chars" in bm else None)
    if words is not None:
        msg = "%s-match-%s" % (msg, words) if token_only else "%s [match code %s]" % (msg, words)
    req: Dict[str, Any] = {"auth_req_id": auth_req_id, "binding_message": msg, "scope": scope, "requested_expiry": int(expiry), "interval": int(interval)}
    if "login_hint" in o:
        req["login_hint"] = o["login_hint"]
    req["stepUpId"] = step_up.get("id")
    req["tier"] = step_up.get("tier")
    if "render" in step_up and "renderDigest" in step_up:
        req["authorization_details"] = [{"type": "pca_approval", "render": step_up["render"], "render_digest": step_up["renderDigest"]}]
        req["render_digest"] = step_up["renderDigest"]
    return req


def requires_ciba(review: Dict[str, Any]) -> bool:
    """Only a tier-3 step-up (human required) goes through CIBA; tier 2 is the guardian's auto-cosign, auto / deny never interrupt."""
    req = review.get("request") if isinstance(review, dict) else None
    return isinstance(review, dict) and review.get("kind") == "step_up" and isinstance(req, dict) and req.get("tier") == 3


def ciba_decision_to_cosign(decision: str, budget: Dict[str, Any], policy: Dict[str, Any], now: Any, full: bool = False) -> Dict[str, Any]:
    """Fold a settled decision into the trust budget: approve recharges (partial rho, or full), deny leaves it unchanged. Budget
    level only: the cryptographic cosign that authorises a tier-3 action is a FROST signature checked by the resource server."""
    if decision == "approve":
        b = recharge_full(budget, policy["bMax"], now) if full else recharge(budget, policy["rho"], policy["bMax"], now)
        return {"budget": b, "cosigned": True}
    return {"budget": budget, "cosigned": False}
