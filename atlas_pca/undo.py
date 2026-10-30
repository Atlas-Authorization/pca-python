"""UNDO WINDOWS (pure layer): reversible actions execute at once and the principal gets a veto window in which they can undo
them. Port of the TypeScript reference ``undo.ts`` (``conformance/undo-vectors.json`` pins every function here byte for byte).

This module lets any Python service VERIFY the artifacts of an undo window: the compensation digest, the signed one-click undo
token, the signed and hash-chained audit receipts of a record, the pure state machine and the window clamp. Admission,
compensation, notification and the durable ledger are the undo coordinator's (the TypeScript coordinator or the hosted
ledger); ``authorize(undo_admit=...)`` is the hook through which that coordinator turns an unanswered escalation into an
allow under a veto window.

STATE MACHINE (``undo_transition``)::

    open --veto (now <= window_end)--> vetoed --compensated--> compensated
      |                                  |  \\--compensation_failed--> compensation_failed --retry--> vetoed
      |                                  |                                   \\--compensated--> compensated
      +--finalize (now > window_end)--> finalized
      +--abort (the effect never ran)--> finalized

Signatures are plain Ed25519 over utf8(domain) || strict canonical JSON of the body. Every function is total.
"""
import copy
import json
import math
import re
from typing import Any, Dict, Mapping, Optional

from .agent import KeyPair
from .intent_wb import _is_safe_int, _js_str, _utf16_len
from .pca import _verify_b64u, b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical

__all__ = [
    "UNDO_TOKEN_DOMAIN", "UNDO_RECEIPT_DOMAIN", "UNDO_COMPENSATION_DOMAIN", "UNDO_RECEIPT_REF_DOMAIN", "UNDO_TOKEN_REF_DOMAIN",
    "UNDO_TOKEN_KIND", "UNDO_RECEIPT_KIND", "UNDO_MIN_WINDOW_MS", "UNDO_DEFAULT_WINDOW_MS", "UNDO_MAX_WINDOW_MS", "UNDO_STATES",
    "UNDO_EVENTS", "VETO_VIAS", "compensation_digest", "sign_undo_token", "undo_token_check", "encode_undo_token",
    "decode_undo_token", "undo_token_digest", "sign_undo_receipt", "verify_undo_receipt", "undo_receipt_digest",
    "undo_receipt_chain_error", "undo_transition", "resolve_undo_window",
]

UNDO_TOKEN_DOMAIN = "atlas-pca/undo-token/v1\x00"
UNDO_RECEIPT_DOMAIN = "atlas-pca/undo-receipt/v1\x00"
UNDO_COMPENSATION_DOMAIN = "atlas-pca/undo-compensation/v1"
UNDO_RECEIPT_REF_DOMAIN = "atlas-pca/undo-receipt-ref/v1"
UNDO_TOKEN_REF_DOMAIN = "atlas-pca/undo-token-ref/v1"
UNDO_TOKEN_KIND = "pca-undo-token"
UNDO_RECEIPT_KIND = "pca-undo-receipt"

#: The floor of a veto window (a human must be able to react), the default and the ceiling.
UNDO_MIN_WINDOW_MS = 30_000
UNDO_DEFAULT_WINDOW_MS = 15 * 60_000
UNDO_MAX_WINDOW_MS = 24 * 60 * 60_000

UNDO_STATES = ("open", "vetoed", "compensated", "compensation_failed", "finalized")
UNDO_EVENTS = ("opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect")
VETO_VIAS = ("token", "operator", "fraud_proof", "revocation")

_ID_MAX = 256
_CONTROL_RE = re.compile("[\x00-\x1f]")
_TOKEN_KEYS = ("v", "kind", "record", "aud", "principal", "compensation_digest", "render_digest", "exp", "signer", "sig")
_RECEIPT_KEYS = ("v", "kind", "record", "event", "state", "at", "compensation_digest", "prev", "note", "signer", "sig")


def _id_ok(s: Any) -> bool:
    """A record id: a string of 1..256 UTF-16 code units without control characters (U+0000..U+001F)."""
    return isinstance(s, str) and 0 < _utf16_len(s) <= _ID_MAX and _CONTROL_RE.search(s) is None


def _is_one(v: Any) -> bool:
    return v == 1 and not isinstance(v, bool)


def _str_in(v: Any, options) -> bool:
    return isinstance(v, str) and v in options


def _domain_bytes(domain: str, body: Any) -> bytes:
    return domain.encode("utf-8") + canonical_bytes_strict(body)


def _secret(secret: Any) -> KeyPair:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != 32:
        raise ValueError("signer_missing: the undo service key must be a 32-byte Ed25519 secret")
    return KeyPair(bytes(secret))


# ---- digests -----------------------------------------------------------------------------------------------------------

def compensation_digest(c: Mapping[str, Any]) -> str:
    """hashCanonical of the compensating action ``{verb, resource, params, undo_of, def_digest, target_param?}``."""
    body = {"d": UNDO_COMPENSATION_DOMAIN, "verb": c["verb"], "resource": c["resource"], "params": c["params"],
            "undo_of": c["undo_of"], "def_digest": c["def_digest"]}
    if "target_param" in c:
        body["target_param"] = c["target_param"]
    return hash_canonical(body)


# ---- the one-click undo token ------------------------------------------------------------------------------------------

def _token_body(t: Mapping[str, Any]) -> dict:
    return {k: t[k] for k in _TOKEN_KEYS if k != "sig"}


def sign_undo_token(record: Mapping[str, Any], secret: bytes) -> dict:
    """A signed capability to veto ONE record (``record``: ``id, aud, principal, compensation_digest, render_digest?,
    window_end``), signed by the undo service key (32-byte Ed25519 seed)."""
    k = _secret(secret)
    rd = record.get("render_digest")
    body = {"v": 1, "kind": UNDO_TOKEN_KIND, "record": record["id"], "aud": record["aud"], "principal": record["principal"],
            "compensation_digest": record["compensation_digest"], "render_digest": "" if rd is None else rd,
            "exp": record["window_end"], "signer": k.public}
    return {**body, "sig": b64u(k.sign(_domain_bytes(UNDO_TOKEN_DOMAIN, body)))}


def undo_token_check(token: Any, expected_signer: Any, record: Mapping[str, Any], now: Any) -> str:
    """The FIRST check a token fails, in this order: ``malformed`` (shape: exactly the 10 members), ``signer`` (not the pinned
    undo service key), ``signature``, ``record`` (another record id), ``binding`` (aud, principal, compensation, render digest
    or window end differ), ``expired`` (``now > exp``; valid THROUGH ``exp``); ``ok`` when none. Never raises."""
    try:
        if not isinstance(token, dict):
            return "malformed"
        if len(token) != len(_TOKEN_KEYS) or not all(k in token for k in _TOKEN_KEYS):
            return "malformed"
        t = token
        if (not _is_one(t["v"]) or t["kind"] != UNDO_TOKEN_KIND or not _id_ok(t["record"]) or not isinstance(t["aud"], str)
                or not isinstance(t["principal"], str) or not isinstance(t["compensation_digest"], str)
                or not isinstance(t["render_digest"], str) or not _is_safe_int(t["exp"]) or not isinstance(t["signer"], str)
                or decode_b64u_strict(t["sig"], 64) is None):
            return "malformed"
        if t["signer"] != expected_signer:
            return "signer"
        if not _verify_b64u(expected_signer, _domain_bytes(UNDO_TOKEN_DOMAIN, _token_body(t)), t["sig"]):
            return "signature"
        if t["record"] != record.get("id"):
            return "record"
        rd = record.get("render_digest")
        if (t["aud"] != record.get("aud") or t["principal"] != record.get("principal")
                or t["compensation_digest"] != record.get("compensation_digest") or t["render_digest"] != ("" if rd is None else rd)
                or t["exp"] != record.get("window_end")):
            return "binding"
        if not _is_safe_int(now) or now > t["exp"]:
            return "expired"
        return "ok"
    except Exception:  # noqa: BLE001
        return "malformed"


def encode_undo_token(t: Mapping[str, Any]) -> str:
    """The token as a URL-safe string (base64url of its strict-canonical JSON) for a one-click link."""
    return b64u(canonical_bytes_strict(dict(t)))


def decode_undo_token(s: Any) -> Optional[dict]:
    """Inverse of :func:`encode_undo_token`: a non-empty string of at most 4096 characters, strict base64url, strict UTF-8, a
    JSON object; None for anything else (the token's own checks are :func:`undo_token_check`)."""
    try:
        if not isinstance(s, str) or len(s) == 0 or _utf16_len(s) > 4096:
            return None
        b = decode_b64u_strict(s)
        if b is None:
            return None
        x = json.loads(b.decode("utf-8"), parse_constant=_no_constant)  # strict UTF-8; JSON.parse semantics (duplicate keys: last wins)
        return x if isinstance(x, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _no_constant(c: str) -> Any:
    raise ValueError("not JSON: %s" % c)  # NaN / Infinity are not JSON (JSON.parse refuses them)


def undo_token_digest(t: Any) -> str:
    return hash_canonical({"d": UNDO_TOKEN_REF_DOMAIN, "t": t})


# ---- receipts ----------------------------------------------------------------------------------------------------------

def undo_receipt_digest(r: Any) -> str:
    """Content address of a receipt (signature included): what the next receipt's ``prev`` names."""
    return hash_canonical({"d": UNDO_RECEIPT_REF_DOMAIN, "r": r})


def sign_undo_receipt(body: Mapping[str, Any], secret: bytes) -> dict:
    """Sign one transition receipt (``body``: ``record, event, state, at, compensation_digest, prev, note``)."""
    k = _secret(secret)
    b = {"v": 1, "kind": UNDO_RECEIPT_KIND, "record": body["record"], "event": body["event"], "state": body["state"],
         "at": body["at"], "compensation_digest": body["compensation_digest"], "prev": body["prev"], "note": body["note"],
         "signer": k.public}
    return {**b, "sig": b64u(k.sign(_domain_bytes(UNDO_RECEIPT_DOMAIN, b)))}


def verify_undo_receipt(r: Any, expected_signer: Any) -> bool:
    """True iff ``r`` is well formed (exactly 11 members, a known event and state) and signed by ``expected_signer`` over
    exactly its content. Never raises."""
    try:
        if not isinstance(r, dict) or not all(k in r for k in _RECEIPT_KEYS):
            return False
        if (not _is_one(r["v"]) or r["kind"] != UNDO_RECEIPT_KIND or not _id_ok(r["record"]) or not _str_in(r["event"], UNDO_EVENTS)
                or not _str_in(r["state"], UNDO_STATES) or not _is_safe_int(r["at"]) or not isinstance(r["compensation_digest"], str)
                or not isinstance(r["prev"], str) or not isinstance(r["note"], str) or r["signer"] != expected_signer
                or decode_b64u_strict(r["sig"], 64) is None):
            return False
        if len(r) != len(_RECEIPT_KEYS):
            return False
        body = {k: r[k] for k in _RECEIPT_KEYS if k != "sig"}
        return _verify_b64u(expected_signer, _domain_bytes(UNDO_RECEIPT_DOMAIN, body), r["sig"])
    except Exception:  # noqa: BLE001
        return False


def undo_receipt_chain_error(record: Mapping[str, Any], expected_signer: Any) -> Optional[str]:
    """Verify a record's receipt chain (``record``: ``id, compensation_digest, state, receipts``): every receipt verifies, names
    this record and its compensation, ``prev`` links each to the one before ('' for the first), the first is ``opened``, times
    never go back, and the last state is the record's state. None when sound, else the reason. Never raises."""
    try:
        rs = record.get("receipts")
        if not isinstance(rs, list) or len(rs) == 0:
            return "no receipts"
        prev, at = "", -math.inf
        for i, r in enumerate(rs):
            if not verify_undo_receipt(r, expected_signer):
                return "receipt %d does not verify" % i
            if r["record"] != record.get("id") or r["compensation_digest"] != record.get("compensation_digest"):
                return "receipt %d is for another record" % i
            if r["prev"] != prev:
                return "receipt %d does not link to the previous one" % i
            if i == 0 and r["event"] != "opened":
                return "the first receipt is not opened"
            if r["at"] < at:
                return "receipt %d goes back in time" % i
            prev, at = undo_receipt_digest(r), r["at"]
        return None if rs[-1]["state"] == record.get("state") else "the last receipt does not state the record state"
    except Exception:  # noqa: BLE001
        return "malformed record (fail closed)"


# ---- the pure transitions ----------------------------------------------------------------------------------------------

def _refused(code: str, reason: str) -> dict:
    return {"outcome": "refused", "code": code, "reason": reason}


def undo_transition(record: Any, event: Any, now: Any) -> dict:
    """The state machine, pure: ``record`` is not modified. Returns ``{"outcome": "applied", "record", "receipt": {event,
    note}}`` (version bumped; the receipt is not yet signed or appended), ``{"outcome": "replayed", "record"}`` (the same
    transition already happened) or ``{"outcome": "refused", "code", "reason"}``. ``event`` is ``{"kind": "veto", "veto": {at,
    via, by, evidence?}}``, ``finalize``, ``{"kind": "abort", "reason"}``, ``{"kind": "effect", "result"?}``, ``{"kind":
    "compensated", "result"?}``, ``{"kind": "compensation_failed", "reason"}`` or ``retry``. ``now`` is the trusted server
    clock. Never raises."""
    try:
        if (not isinstance(record, dict) or not _str_in(record.get("state"), UNDO_STATES) or not _is_safe_int(record.get("window_end"))
                or not _is_safe_int(record.get("ver"))):
            return _refused("invalid", "malformed record")
        if not _is_safe_int(now):
            return _refused("invalid", "now must be a safe integer")
        state, end = record["state"], record["window_end"]

        def nxt(patch: Dict[str, Any], ev: str, note: str = "") -> dict:
            r = copy.deepcopy(record)
            r.update(patch)
            r["ver"] = record["ver"] + 1
            return {"outcome": "applied", "record": r, "receipt": {"event": ev, "note": note}}

        def replayed() -> dict:
            return {"outcome": "replayed", "record": record}

        kind = event.get("kind") if isinstance(event, dict) else None
        if kind == "veto":
            v = event.get("veto")
            if (not isinstance(v, dict) or not _is_safe_int(v.get("at")) or not _str_in(v.get("via"), VETO_VIAS)
                    or not isinstance(v.get("by"), str) or len(v["by"]) == 0):
                return _refused("invalid", "malformed veto")
            if state in ("vetoed", "compensated", "compensation_failed"):
                return replayed()
            if state == "finalized":
                return _refused("finalized", "the window is closed and the action is final")
            if now > end:
                return _refused("window_closed", "the veto window closed at %d" % end)
            return nxt({"state": "vetoed", "veto": dict(v)}, "vetoed", v["via"])
        if kind == "finalize":
            if state == "finalized":
                return replayed()
            if state != "open":
                return _refused("vetoed", "a %s record is not finalized" % state)
            if now <= end:
                return _refused("window_open", "the veto window is open until %d" % end)
            return nxt({"state": "finalized", "outcome": {"at": now, "status": "finalized"}}, "finalized")
        if kind == "abort":
            outcome = record.get("outcome")
            if state == "finalized" and isinstance(outcome, dict) and outcome.get("status") == "aborted":
                return replayed()
            if state not in ("open", "vetoed"):
                return _refused("finalized", "a %s record cannot be aborted" % state)
            if "effect" in record:
                return _refused("effect_recorded", "the effect ran: it can only be compensated or finalized")
            why = _js_str(event.get("reason"))
            return nxt({"state": "finalized", "outcome": {"at": now, "status": "aborted", "reason": why[:512]}}, "aborted", why[:128])
        if kind == "effect":
            if "effect" in record:
                return replayed()
            if state not in ("open", "vetoed"):
                return _refused("finalized", "a %s record takes no effect report" % state)
            eff: Dict[str, Any] = {"at": now}
            if "result" in event:
                eff["result"] = copy.deepcopy(event["result"])
            return nxt({"effect": eff}, "effect")
        if kind == "compensated":
            if state == "compensated":
                return replayed()
            if state not in ("vetoed", "compensation_failed"):
                return _refused("not_vetoed", "a %s record is not being compensated" % state)
            out: Dict[str, Any] = {"at": now, "status": "compensated"}
            if "result" in event:
                out["result"] = copy.deepcopy(event["result"])
            return nxt({"state": "compensated", "outcome": out}, "compensated")
        if kind == "compensation_failed":
            if state == "compensation_failed":
                return replayed()
            if state != "vetoed":
                return _refused("not_vetoed", "a %s record is not being compensated" % state)
            why = _js_str(event.get("reason"))
            return nxt({"state": "compensation_failed", "outcome": {"at": now, "status": "compensation_failed", "reason": why[:512]}},
                       "compensation_failed", why[:128])
        if kind == "retry":
            if state != "compensation_failed":
                return _refused("not_failed", "a %s record is not retried" % state)
            return nxt({"state": "vetoed", "attempt": record.get("attempt", 0) + 1}, "retried")
        return _refused("invalid", "unknown event")
    except Exception:  # noqa: BLE001
        return _refused("invalid", "evaluation error (fail closed)")


def resolve_undo_window(requested_ms: Any = None, policy: Optional[Mapping[str, Any]] = None) -> int:
    """Clamp a requested window into [max(30 s, min_ms), max_ms (<= 24 h)]; absent or non-finite -> the default (15 min, or
    the policy's ``default_ms``). ``policy`` keys: ``min_ms`` / ``max_ms`` / ``default_ms`` (the reference's ``minMs`` /
    ``maxMs`` / ``defaultMs`` are accepted too)."""
    p = dict(policy or {})

    def opt(snake: str, camel: str) -> Any:
        return p.get(snake, p.get(camel))

    mn_p, mx_p, df_p = opt("min_ms", "minMs"), opt("max_ms", "maxMs"), opt("default_ms", "defaultMs")
    mn = max(UNDO_MIN_WINDOW_MS, UNDO_MIN_WINDOW_MS if mn_p is None else mn_p)
    mx = max(mn, min(UNDO_MAX_WINDOW_MS if mx_p is None else mx_p, UNDO_MAX_WINDOW_MS))
    finite = isinstance(requested_ms, (int, float)) and not isinstance(requested_ms, bool) and math.isfinite(requested_ms)
    want = requested_ms if finite else (UNDO_DEFAULT_WINDOW_MS if df_p is None else df_p)
    return int(math.floor(min(mx, max(mn, want))))
