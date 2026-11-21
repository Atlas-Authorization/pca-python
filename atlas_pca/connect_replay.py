"""One-time-use guard for a verified PCActn and its reference in-memory store: the anti-replay primitives the token vault spends an
action with. A port of the TypeScript reference (@atlasauth/pca, replay): a store-contract (`consume_once(key, retain_until_ms,
now_ms) -> bool`, `advance(stream_key, counter) -> bool`, both raising when they cannot decide), the injective namespaced key, and
the guard that composes them with the wire-level freshness rules. Run the guard only AFTER the PCActn verified."""
from ._fin import fin
import hashlib
import math
import struct
from typing import Any, Dict, Optional

from .pca import b64u

__all__ = ["MAX_REPLAY_COMPONENT_LEN", "PCACTN_MAX_LIFETIME_MS", "PCACTN_MAX_SKEW_MS", "replay_key", "guard_pcactn_replay", "InMemoryReplayStore"]

MAX_REPLAY_COMPONENT_LEN = 512
PCACTN_MAX_LIFETIME_MS = 3_600_000
PCACTN_MAX_SKEW_MS = 60_000
_MAX_AUD_LEN = 256
_MAX_NONCE_LEN = 128
_MAX_SAFE = 2 ** 53 - 1


def _lone(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _u8len(s: str) -> int:
    return len(s.encode("utf-8", "replace"))


def _safe_nonneg_int(n: Any) -> bool:
    if isinstance(n, bool) or not isinstance(n, (int, float)):
        return False
    if isinstance(n, float):
        if not (fin(n) and n.is_integer()) or (n == 0 and math.copysign(1.0, n) < 0):
            return False
    return 0 <= n <= _MAX_SAFE


def _safe_int(n: Any) -> bool:
    return not isinstance(n, bool) and isinstance(n, (int, float)) and fin(n) and float(n).is_integer() and abs(n) <= _MAX_SAFE


def replay_key(namespace: str, *parts: str) -> str:
    """Length-prefixed, injective encoding of the parts, hashed to a fixed-size key. Raises on a part that is not a well-formed string."""
    buf = bytearray()
    for part in (namespace,) + parts:
        if not isinstance(part, str) or _lone(part):
            raise TypeError("replayKey: every part must be a well-formed string (no lone surrogates)")
        b = part.encode("utf-8")
        buf += struct.pack(">I", len(b)) + b
    return "%s:%s" % (namespace, b64u(hashlib.sha256(bytes(buf)).digest()))


def guard_pcactn_replay(store: Any, p: Any, aud: Any, now: Any, clock_skew_ms: Any = None, require_nonce: bool = True,
                        counters: Any = None) -> Dict[str, Any]:
    """Decide whether a (signature-verified) PCActn may be accepted ONCE: {ok: True} or {ok: False, code, reason}. Never raises: every
    failure, including a store failure, is a denial."""
    def deny(code: str, reason: str) -> Dict[str, Any]:
        return {"ok": False, "code": code, "reason": reason}

    skew_ok = isinstance(clock_skew_ms, (int, float)) and not isinstance(clock_skew_ms, bool) and fin(clock_skew_ms)
    skew = min(clock_skew_ms if skew_ok and clock_skew_ms >= 0 else PCACTN_MAX_SKEW_MS, PCACTN_MAX_SKEW_MS)
    obj_ok = isinstance(p, dict)
    chain = p.get("cap_chain") if obj_ok else None
    leaf = chain[-1] if isinstance(chain, list) and chain else None
    leaf_ok = bool(leaf) and isinstance(leaf, dict) and isinstance(leaf.get("holder"), str) and isinstance(p.get("grant_ref"), str)
    comps_ok = leaf_ok and all(not (len(c) == 0 or _lone(c) or _u8len(c) > MAX_REPLAY_COMPONENT_LEN) for c in (p["grant_ref"], leaf["holder"]))
    has_nonce = obj_ok and "nonce" in p
    nonce = p.get("nonce") if obj_ok else None
    nonce_ok = has_nonce and isinstance(nonce, str) and len(nonce) != 0 and _u8len(nonce) <= _MAX_NONCE_LEN and not _lone(nonce)
    now_ok = _safe_int(now)
    aud_ok = isinstance(aud, str) and len(aud) != 0 and _u8len(aud) <= _MAX_AUD_LEN and not _lone(aud)
    aud_matches = obj_ok and isinstance(p.get("aud"), str) and p["aud"] == aud
    iat_ok = obj_ok and _safe_nonneg_int(p.get("iat"))
    exp_ok = obj_ok and _safe_nonneg_int(p.get("exp"))
    iat = p["iat"] if iat_ok else 0
    exp = p["exp"] if exp_ok else 0
    counter_ok = obj_ok and _safe_nonneg_int(p.get("counter"))
    sk = math.floor(skew)
    window_ok = iat_ok and exp_ok and exp > iat and exp - iat <= PCACTN_MAX_LIFETIME_MS
    code = None
    if not now_ok or not aud_ok or not obj_ok:
        code = "malformed"
    elif not aud_matches:
        code = "audience"
    elif not window_ok:
        code = "malformed"
    elif iat > now + sk:
        code = "not_yet_valid"
    elif now > exp:
        code = "expired"
    elif not leaf_ok or not comps_ok or not counter_ok:
        code = "malformed"
    if code is not None:
        reasons = {"audience": "the PCActn is for another audience", "not_yet_valid": "iat is in the future beyond the clock-skew allowance",
                   "expired": "the PCActn has expired"}
        if code in reasons:
            return deny(code, reasons[code])
        if not now_ok:
            return deny(code, "verifier clock is not an integer epoch-ms")
        if not aud_ok:
            return deny(code, "verifier audience is invalid")
        if not obj_ok:
            return deny(code, "not a PCActn")
        if not window_ok:
            return deny(code, "iat / exp are not a valid bounded window")
        if not leaf_ok:
            return deny(code, "no leaf holder / grant")
        if not comps_ok:
            return deny(code, "grant / holder is not a bounded string")
        return deny(code, "counter is not a non-negative safe integer")
    if exp + math.ceil(skew) > _MAX_SAFE:
        return deny("malformed", "exp + clock skew exceeds the safe-integer range (retention horizon not representable)")
    retain_until = exp + skew
    try:
        consumed = True
        if has_nonce:
            if not nonce_ok:
                return deny("malformed", "nonce must be a non-empty well-formed string of <= 128 UTF-8 bytes")
            consumed = store.consume_once(replay_key("pca-nonce/v1", aud, p["grant_ref"], leaf["holder"], nonce), retain_until, now)
            if not consumed:
                return deny("replay", "nonce already consumed")
        elif require_nonce is not False:
            return deny("malformed", "a nonce is required")
        if counters is not None:
            advanced = counters.advance(replay_key("pca-counter/v1", aud, p["grant_ref"], leaf["holder"]), p["counter"])
            if not advanced:
                return deny("replay", "counter is not greater than the last accepted")
    except Exception as e:  # noqa: BLE001 - a store that cannot decide fails closed
        return deny("store_unavailable", "replay store failed closed: %s" % (e if str(e) else "error"))
    return {"ok": True}


class InMemoryReplayStore:
    """Reference store: correct only for a single verifier process whose lifetime covers the action lifetime."""

    def __init__(self, max_entries: int = 100_000):
        self._seen: Dict[str, Any] = {}
        self._streams: Dict[str, Any] = {}
        self._max = max_entries

    @property
    def size(self) -> int:
        return len(self._seen)

    def prune(self, now_ms: Any) -> int:
        if not _finite(now_ms):
            return 0  # an infinite clock must not expire live replay keys
        dead = [k for k, until in self._seen.items() if until < now_ms]
        for k in dead:
            del self._seen[k]
        return len(dead)

    def consume_once(self, key: Any, retain_until_ms: Any, now_ms: Any) -> bool:
        if not isinstance(key, str) or len(key) == 0 or not _finite(retain_until_ms) or not _finite(now_ms) or retain_until_ms < now_ms:
            raise ValueError("consumeOnce: invalid key or retention horizon")
        until = self._seen.get(key)
        if until is not None and until >= now_ms:
            return False
        if until is None and len(self._seen) >= self._max:
            self.prune(now_ms)
            if len(self._seen) >= self._max:
                raise RuntimeError("replay store full of live entries")
        self._seen[key] = max(retain_until_ms, until if until is not None else 0)
        return True

    def advance(self, stream_key: Any, counter: Any) -> bool:
        if not isinstance(stream_key, str) or len(stream_key) == 0 or not _safe_nonneg_int(counter):
            raise ValueError("advance: invalid stream or counter")
        last = self._streams.get(stream_key)
        if last is not None and not counter > last:
            return False
        self._streams[stream_key] = counter
        return True


def _finite(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)
