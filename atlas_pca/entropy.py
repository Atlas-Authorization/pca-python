"""Quantum random number generator (QRNG) entropy as an ADD to key generation, never a trust dependency.

Every seed is ``HKDF-SHA256(local CSPRNG || quantum)``: the local bytes are always part of the input keying material, so a QRNG that is
unavailable, slow, malformed or fully hostile cannot lower the result below the strength of the local CSPRNG. Quantum bytes are never used raw
as a key, and this is not a post-quantum claim (that comes from the signature suites).

Parts: ``HttpQrngSource`` (ANU-style JSON, hex or base64 bodies; https only, strict validation, the key never in an error), the unavailable
stubs, the SP 800-90B 4.4 continuous health tests, the combiner ``mix_entropy``, ``secure_seed`` and an Ed25519 key-pair helper.

The package carries no HTTP client: ``HttpQrngSource`` takes a ``transport`` callable
``transport(url, headers=..., redirect="error", timeout=seconds)`` that returns an object with ``ok``, ``status``, ``json()`` and ``text()``
and must not follow redirects. A source is any object with a ``name`` and ``fetch(num_bytes) -> bytes``.

Errors: ``EntropyError`` (with a ``code``), ``TypeError`` for a wrong argument type, ``ValueError`` for an out-of-range one or an unparsable
URL, ``RuntimeError`` for a failed source."""
from __future__ import annotations

import base64
import ctypes
import hashlib
import math
import os
import re
import socket
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from ._fdlibm import pow as fdlibm_pow  # the reference runtime's pow, bit for bit: the cutoffs must not depend on the platform libm
from ._hkdf import hkdf_sha256
from .pca import utf8

MAX_HKDF_OUTPUT = 255 * 32  # 8160 (RFC 5869)
MIN_LOCAL_BYTES = 16
DEFAULT_SEED_BYTES = 32
DEFAULT_MAX_QRNG_BYTES = 1024
DEFAULT_TIMEOUT_MS = 5000

_MIX_LABEL = "atlas-pca/entropy/mix/v1"
_MIX_SALT = b"atlas-pca/entropy/salt/v1"
_HEX_RE = re.compile(r"[0-9a-fA-F]*")
_B64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
# what the reference trims from a text body (ECMAScript WhiteSpace and LineTerminator), not Python's wider default set
_TRIM = "\t\n\v\f\r                  　﻿"
_BYTES = (bytes, bytearray)


class EntropyError(Exception):
    """A fail-closed entropy refusal; ``code`` is ``quantum_required``, ``health_test_failed`` or ``insecure_transport``."""

    name = "EntropyError"

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _is_int(v: Any) -> bool:
    """A whole number (1.0 counts, as in JSON); never a bool, a string, NaN or an infinity."""
    if isinstance(v, bool):
        return False
    return isinstance(v, int) or (isinstance(v, float) and v.is_integer())


def _show(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if v != v:
            return "NaN"
        if v in (math.inf, -math.inf):
            return "Infinity" if v > 0 else "-Infinity"
        if v.is_integer():
            return str(int(v))
    return str(v)


# ---- sources ---------------------------------------------------------------------------------------------------------------------

class NullQrngSource:
    """A source that is never available: ``fetch`` always fails, so ``secure_seed`` falls back to the local CSPRNG."""

    name = "null-qrng"

    def __init__(self, reason: str = "no QRNG source configured"):
        self._reason = reason

    def fetch(self, num_bytes: int) -> bytes:
        raise RuntimeError("QRNG unavailable: %s" % self._reason)


def unavailable_source(reason: Optional[str] = None) -> NullQrngSource:
    return NullQrngSource() if reason is None else NullQrngSource(reason)


def _url(text: str):
    """The WHATWG URL of `text` (Ada, the parser Node uses); ValueError when it does not parse."""
    import ada_url
    return ada_url.URL(text)


def _safe_host(url: str) -> str:
    try:
        return _url(url).host or "unknown"
    except Exception:  # noqa: BLE001 - the name is informative only; fetch() refuses the URL
        return "unknown"


def _assert_secure_transport(url: Any, allow_loopback: bool) -> None:
    try:
        u = _url(url)
    except Exception:  # noqa: BLE001
        raise EntropyError("insecure_transport", "QRNG: endpoint URL is not a valid URL") from None
    if u.protocol == "https:":
        return
    if u.protocol == "http:" and allow_loopback and u.hostname in ("localhost", "127.0.0.1", "[::1]"):
        return
    raise EntropyError("insecure_transport", "QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)")


def _within(seconds: float, call: Callable[[], Any]) -> Any:
    """call() on a worker thread, abandoned with TimeoutError after `seconds`: a transport that ignores its timeout cannot hold the caller."""
    box: dict = {}

    def work() -> None:
        try:
            box["value"] = call()
        except BaseException as e:  # noqa: BLE001 - re-raised on the calling thread
            box["error"] = e

    t = threading.Thread(target=work, name="atlas-pca-qrng", daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise TimeoutError("timeout")
    if "error" in box:
        raise box["error"]
    return box["value"]


class HttpQrngSource:
    """A QRNG behind an HTTP endpoint. `format` is ``anu-uint8`` (JSON ``{"data": [0..255, ...]}``), ``hex`` or ``base64``."""

    def __init__(self, url: str, *, transport: Optional[Callable[..., Any]] = None, api_key: Optional[str] = None,
                 api_key_header: Optional[str] = None, format: Optional[str] = None, timeout_ms: Optional[int] = None,  # noqa: A002
                 max_bytes: Optional[int] = None, length_param: Optional[str] = None, extra_params: Optional[Mapping[str, str]] = None,
                 build_url: Optional[Callable[[str, int], str]] = None, allow_insecure_loopback: bool = False):
        if not isinstance(url, str) or len(url) == 0:
            raise TypeError("HttpQrngSource: `url` must be a non-empty string")
        max_bytes = DEFAULT_MAX_QRNG_BYTES if max_bytes is None else max_bytes
        if not _is_int(max_bytes) or max_bytes <= 0:
            raise TypeError("HttpQrngSource: `maxBytes` must be a positive integer")
        timeout_ms = DEFAULT_TIMEOUT_MS if timeout_ms is None else timeout_ms
        if not _is_int(timeout_ms) or timeout_ms <= 0:
            raise TypeError("HttpQrngSource: `timeoutMs` must be a positive integer")
        self._url = url
        self._api_key = api_key
        self._api_key_header = "x-api-key" if api_key_header is None else api_key_header
        self._format = "anu-uint8" if format is None else format
        self._timeout_ms = int(timeout_ms)
        self._max_bytes = int(max_bytes)
        self._length_param = "length" if length_param is None else length_param
        self._extra_params = extra_params
        self._build_url = build_url
        self._allow_insecure_loopback = allow_insecure_loopback is True
        self._transport = transport
        self.name = "http-qrng(%s)" % _safe_host(url)

    def __repr__(self) -> str:  # never print the key
        return "HttpQrngSource(%r)" % self.name

    def _request_url(self, num_bytes: int) -> str:
        if self._build_url is not None:
            return self._build_url(self._url, num_bytes)
        import ada_url
        u = _url(self._url)
        params = ada_url.URLSearchParams(u.search[1:] if u.search.startswith("?") else u.search)
        params.set(self._length_param, str(num_bytes))
        for k, v in (self._extra_params or {}).items():
            params.set(k, v)
        u.search = str(params)
        return u.href

    def fetch(self, num_bytes: int) -> bytes:
        if not _is_int(num_bytes) or num_bytes <= 0:
            raise TypeError("QRNG: numBytes must be a positive integer, got %s" % _show(num_bytes))
        num_bytes = int(num_bytes)
        if num_bytes > self._max_bytes:
            raise ValueError("QRNG: requested %d bytes exceeds per-request cap %d" % (num_bytes, self._max_bytes))
        if self._transport is None:
            raise RuntimeError("QRNG: no fetch implementation available in this runtime")
        url = self._request_url(num_bytes)
        _assert_secure_transport(url, self._allow_insecure_loopback)
        headers = {"accept": "application/json, text/plain"}
        if self._api_key is not None and len(self._api_key) > 0:
            headers[self._api_key_header] = self._api_key
        seconds = self._timeout_ms / 1000.0
        try:
            res = _within(seconds, lambda: self._transport(url, headers=headers, redirect="error", timeout=seconds))
        except Exception as err:  # noqa: BLE001 - every transport failure is one refusal, key scrubbed and the cause not chained
            detail = "timeout" if isinstance(err, (TimeoutError, socket.timeout)) else str(err)
            if self._api_key:
                detail = detail.replace(self._api_key, "[redacted]")
            raise RuntimeError("QRNG: fetch failed (%s)" % detail) from None
        if not res.ok:
            raise RuntimeError("QRNG: endpoint returned HTTP %s" % _show(res.status))
        if self._format == "anu-uint8":
            data = parse_anu_uint8(res.json())
        else:
            text = res.text().strip(_TRIM)
            data = parse_hex(text) if self._format == "hex" else parse_base64(text)
        if len(data) != num_bytes:
            raise RuntimeError("QRNG: expected %d bytes, response decoded to %d" % (num_bytes, len(data)))
        return data


def parse_anu_uint8(body: Any) -> bytes:
    """The bytes of an ANU-style JSON body ``{"success"?: true, "data": [0..255, ...]}`` (already decoded); anything else refuses."""
    if not isinstance(body, (dict, list)):
        raise RuntimeError("QRNG: response body is not a JSON object")
    rec = body if isinstance(body, dict) else {}
    if "success" in rec and rec["success"] is not True:
        raise RuntimeError("QRNG: response reports success=false")
    data = rec.get("data")
    if not isinstance(data, list):
        raise RuntimeError("QRNG: response `data` is not an array")
    out = bytearray(len(data))
    for i, v in enumerate(data):
        if not _is_int(v) or not 0 <= v <= 255:
            raise RuntimeError("QRNG: response data[%d] is not a 0..255 integer" % i)
        out[i] = int(v)
    return bytes(out)


def parse_hex(text: str) -> bytes:
    if not isinstance(text, str) or _HEX_RE.fullmatch(text) is None or len(text) % 2 != 0:
        raise RuntimeError("QRNG: malformed hex payload")
    return bytes.fromhex(text)


def parse_base64(text: str) -> bytes:
    """Standard-alphabet base64 as the WHATWG forgiving decode reads it: padding optional but exact when present, spare trailing bits dropped.
    None and an integer are read as their JSON text ("null", "12"), as the reference reads them."""
    if text is None or (isinstance(text, int) and not isinstance(text, bool)):
        text = "null" if text is None else str(text)
    if not isinstance(text, str) or _B64_RE.fullmatch(text) is None:
        raise RuntimeError("QRNG: malformed base64 payload")
    data = text
    if len(data) % 4 == 0:
        data = data[:-2] if data.endswith("==") else data[:-1] if data.endswith("=") else data
    if len(data) % 4 == 1 or "=" in data:
        raise RuntimeError("QRNG: malformed base64 payload")
    return base64.b64decode(data + "=" * (-len(data) % 4))


# ---- SP 800-90B 4.4 continuous health tests ----------------------------------------------------------------------------------------

@dataclass(frozen=True)
class HealthVerdict:
    ok: bool
    test: Optional[str] = None  # "repetition-count" | "adaptive-proportion" when not ok


def _div(a: float, b: float) -> float:
    """IEEE-754 division (a zero divisor gives an infinity or NaN, as the reference arithmetic does)."""
    try:
        return a / b
    except ZeroDivisionError:
        return math.nan if a == 0 or a != a else math.copysign(math.inf, a) * math.copysign(1.0, b)


def repetition_cutoff(h: float) -> float:
    """Repetition count cutoff 1 + ceil(20 / h) for a claimed min-entropy of h bits per byte (false-positive rate 2^-20)."""
    q = _div(20.0, float(h))
    return q if q != q else 1 + q if q in (math.inf, -math.inf) else 1 + math.ceil(q)


def proportion_cutoff(h: float, w: float) -> int:
    """Adaptive proportion cutoff for a window of w samples at min-entropy h: 1 + the smallest k whose binomial CDF reaches 1 - 2^-20."""
    h, w = float(h), float(w)
    p = fdlibm_pow(2.0, -h)
    target = 1 - fdlibm_pow(2.0, -20.0)
    pmf = fdlibm_pow(1 - p, w)
    cdf = pmf
    k = 0
    while cdf < target and k < w:
        pmf *= _div(w - k, k + 1) * _div(p, 1 - p)
        k += 1
        cdf += pmf
    return 1 + k


def health_test_bytes(data: bytes, h: Optional[float] = None, window: Optional[int] = None) -> HealthVerdict:
    """Repetition count over the whole buffer, then adaptive proportion over each complete window. Fails CLOSED on an empty buffer and on
    parameters outside h in [1, 8] / an integer window >= 2."""
    if not isinstance(data, _BYTES):
        raise TypeError("health_test_bytes: expected bytes")
    h = 8 if h is None else h
    w0 = 512 if window is None else window
    bad = HealthVerdict(False, "repetition-count")
    if isinstance(h, bool) or not isinstance(h, (int, float)) or not (1 <= h <= 8) or not _is_int(w0) or w0 < 2:
        return bad
    if len(data) == 0:
        return bad
    rc = repetition_cutoff(h)
    run = 1
    for i in range(1, len(data)):
        run = run + 1 if data[i] == data[i - 1] else 1
        if run >= rc:
            return bad
    w = min(int(w0), len(data))
    ac = proportion_cutoff(h, w)
    for start in range(0, len(data) - w + 1, w):
        if data.count(data[start:start + 1], start, start + w) >= ac:
            return HealthVerdict(False, "adaptive-proportion")
    return HealthVerdict(True)


# ---- the combiner ------------------------------------------------------------------------------------------------------------------

def mix_entropy(local: bytes, quantum: bytes, length: Optional[int] = None, context: Optional[str] = None) -> bytes:
    """HKDF-SHA256 over the length-framed pair (local, quantum): `length` bytes (default len(local)), domain-separated by `context`.
    `local` shorter than 16 bytes refuses; `quantum` may be empty."""
    if not isinstance(local, _BYTES):
        raise TypeError("mixEntropy: `local` must be bytes")
    if not isinstance(quantum, _BYTES):
        raise TypeError("mixEntropy: `quantum` must be bytes")
    if len(local) < MIN_LOCAL_BYTES:
        raise ValueError("mixEntropy: local CSPRNG must be >= %d bytes (fail-closed)" % MIN_LOCAL_BYTES)
    length = len(local) if length is None else length
    if not _is_int(length) or length <= 0 or length > MAX_HKDF_OUTPUT:
        raise ValueError("mixEntropy: length must be an integer in 1..%d" % MAX_HKDF_OUTPUT)
    length = int(length)
    ikm = len(local).to_bytes(4, "big") + len(quantum).to_bytes(4, "big") + bytes(local) + bytes(quantum)
    label = "%s/%s" % (_MIX_LABEL, context) if isinstance(context, str) and context else _MIX_LABEL
    return hkdf_sha256(ikm, _MIX_SALT, utf8(label) + length.to_bytes(4, "big"), length)


# ---- seeds -------------------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SecureSeedResult:
    seed: bytes
    used_quantum: bool
    quantum_byte_count: int  # bytes of quantum entropy mixed in (0 on fallback)
    source: Optional[str]

    def __repr__(self) -> str:  # never print the seed
        return "SecureSeedResult(used_quantum=%r, quantum_byte_count=%r, source=%r)" % (self.used_quantum, self.quantum_byte_count, self.source)


def secure_seed(length: Optional[int] = None, *, source: Any = None, quantum_bytes: Optional[int] = None, local_bytes: Optional[int] = None,
                context: Optional[str] = None, require_quantum: bool = False, health_test: Any = None,
                on_qrng_error: Optional[Callable[[BaseException], None]] = None,
                random_bytes_impl: Optional[Callable[[int], bytes]] = None) -> SecureSeedResult:
    """A seed of `length` bytes (default 32) from the local CSPRNG mixed with best-effort, health-tested quantum bytes of `source`.

    A failing, short or unhealthy source falls back to the local CSPRNG alone (reported through `on_qrng_error`, whose own failure is
    ignored); ``require_quantum=True`` turns that fallback into an ``EntropyError('quantum_required')``. `health_test` is ``False`` to
    disable the tests or ``{"h": ..., "window": ...}``; `random_bytes_impl` replaces os.urandom (tests)."""
    length = DEFAULT_SEED_BYTES if length is None else length
    if not _is_int(length) or length <= 0 or length > MAX_HKDF_OUTPUT:
        raise ValueError("secureSeed: length must be an integer in 1..%d" % MAX_HKDF_OUTPUT)
    length = int(length)
    local_bytes = max(DEFAULT_SEED_BYTES, length) if local_bytes is None else local_bytes
    if not _is_int(local_bytes) or local_bytes < MIN_LOCAL_BYTES:
        raise ValueError("secureSeed: localBytes must be an integer >= %d" % MIN_LOCAL_BYTES)
    quantum_bytes = max(DEFAULT_SEED_BYTES, length) if quantum_bytes is None else quantum_bytes
    if not _is_int(quantum_bytes) or quantum_bytes <= 0:
        raise ValueError("secureSeed: quantumBytes must be a positive integer")
    local_bytes, quantum_bytes = int(local_bytes), int(quantum_bytes)
    local = random_bytes_impl(local_bytes) if random_bytes_impl is not None else os.urandom(local_bytes)
    if not isinstance(local, _BYTES) or len(local) != local_bytes:
        raise RuntimeError("secureSeed: local CSPRNG did not return the requested bytes (fail-closed)")
    quantum = b""
    used = False
    name = None
    if source is not None:
        name = source.name
        try:
            q = source.fetch(quantum_bytes)
            if not isinstance(q, _BYTES) or len(q) != quantum_bytes:
                raise RuntimeError("QRNG: source returned %s, expected %d" % (len(q) if isinstance(q, _BYTES) else "non-bytes", quantum_bytes))
            if health_test is not False:
                v = health_test_bytes(q, **{k: (health_test or {}).get(k) for k in ("h", "window")})
                if not v.ok:
                    raise EntropyError("health_test_failed", "QRNG: %s test failed; source rejected" % (v.test or "health"))
            quantum, used = bytes(q), True
        except Exception as err:  # noqa: BLE001 - any source failure is a fallback, never a failure of key generation
            quantum, used = b"", False
            if on_qrng_error is not None:
                try:
                    on_qrng_error(err)
                except Exception:  # noqa: BLE001 - observability must never break key generation
                    pass
    if require_quantum is True and not used:
        raise EntropyError("quantum_required", "secureSeed: quantum entropy is required but was not obtained (fail-closed)")
    return SecureSeedResult(mix_entropy(local, quantum, length, context), used, len(quantum) if used else 0, name)


@dataclass(frozen=True)
class EntropyKeyPair:
    secret_key: bytes  # the 32-byte Ed25519 seed
    public_key: bytes
    used_quantum: bool

    def __repr__(self) -> str:  # never print the secret
        return "EntropyKeyPair(public_key=%r, used_quantum=%r)" % (self.public_key, self.used_quantum)


def generate_keypair_with_entropy(*, context: Optional[str] = None, **options: Any) -> EntropyKeyPair:
    """An Ed25519 key pair whose seed is secure_seed(length=32, context=`context` or "ed25519-key", ...); takes secure_seed's keywords."""
    options.pop("length", None)
    r = secure_seed(32, context="ed25519-key" if context is None else context, **options)
    from .kem import _sodium  # libsodium through pysodium (a core dependency): constant-time public-key derivation
    pk, sk = ctypes.create_string_buffer(32), ctypes.create_string_buffer(64)
    if _sodium().crypto_sign_seed_keypair(pk, sk, r.seed) != 0:
        raise RuntimeError("generate_keypair_with_entropy: Ed25519 key derivation failed")
    return EntropyKeyPair(r.seed, pk.raw, r.used_quantum)


__all__ = [
    "MAX_HKDF_OUTPUT", "MIN_LOCAL_BYTES", "DEFAULT_SEED_BYTES", "DEFAULT_MAX_QRNG_BYTES", "DEFAULT_TIMEOUT_MS", "EntropyError",
    "NullQrngSource", "unavailable_source", "HttpQrngSource", "parse_anu_uint8", "parse_hex", "parse_base64", "HealthVerdict",
    "repetition_cutoff", "proportion_cutoff", "health_test_bytes", "mix_entropy", "SecureSeedResult", "secure_seed", "EntropyKeyPair",
    "generate_keypair_with_entropy",
]
