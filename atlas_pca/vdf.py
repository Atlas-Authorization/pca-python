"""Wesolowski VDF over an RSA group plus the PCA timelock (the TypeScript reference, @atlasauth/pca-vdf).

Pure big-integer math on Python's arbitrary-precision int; stdlib only. Same domains, transcript, error texts and check order as
the reference, so challenge primes, proofs and timelock inputs are byte-identical. A VDF in an RSA group needs a modulus of unknown
factorisation (see RSA_2048_CHALLENGE_MODULUS / checkProductionModulus); the dev setup below is for tests only.
"""
from __future__ import annotations

from ._fin import fin
import hashlib
import math
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Set, Union

from .pca import hash_canonical

CHALLENGE_PRIME_BITS = 256
INSECURE_DEV_SETUP_DEFAULT_BITS = 2048
MIN_PRODUCTION_MODULUS_BITS = 2048

RSA_2048_CHALLENGE_MODULUS = int(
    "2519590847565789349402718324004839857142928212620403202777713783604366202070"
    "7595556264018525880784406918290641249515082189298559149176184502808489120072"
    "8449926873928072877767359714183472702618963750149718246911650776133798590957"
    "0009733045974880842840179742910064245869181719511874612151517265463228221686"
    "9987549182422433637259085141865462043576798423387184774447920739934236584823"
    "8242811981638150106748104516603773060562016196762561338441436038339044149526"
    "3443219011465754445417842402092461651572335077870774981712577246796292638635"
    "6373289912154831438167899885040445364023527381951378636564391212010397122822"
    "120720357"
)
DEFAULT_MODULUS = RSA_2048_CHALLENGE_MODULUS

_MAX_SAFE = 2 ** 53 - 1


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _safe_int(v: Any) -> Optional[int]:
    """The value as an int when it is a JS-safe integer (a float with an integral value counts, as in JS), else None."""
    if _is_int(v):
        return v if abs(v) <= _MAX_SAFE else None
    if isinstance(v, float) and v == v and abs(v) <= _MAX_SAFE and v == int(v):
        return int(v)
    return None


def _rem(a: int, n: int) -> int:
    """JS BigInt `%`: the sign follows the dividend; a zero divisor raises."""
    r = abs(a) % abs(n)
    return -r if a < 0 else r


def _umod(x: int, n: int) -> int:
    return _rem(_rem(x, n) + n, n)


def utf8(s: str) -> bytes:
    """TextEncoder semantics: a lone surrogate becomes U+FFFD instead of raising."""
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def bytes_to_big_int(b: bytes) -> int:
    return int.from_bytes(bytes(b), "big")


def big_int_to_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("bigIntToBytes: negative value")
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _u32be(n: int) -> bytes:
    return (n & 0xFFFFFFFF).to_bytes(4, "big")


def _u64be(n: int) -> bytes:
    return (n & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")


def _len_prefixed(b: bytes) -> bytes:
    return _u32be(len(b)) + b


def _normalize_steps(t: Any) -> int:
    s = _safe_int(t)
    if s is None or s < 0:
        raise ValueError("VDF: steps T must be a non-negative safe integer, got %s" % (t,))
    return s


def gcd(a: int, b: int) -> int:
    x, y = abs(a), abs(b)
    while y != 0:
        x, y = y, x % y
    return x


def _is_unit(v: int, n: int) -> bool:
    return 0 < v < n and gcd(v, n) == 1


def modpow(base: int, exp: int, mod: int) -> int:
    if mod <= 0:
        raise ValueError("modpow: modulus must be positive")
    if mod == 1:
        return 0
    if exp < 0:
        raise ValueError("modpow: negative exponent (no inverse in a group of unknown order)")
    return pow(base, exp, mod)


# ---- primality: Baillie-PSW (strong Miller-Rabin on the first 25 primes + strong Lucas)

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)


def _is_perfect_square(n: int) -> bool:
    if n < 0:
        return False
    if n < 2:
        return True
    r = math.isqrt(n)
    return r * r == n


def _jacobi(a: int, n: int) -> int:
    r = 1
    a %= n
    while a != 0:
        while (a & 1) == 0:
            a >>= 1
            if (n & 7) in (3, 5):
                r = -r
        a, n = n, a
        if (a & 3) == 3 and (n & 3) == 3:
            r = -r
        a %= n
    return r if n == 1 else 0


def is_strong_lucas_probable_prime(n: int) -> bool:
    if n < 3 or (n & 1) == 0 or _is_perfect_square(n):
        return False
    d_ = 5
    while True:
        j = _jacobi(d_, n)
        if j == -1:
            break
        if j == 0 and abs(d_) != n:
            return False
        d_ = -(d_ + 2) if d_ > 0 else -d_ + 2
    p = 1
    q = (1 - d_) // 4  # exact: D = 1 (mod 4)

    def mod(x: int) -> int:
        return x % n

    def half(x: int) -> int:
        return (x + n if (x & 1) == 1 else x) >> 1

    d = n + 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1
    u, v, qk = 1, p, mod(q)
    bits = bin(d)[2:]
    for i in range(1, len(bits)):
        u = mod(u * v)
        v = mod(v * v - 2 * qk)
        qk = mod(qk * qk)
        if bits[i] == "1":
            u1 = half(mod(p * u + v))
            v1 = half(mod(d_ * u + p * v))
            u, v = u1, v1
            qk = mod(qk * q)
    if u == 0 or v == 0:
        return True
    for _ in range(1, s):
        v = mod(v * v - 2 * qk)
        if v == 0:
            return True
        qk = mod(qk * qk)
    return False


def is_miller_rabin_probable_prime(n: int) -> bool:
    if n < 3 or (n & 1) == 0:
        return False
    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1
    for a in _SMALL_PRIMES:
        base = a % n
        if base == 0:
            continue
        x = pow(base, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(1, s):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


# the product of every prime below 20000 and that bound: one gcd sieves a big candidate far faster than a modular exponentiation (module-level
# statements, not a function, so the pinned fuzz does not try to print a 30 000-digit integer)
_SIEVE_BOUND = 20000
_PRIMORIAL = 1
_flags = bytearray([1]) * _SIEVE_BOUND
for _i in range(2, _SIEVE_BOUND):
    if _flags[_i]:
        _PRIMORIAL *= _i
        _flags[_i * _i::_i] = bytearray(len(_flags[_i * _i::_i]))
del _flags, _i


def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    if n > _SIEVE_BOUND and math.gcd(n, _PRIMORIAL) != 1:  # a factor below the bound: composite (the same verdict the tests below reach)
        return False
    return is_miller_rabin_probable_prime(n) and is_strong_lucas_probable_prime(n)


# ---- Fiat-Shamir challenge prime

_HASH_TO_PRIME_DOMAIN = b"atlas-pca/vdf/wesolowski/hash-to-prime/v1\x00"


def hash_to_prime(x: int, y: int, t: Any, n: int, bits: Any = CHALLENGE_PRIME_BITS) -> int:
    b = _safe_int(bits)
    if b is None or b < 8 or b > 8192:
        raise ValueError("hashToPrime: bits must be an integer in [8, 8192]")
    steps = _normalize_steps(t)
    xr, yr = _umod(x, n), _umod(y, n)
    transcript = (
        _HASH_TO_PRIME_DOMAIN
        + _len_prefixed(big_int_to_bytes(xr))
        + _len_prefixed(big_int_to_bytes(yr))
        + _len_prefixed(big_int_to_bytes(steps))
        + _len_prefixed(big_int_to_bytes(n))
        + _len_prefixed(_u32be(b))
    )
    seed = hashlib.sha256(transcript).digest()
    bytes_needed = (b + 7) // 8
    top_bit = 1 << (b - 1)
    mask = (1 << b) - 1
    counter = 0
    while True:
        chunks = b""
        block_index = 0
        while len(chunks) < bytes_needed:
            chunks += hashlib.sha256(seed + _u64be(counter) + _u32be(block_index)).digest()
            block_index += 1
        cand = (bytes_to_big_int(chunks[:bytes_needed]) & mask) | top_bit | 1
        if is_probable_prime(cand):
            return cand
        counter += 1


# ---- the VDF

def sequential_square(x: int, t: Any, n: int) -> int:
    if n <= 1:
        raise ValueError("VDF: modulus N must be > 1")
    steps = _normalize_steps(t)
    y = _umod(x, n)
    for _ in range(steps):
        y = (y * y) % n
    return y


def _wesolowski_proof(x: int, t: int, l: int, n: int) -> int:
    xr = _umod(x, n)
    pi = 1 % n
    r = 1 % l
    for _ in range(t):
        two_r = r * 2
        b = two_r // l
        r = two_r % l
        pi = (pi * pi) % n
        if b == 1:
            pi = (pi * xr) % n
    return pi


def _check_eval_input(x: int, n: int) -> None:
    xr = _umod(x, n)
    if not _is_unit(xr, n) or xr == 1 or xr == n - 1:
        raise ValueError("VDF: input x must be a non-trivial unit mod N (not 0, 1, -1, or sharing a factor with N)")


def vdf_eval(x: int, t: Any, n: int) -> Dict[str, int]:
    if n <= 3 or (n & 1) == 0:
        raise ValueError("VDF: modulus N must be odd and > 3")
    steps = _normalize_steps(t)
    _check_eval_input(x, n)
    y = sequential_square(x, t, n)
    l = hash_to_prime(x, y, t, n)
    return {"y": y, "pi": _wesolowski_proof(x, steps, l, n)}


def _verdict(ok: bool, reason: Optional[str] = None) -> Dict[str, Any]:
    return {"ok": True} if ok else {"ok": False, "reason": reason}


def _verify(x: Any, y: Any, pi: Any, t: Any, n: Any, canonical: bool) -> Dict[str, Any]:
    try:
        if not (_is_int(x) and _is_int(y) and _is_int(pi) and _is_int(n)):
            return _verdict(False, "malformed-input")
        if n <= 3 or (n & 1) == 0:
            return _verdict(False, "bad-modulus")
        steps = _safe_int(t)
        if steps is None or steps < 0:
            return _verdict(False, "bad-steps")
        if not _is_unit(y, n) or (canonical and y > n - y):
            return _verdict(False, "non-canonical-y")
        if not _is_unit(pi, n) or (canonical and pi > n - pi):
            return _verdict(False, "non-canonical-pi")
        xr = _umod(x, n)
        if not _is_unit(xr, n) or xr == 1 or xr == n - 1:
            return _verdict(False, "bad-input-x")
        l = hash_to_prime(x, y, steps, n)
        r = modpow(2, steps, l)
        lhs = (modpow(pi, l, n) * modpow(xr, r, n)) % n
        good = lhs == y or lhs == n - y if canonical else lhs == y
        return _verdict(good, "equation-mismatch")
    except Exception:  # noqa: BLE001 - fail closed, like the reference catch
        return _verdict(False, "malformed-input")


def vdf_verify_detailed(x: Any, y: Any, pi: Any, t: Any, n: Any) -> Dict[str, Any]:
    """{"ok": True} or {"ok": False, "reason": ...}; never raises."""
    return _verify(x, y, pi, t, n, False)


def canonical_vdf_output(y: int, n: int) -> int:
    return n - y if y > n - y else y


def vdf_eval_canonical(x: int, t: Any, n: int) -> Dict[str, int]:
    if n <= 3 or (n & 1) == 0:
        raise ValueError("VDF: modulus N must be odd and > 3")
    steps = _normalize_steps(t)
    _check_eval_input(x, n)
    y = canonical_vdf_output(sequential_square(x, t, n), n)
    l = hash_to_prime(x, y, t, n)
    return {"y": y, "pi": canonical_vdf_output(_wesolowski_proof(x, steps, l, n), n)}


def vdf_verify_canonical_detailed(x: Any, y: Any, pi: Any, t: Any, n: Any) -> Dict[str, Any]:
    return _verify(x, y, pi, t, n, True)


def vdf_verify_canonical(x: Any, y: Any, pi: Any, t: Any, n: Any) -> bool:
    return vdf_verify_canonical_detailed(x, y, pi, t, n)["ok"]


def vdf_verify(x: Any, y: Any, pi: Any, t: Any, n: Any) -> bool:
    return vdf_verify_detailed(x, y, pi, t, n)["ok"]


# ---- modulus screening (an RSA-group VDF is only as good as the modulus's unknown factorisation)

_INSECURE_DEV_MODULI: Set[int] = set()
_PRODUCTION_SCREEN_PASSED: Set[int] = set()
_SCREEN_PRIMES: List[int] = []


def _screen_primes() -> List[int]:
    if not _SCREEN_PRIMES:
        limit = 1 << 16
        sieve = bytearray(limit)
        for i in range(2, limit):
            if sieve[i]:
                continue
            _SCREEN_PRIMES.append(i)
            for j in range(i * i, limit, i):
                sieve[j] = 1
    return _SCREEN_PRIMES


def _random_prime(bits: int, rnd: Callable[[int], bytes]) -> int:
    if bits < 16 or bits > 8192:
        raise ValueError("randomPrime: bits must be in [16, 8192]")
    nbytes = (bits + 7) // 8
    top_bit = 1 << (bits - 1)
    mask = (1 << bits) - 1
    for _ in range(50000):
        cand = (bytes_to_big_int(rnd(nbytes)) & mask) | top_bit | 1
        if is_probable_prime(cand):
            return cand
    raise RuntimeError("insecureDevSetup: randomness source failed to yield a prime (stuck or constant RNG?)")


def insecure_dev_setup(bits: Optional[int] = None, random_bytes: Optional[Callable[[int], bytes]] = None) -> Dict[str, Any]:
    """TEST ONLY: a modulus whose factors the caller knows (so it delays nobody). Registered so the production screen refuses it."""
    bits = INSECURE_DEV_SETUP_DEFAULT_BITS if bits is None else bits
    if _safe_int(bits) is None or bits < 32:
        raise ValueError("insecureDevSetup: bits must be a safe integer >= 32")
    rnd = random_bytes or secrets.token_bytes
    half = bits // 2
    p = _random_prime(half, rnd)
    q = _random_prime(bits - half, rnd)
    i = 0
    while p == q:
        if i >= 8:
            raise RuntimeError("insecureDevSetup: randomness source returned the same prime repeatedly (constant RNG?)")
        q = _random_prime(bits - half, rnd)
        i += 1
    n = p * q
    _INSECURE_DEV_MODULI.add(n)
    return {"insecureDevOnly": True, "N": n, "p": p, "q": q, "bits": n.bit_length()}


def check_production_modulus(n: Any) -> Dict[str, Any]:
    if not _is_int(n):
        return {"ok": False, "reason": "modulus is not a bigint"}
    if n not in _INSECURE_DEV_MODULI and n in _PRODUCTION_SCREEN_PASSED:
        return {"ok": True}
    if n in _INSECURE_DEV_MODULI:
        return {"ok": False, "reason": "modulus came from insecureDevSetup(): its factors are known, so it provides no delay"}
    if n <= 3:
        return {"ok": False, "reason": "modulus is too small"}
    if n.bit_length() < MIN_PRODUCTION_MODULUS_BITS:
        return {"ok": False, "reason": "modulus is below %d bits" % MIN_PRODUCTION_MODULUS_BITS}
    if (n & 1) == 0:
        return {"ok": False, "reason": "modulus is even"}
    if _is_perfect_square(n):
        return {"ok": False, "reason": "modulus is a perfect square"}
    if is_probable_prime(n):
        return {"ok": False, "reason": "modulus is prime (group order N-1 is public)"}
    for p in _screen_primes():
        if n % p == 0:
            return {"ok": False, "reason": "modulus has the small prime factor %d" % p}
    _PRODUCTION_SCREEN_PASSED.add(n)
    return {"ok": True}


# ---- PCA timelock: the VDF challenge is bound to the action and to an unpredictable beacon

_X_DERIVATION_DOMAIN = "atlas-pca/vdf/timelock/input/v2\x00"
Beacon = Union[str, bytes]


def action_digest(action: Any) -> str:
    """A string is an opaque, precomputed digest; anything else is a PCActn digested like the ledger (strict canonical sha256)."""
    return action if isinstance(action, str) else hash_canonical(action)


def _beacon_bytes(beacon: Any) -> bytes:
    b = utf8(beacon) if isinstance(beacon, str) else beacon
    if not isinstance(b, (bytes, bytearray)) or len(b) == 0:
        raise ValueError("timelock: a non-empty beacon (unpredictable, post-action value) is required")
    return bytes(b)


def derive_timelock_input(action: Any, n: Any, beacon: Any) -> int:
    """x in [2, N) bound to the action and the beacon; deterministic."""
    if not _is_int(n) or n <= 3:
        raise ValueError("deriveTimelockInput: modulus N must be a bigint > 3")
    digest = utf8(action_digest(action))
    msg = utf8(_X_DERIVATION_DOMAIN) + _len_prefixed(digest) + _len_prefixed(_beacon_bytes(beacon))
    raw = bytes_to_big_int(hashlib.sha256(msg).digest()) % n
    return raw + 2 if raw <= 1 else raw


def _require_production_modulus(n: Any, allow_insecure_dev_modulus: Any) -> None:
    if allow_insecure_dev_modulus is True:
        return
    check = check_production_modulus(n)
    if not check["ok"]:
        raise ValueError(
            "timelock: refusing this modulus: %s. Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; "
            "tests may pass allowInsecureDevModulus: true." % check["reason"]
        )


def _require_steps(steps: Any) -> int:
    s = _safe_int(steps)
    if s is None or s < 1:
        raise ValueError("timelock: steps must be a safe integer >= 1, got %s" % (steps,))
    return s


def require_timelock(action: Any, steps: Any, n: Any, beacon: Any, allow_insecure_dev_modulus: Any = None) -> Dict[str, Any]:
    s = _require_steps(steps)
    _require_production_modulus(n, allow_insecure_dev_modulus)
    x = derive_timelock_input(action, n, beacon)
    return {"kind": "vdf-timelock", "x": x, "steps": s, "N": n, "actionDigest": action_digest(action)}


def prove_timelock_elapsed(action: Any, steps: Any, n: Any, beacon: Any, allow_insecure_dev_modulus: Any = None) -> Dict[str, Any]:
    """Runs the VDF: the squarings ARE the cooling-off, so this is deliberately slow."""
    s = _require_steps(steps)
    _require_production_modulus(n, allow_insecure_dev_modulus)
    x = derive_timelock_input(action, n, beacon)
    proof = vdf_eval_canonical(x, s, n)
    return {"kind": "vdf-timelock-proof", "y": proof["y"], "pi": proof["pi"], "steps": s}


def verify_timelock(action: Any, proof: Any, steps: Any, n: Any, beacon: Any, allow_insecure_dev_modulus: Any = None) -> bool:
    """Fail closed: any malformed input or refused modulus is False. Offline, no clock."""
    try:
        required = _require_steps(steps)
        _require_production_modulus(n, allow_insecure_dev_modulus)
        if not isinstance(proof, dict) or proof.get("kind") != "vdf-timelock-proof":
            return False
        if _safe_int(proof.get("steps")) is None or proof.get("steps") != required:
            return False
        if not _is_int(proof.get("y")) or not _is_int(proof.get("pi")):
            return False
        x = derive_timelock_input(action, n, beacon)
        return vdf_verify_canonical(x, proof["y"], proof["pi"], required, n)
    except Exception:  # noqa: BLE001
        return False


def calibrate_steps(
    n: int,
    desired_seconds: float,
    sample_squarings: int = 50000,
    adversary_advantage: float = 10,
    now: Optional[Callable[[], float]] = None,
) -> Dict[str, float]:
    """Operator helper: squarings measured here times a conservative adversary advantage, so the delay is a floor. `now` is in ms."""
    if not _is_int(n) or n <= 3:
        raise ValueError("calibrateSteps: modulus N must be a bigint > 3")
    if not isinstance(desired_seconds, (int, float)) or not fin(desired_seconds) or desired_seconds <= 0:
        raise ValueError("calibrateSteps: desiredSeconds must be > 0")
    if _safe_int(sample_squarings) is None or sample_squarings < 1:
        raise ValueError("calibrateSteps: sampleSquarings must be a safe integer >= 1")
    if not fin(adversary_advantage) or adversary_advantage < 1:
        raise ValueError("calibrateSteps: adversaryAdvantage must be >= 1")
    clock = now or (lambda: time.perf_counter() * 1000.0)
    y = 2 % n
    t0 = clock()
    for _ in range(int(sample_squarings)):
        y = (y * y) % n
    elapsed = max(clock() - t0, 2.220446049250313e-16)
    per_s = sample_squarings / elapsed * 1000.0
    adv = per_s * adversary_advantage
    return {"steps": max(1, math.ceil(adv * desired_seconds)), "measuredSquaringsPerSecond": per_s, "assumedAdversarySquaringsPerSecond": adv}
