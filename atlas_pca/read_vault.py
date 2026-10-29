"""Tokenisation vault and aggregate read limits (K5 follow-up, C-315..C-319; verification side). Companion of ``readside``.

VAULT. ``redact_read_with_vault`` runs ``redact_read`` and records every ``token`` it minted (class, value, grant digest) in a
vault store; ``detokenize`` returns the value only for a sink the SAME signed, unexpired, pinned-principal grant lets that class
reach (an ``escalate`` class asks). Everything else denies.

AGGREGATES. ``aggregate_read`` is a pure step over an explicit state ``{spent_micro, queries, answered}``: group-size floor,
per-value clamp, query cap, integer micro-epsilon budget, a repeated identical query answered from the state for free. With
``dp`` the answer gets discrete Laplace noise from an INTEGER-EXACT sampler (Canonne-Kamath-Steinke) over a stream of SHA-256
blocks: ``seeded`` is keyed by the salt and the query digest (every language agrees byte for byte; the shared vectors pin it),
``secure`` by the OS CSPRNG. Signing is the reference implementation's job. Total functions; integers only."""
import re
import secrets
from typing import Any, Dict, List, Optional

from .k3 import is_obj, is_str, verify_body
from .pca import b64u, decode_b64u_strict, hash_canonical
from .readside import READ_GRANT_DOMAIN, read_grant_digest, redact_read, valid_read_grant_body
from .workflow import ID_RE, is_b32, is_int, is_uint, only_keys, rx, sorted_unique


# ---- vault ----------------------------------------------------------------------------------------------------------------


class MemoryVault:
    """In-memory token store (``put(token, entry)`` / ``get(token)``); entry ``{cls, value, grant, exp}``."""

    def __init__(self) -> None:
        self._m: Dict[str, dict] = {}

    def put(self, token: str, entry: dict) -> None:
        self._m[token] = entry

    def get(self, token: str) -> Optional[dict]:
        return self._m.get(token)


def memory_vault() -> MemoryVault:
    return MemoryVault()


def redact_read_with_vault(inp: Any, store: Any) -> dict:
    """``redact_read`` that also records every token it minted in ``store``."""
    r = redact_read(inp)
    if r["decision"] != "allow":
        return r
    try:
        g = inp["grant"]["body"]
        digest = read_grant_digest(g)
        for path, f in r["fields"].items():
            if f["action"] == "masked" and f["kind"] == "token":
                store.put(r["view"][path], {"cls": f["class"], "value": inp["record"][path], "grant": digest, "exp": g["expires_at"]})
    except Exception:  # noqa: BLE001 - a store that fails must not hand out tokens nobody can redeem
        return {"decision": "deny", "code": "bad_request", "view": {}, "fields": {}, "labels": [], "counts": dict(r["counts"])}
    return r


def _no(code: str) -> dict:
    return {"decision": "deny", "code": code, "value": None}


def detokenize(inp: Any) -> dict:
    """Turn a token back into its value, only for a sink the grant allows that token's class to reach.
    ``inp``: grant, principal, now, sink, token, store."""
    try:
        if not (is_b32(inp.get("principal")) and is_uint(inp.get("now")) and isinstance(inp.get("token"), str) and isinstance(inp.get("sink"), str)):
            return _no("bad_request")
        sg = inp.get("grant")
        if not is_obj(sg) or not only_keys(sg, ("body", "sig")) or not valid_read_grant_body(sg["body"]):
            return _no("bad_grant")
        b = sg["body"]
        if b["principal"] != inp["principal"] or not verify_body(READ_GRANT_DOMAIN, b, inp["principal"], sg["sig"]):
            return _no("bad_signature")
        if inp["now"] < b["issued_at"]:
            return _no("not_yet")
        if inp["now"] >= b["expires_at"]:
            return _no("expired")
        e = inp["store"].get(inp["token"])
        if e is None or e["grant"] != read_grant_digest(b):
            return _no("unknown_token")
        if inp["now"] >= e["exp"]:
            return _no("expired")
        rule = b["sinks"].get(inp["sink"])
        if rule is None:
            return _no("unknown_sink")
        if e["cls"] in rule["allow"]:
            return {"decision": "allow", "code": None, "value": e["value"]}
        if e["cls"] in rule["escalate"]:
            return {"decision": "escalate", "code": "label_escalate", "value": None}
        return _no("label_flow")
    except Exception:  # noqa: BLE001
        return _no("bad_request")


# ---- aggregates -----------------------------------------------------------------------------------------------------------

AGGREGATE_DOMAIN = "atlas-pca/aggregate-grant/v1\0"
_AG_REF = "atlas-pca/aggregate-grant-ref/v1"
_AG_Q = "atlas-pca/aggregate-query/v1"
_AG_N = "atlas-pca/aggregate-noise/v1"
_FN_RE = re.compile(r"count|sum")


def empty_aggregate_state() -> dict:
    return {"spent_micro": 0, "queries": 0, "answered": {}}


def _valid_rule(r: Any) -> bool:
    return (is_obj(r) and only_keys(r, ("verb", "resource_prefix", "purposes", "fns", "min_group", "clamp", "epsilon_micro", "dp"))
            and is_str(r["verb"], 128) and is_str(r["resource_prefix"], 512) and sorted_unique(r["purposes"], ID_RE, 16) and len(r["purposes"]) > 0
            and sorted_unique(r["fns"], _FN_RE, 2) and len(r["fns"]) > 0 and is_uint(r["min_group"]) and r["min_group"] >= 1
            and is_uint(r["clamp"]) and r["clamp"] <= 1_000_000 and is_uint(r["epsilon_micro"]) and r["epsilon_micro"] <= 1_073_741_824
            and isinstance(r["dp"], bool) and (r["epsilon_micro"] >= 1 if r["dp"] else True))


def valid_aggregate_grant_body(b: Any) -> bool:
    return (is_obj(b) and only_keys(b, ("v", "id", "principal", "issued_at", "expires_at", "rules", "epsilon_budget_micro", "max_queries"))
            and is_int(b["v"]) and b["v"] == 1 and rx(ID_RE, b["id"]) and is_b32(b["principal"]) and is_uint(b["issued_at"]) and is_uint(b["expires_at"])
            and isinstance(b["rules"], list) and 1 <= len(b["rules"]) <= 16 and all(_valid_rule(r) for r in b["rules"])
            and is_uint(b["epsilon_budget_micro"]) and is_uint(b["max_queries"]))


def aggregate_grant_digest(b: dict) -> str:
    return hash_canonical({"d": _AG_REF, "g": b})


def _clamped(values: List[int], clamp: int) -> int:
    return sum(max(-clamp, min(clamp, v)) for v in values)


def aggregate_read(inp: Any) -> dict:
    """Answer one aggregate under the grant, or refuse. The input state is never mutated. ``inp``: grant, principal, now, verb,
    resource, purpose, fn, values, salt, noise, state. Result: ``{decision, code, value, state, charged_micro}``."""
    def fail(code: str, s: Optional[dict] = None) -> dict:
        return {"decision": "deny", "code": code, "value": None, "state": empty_aggregate_state() if s is None else s, "charged_micro": 0}
    try:
        st = inp.get("state")
        if not is_obj(st) or not is_uint(st.get("spent_micro")) or not is_uint(st.get("queries")) or not is_obj(st.get("answered")) \
                or not all(is_int(v) for v in st["answered"].values()):
            return fail("bad_request")

        def keep(code: str) -> dict:
            return fail(code, st)
        principal, now = inp.get("principal"), inp.get("now")
        if not is_b32(principal) or not is_uint(now):
            return keep("bad_request")
        sg = inp.get("grant")
        if not is_obj(sg) or not only_keys(sg, ("body", "sig")) or not valid_aggregate_grant_body(sg["body"]):
            return keep("bad_grant")
        g = sg["body"]
        if g["principal"] != principal or not verify_body(AGGREGATE_DOMAIN, g, principal, sg["sig"]):
            return keep("bad_signature")
        if now < g["issued_at"]:
            return keep("not_yet")
        if now >= g["expires_at"]:
            return keep("expired")
        verb, resource, purpose, fn, noise, salt, values = (inp.get(k) for k in ("verb", "resource", "purpose", "fn", "noise", "salt", "values"))
        if not (is_str(verb, 128) and is_str(resource, 512) and rx(ID_RE, purpose) and isinstance(fn, str) and fn in ("count", "sum")
                and isinstance(noise, str) and noise in ("seeded", "secure") and isinstance(salt, str) and len(salt.encode("utf-16-le", "surrogatepass")) // 2 >= 16
                and isinstance(values, list) and len(values) <= 1_000_000 and all(is_int(v) for v in values)):
            return keep("bad_request")
        rule = next((r for r in g["rules"] if r["verb"] == verb and resource.startswith(r["resource_prefix"]) and purpose in r["purposes"]), None)
        if rule is None or fn not in rule["fns"]:
            return keep("no_read_scope")
        if len(values) < rule["min_group"]:
            return keep("group_too_small")
        total = _clamped(values, rule["clamp"])
        qd = hash_canonical({"d": _AG_Q, "g": aggregate_grant_digest(g), "verb": verb, "resource": resource, "purpose": purpose, "fn": fn, "n": len(values), "s": total})
        prior = st["answered"].get(qd)
        if prior is not None:
            return {"decision": "allow", "code": None, "value": prior, "state": st, "charged_micro": 0}
        if st["queries"] + 1 > g["max_queries"]:
            return keep("query_cap")
        cost = rule["epsilon_micro"] if rule["dp"] else 0
        if st["spent_micro"] + cost > g["epsilon_budget_micro"]:
            return keep("epsilon_exhausted")
        exact = len(values) if fn == "count" else total
        if rule["dp"]:
            sens = 1 if fn == "count" else rule["clamp"]
            draws = secure_draws() if noise == "secure" else seeded_draws(hash_canonical({"d": _AG_N, "salt": salt, "q": qd}))
            exact += discrete_laplace(draws, rule["epsilon_micro"], sens * 1_000_000)
        nxt = {"spent_micro": st["spent_micro"] + cost, "queries": st["queries"] + 1, "answered": {**st["answered"], qd: exact}}
        return {"decision": "allow", "code": None, "value": exact, "state": nxt, "charged_micro": cost}
    except Exception:  # noqa: BLE001 - includes the sampler's RangeError
        return fail("bad_request")


# ---- integer-exact discrete Laplace sampler (Canonne, Kamath, Steinke 2020, Alg. 1-2) ------------------------------------------
# Python ints are unbounded, so every step is exact. P[noise = x] is proportional to exp(-|x| * epsilon / sensitivity).

_DP_STREAM = "atlas-pca/dp-stream/v1"
_TWO48 = 2**48
_MAX_STEPS = 100_000


class SamplerRangeError(Exception):
    """The reference's RangeError: a bad bound, or a sampler that did not terminate."""


class SeededDraws:
    """Block i is SHA-256 of the canonical ``{d, seed, i}``; each block yields five 48-bit big-endian values (bytes 0-5, 6-11, ...)."""

    def __init__(self, seed: str) -> None:
        self._seed, self._block, self._buf = seed, 0, []

    def _next48(self) -> int:
        if not self._buf:
            raw = decode_b64u_strict(hash_canonical({"d": _DP_STREAM, "seed": self._seed, "i": self._block}), 32)
            self._block += 1
            self._buf = [int.from_bytes(raw[k * 6:k * 6 + 6], "big") for k in range(4, -1, -1)]  # popped from the end: first value first
        return self._buf.pop()

    def uniform(self, n: Any) -> int:
        if not is_int(n) or n < 1 or n > 2**47:
            raise SamplerRangeError("uniform: bad bound")
        limit = _TWO48 - (_TWO48 % n)
        for _ in range(_MAX_STEPS):
            r = self._next48()
            if r < limit:
                return r % n
        raise SamplerRangeError("uniform: no draw")


def seeded_draws(seed: str) -> SeededDraws:
    return SeededDraws(seed)


def secure_draws() -> SeededDraws:
    """The PRODUCTION setting: a fresh 32-byte seed from the OS CSPRNG (base64url, unpadded) through the same sampler. Answers differ
    per call; a repeated query is still answered from the state."""
    return SeededDraws(b64u(secrets.token_bytes(32)))


def _bern_exp_small(d: SeededDraws, num: int, den: int) -> bool:
    """Bernoulli(exp(-num/den)) for 0 <= num/den <= 1."""
    for k in range(1, _MAX_STEPS + 1):
        if not d.uniform(den * k) < num:  # not Bernoulli(num / (den * k))
            return k % 2 == 1
    raise SamplerRangeError("bernoulli: no termination")


def discrete_laplace(d: SeededDraws, s: int, t: int) -> int:
    """Discrete Laplace with P[x] proportional to exp(-|x| s / t) (CKS Alg. 2: s the rate numerator, t the scale denominator)."""
    if not is_int(s) or not is_int(t) or s < 1 or t < 1:
        raise SamplerRangeError("laplace: bad parameters")
    for _ in range(_MAX_STEPS):
        u = d.uniform(t)
        if not _bern_exp_small(d, u, t):
            continue
        v = 0
        while _bern_exp_small(d, 1, 1):
            v += 1
            if v > _MAX_STEPS:
                raise SamplerRangeError("laplace: no termination")
        y = (u + t * v) // s
        negative = d.uniform(2) == 1
        if negative and y == 0:
            continue
        return -y if negative else y
    raise SamplerRangeError("laplace: no sample")
