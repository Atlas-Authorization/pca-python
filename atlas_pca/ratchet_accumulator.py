"""Homomorphic risk accumulator with a zero-knowledge spend ceiling (Pedersen commitments on ristretto255 plus a
bit-decomposition range proof). Mirrors the TypeScript reference (@atlasauth/pca-ratchet), wire format included:
proofs are JSON-shaped dicts with the reference's camelCase member names; a blinding is a plain Python int."""
from ._fin import fin
import math
from typing import Any, Callable, Dict, List, Optional, Sequence

from .ratchet_group import (
    G, H, L, ZERO, require_prover, add, decode_point, decode_scalar, encode_point, encode_scalar, equals, hash_to_scalar, mod, mul,
    number_to_bytes_le, rand_scalar, scalar_add, scalar_mul, scalar_sub, sub, to_raw_bytes, utf8,
)

N_BITS = 32


class AccumulatorError(Exception):
    """code: invalid_value | length_mismatch | invalid_proof_shape."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _as_units(x: Any) -> int:
    if isinstance(x, bool):
        raise AccumulatorError("invalid_value", "risk/budget must be a non-negative integer")
    if isinstance(x, int):
        if x < 0:
            raise AccumulatorError("invalid_value", "risk/budget must be >= 0")
        return x
    if not isinstance(x, float) or not fin(x) or x != math.floor(x) or x < 0:
        raise AccumulatorError("invalid_value", "risk/budget must be a non-negative integer")
    return int(x)


def commit_risk(risk: Any, blinding: Optional[int] = None) -> Dict[str, Any]:
    """Commit to a non-negative integer risk in units, with a given or fresh random blinding."""
    require_prover()
    v = _as_units(risk)
    b = rand_scalar() if blinding is None else mod(blinding)
    c = add(mul(G, v), mul(H, b))
    return {"commitment": encode_point(c), "blinding": b}


def add_commitments(commitments: Sequence[str]) -> str:
    """Homomorphic sum; an empty input commits to (0, 0), the identity."""
    acc = ZERO
    for c in commitments:
        acc = add(acc, decode_point(c))
    return encode_point(acc)


def open_commitment(commitment: Any, risk: Any, blinding: Any) -> bool:
    """Never raises; malformed input is False."""
    try:
        v = _as_units(risk)
        expected = add(mul(G, v), mul(H, mod(blinding)))
        return equals(decode_point(commitment), expected)
    except Exception:
        return False


_CTX_DOMAIN = utf8("atlas-pca-ratchet/budget/ctx/v1")
_RISK_CTX_DOMAIN = utf8("atlas-pca-ratchet/risk-range/ctx/v1")
_OR_DOMAIN = utf8("atlas-pca-ratchet/budget/bit-or/v1")
_AGG_DOMAIN = utf8("atlas-pca-ratchet/budget/agg/v1")

MAX_PROVABLE_CEILING = (1 << N_BITS) - 1


def _effective_ceiling(b_max: int) -> int:
    # a ceiling above the range is clamped: "sum <= 2^N-1" is strictly stronger, so a verifier is never weakened
    return MAX_PROVABLE_CEILING if b_max > MAX_PROVABLE_CEILING else b_max


def _context_hash(n: int, b_max: int, commitment_sum: Any, bits: List[Any]) -> bytes:
    parts = [_CTX_DOMAIN, bytes([n & 0xFF]), number_to_bytes_le(mod(b_max), 32), to_raw_bytes(commitment_sum)]
    parts.extend(to_raw_bytes(b) for b in bits)
    return number_to_bytes_le(hash_to_scalar(parts), 32)


def _risk_context_hash(n: int, commitment: Any, bits: List[Any]) -> bytes:
    parts = [_RISK_CTX_DOMAIN, bytes([n & 0xFF]), to_raw_bytes(commitment)]
    parts.extend(to_raw_bytes(b) for b in bits)
    return number_to_bytes_le(hash_to_scalar(parts), 32)


def _prove_bit(ctx: bytes, index: int, b_pt: Any, b: int, s: int) -> Dict[str, str]:
    p0 = b_pt
    p1 = sub(b_pt, G)
    real = 1 if b == 1 else 0
    e_fake = rand_scalar()
    z_fake = rand_scalar()
    p_fake = p0 if real == 1 else p1
    a_fake = sub(mul(H, z_fake), mul(p_fake, e_fake))
    k = rand_scalar()
    a_real = mul(H, k)
    a0 = a_real if real == 0 else a_fake
    a1 = a_real if real == 1 else a_fake
    e = hash_to_scalar([_OR_DOMAIN, ctx, bytes([index & 0xFF]), to_raw_bytes(a0), to_raw_bytes(a1)])
    e_real = scalar_sub(e, e_fake)
    z_real = scalar_add(k, scalar_mul(e_real, s))
    e0, e1 = (e_real, e_fake) if real == 0 else (e_fake, e_real)
    z0, z1 = (z_real, z_fake) if real == 0 else (z_fake, z_real)
    return {"e0": encode_scalar(e0), "e1": encode_scalar(e1), "z0": encode_scalar(z0), "z1": encode_scalar(z1)}


def _verify_bit(ctx: bytes, index: int, b_pt: Any, proof: Any) -> bool:
    e0 = decode_scalar(proof["e0"])
    e1 = decode_scalar(proof["e1"])
    z0 = decode_scalar(proof["z0"])
    z1 = decode_scalar(proof["z1"])
    p0 = b_pt
    p1 = sub(b_pt, G)
    a0 = sub(mul(H, z0), mul(p0, e0))
    a1 = sub(mul(H, z1), mul(p1, e1))
    e = hash_to_scalar([_OR_DOMAIN, ctx, bytes([index & 0xFF]), to_raw_bytes(a0), to_raw_bytes(a1)])
    return scalar_add(e0, e1) == e


def _prove_schnorr(ctx: bytes, d: Any, w: int) -> Dict[str, str]:
    k = rand_scalar()
    a = mul(H, k)
    e = hash_to_scalar([_AGG_DOMAIN, ctx, to_raw_bytes(d), to_raw_bytes(a)])
    z = scalar_add(k, scalar_mul(e, w))
    return {"a": encode_point(a), "z": encode_scalar(z)}


def _verify_schnorr(ctx: bytes, d: Any, proof: Any) -> bool:
    a = decode_point(proof["a"])
    z = decode_scalar(proof["z"])
    e = hash_to_scalar([_AGG_DOMAIN, ctx, to_raw_bytes(d), to_raw_bytes(a)])
    return equals(mul(H, z), add(a, mul(d, e)))


def _range_prove(make_ctx: Callable[[List[Any]], bytes], v_pt: Any, value: int, gamma: int) -> Dict[str, Any]:
    v_masked = value & ((1 << N_BITS) - 1)  # low N_BITS bits, two's complement for a negative slack
    bit_commitments: List[Any] = []
    bit_blindings: List[int] = []
    bits: List[int] = []
    for i in range(N_BITS):
        bit = (v_masked >> i) & 1
        s = rand_scalar()
        bits.append(bit)
        bit_blindings.append(s)
        bit_commitments.append(add(mul(G, bit), mul(H, s)))
    ctx = make_ctx(bit_commitments)
    orp = [_prove_bit(ctx, i, bit_commitments[i], bits[i], bit_blindings[i]) for i in range(N_BITS)]
    s_star = 0
    agg_point = ZERO
    for i in range(N_BITS):
        w = 1 << i
        s_star = scalar_add(s_star, scalar_mul(w, bit_blindings[i]))
        agg_point = add(agg_point, mul(bit_commitments[i], w))
    d = sub(agg_point, v_pt)
    agg = _prove_schnorr(ctx, d, scalar_sub(s_star, gamma))
    return {"bitCommitments": bit_commitments, "or": orp, "agg": agg}


def _range_verify(make_ctx: Callable[[List[Any]], bytes], v_pt: Any, proof: Any) -> bool:
    if not isinstance(proof, dict):
        return False
    n = proof.get("n")
    bit_commitments = proof.get("bitCommitments")
    orp = proof.get("or")
    agg = proof.get("agg")
    if isinstance(n, bool) or not isinstance(n, (int, float)) or n != N_BITS:
        return False
    if not isinstance(bit_commitments, list) or not isinstance(orp, list):
        return False
    if len(bit_commitments) != N_BITS or len(orp) != N_BITS:
        return False
    if not isinstance(agg, dict):
        return False
    b = [decode_point(x) for x in bit_commitments]
    ctx = make_ctx(b)
    for i in range(N_BITS):
        if not _verify_bit(ctx, i, b[i], orp[i]):
            return False
    agg_point = ZERO
    for i in range(N_BITS):
        agg_point = add(agg_point, mul(b[i], 1 << i))
    return _verify_schnorr(ctx, sub(agg_point, v_pt), agg)


def _wire(r: Dict[str, Any]) -> Dict[str, Any]:
    return {"n": N_BITS, "bitCommitments": [encode_point(p) for p in r["bitCommitments"]], "or": r["or"], "agg": r["agg"]}


def prove_budget(risks: Sequence[Any], blindings: Sequence[int], b_max: Any) -> Dict[str, Any]:
    """Prove sum(risk) <= b_max over the committed values. An over-budget input yields a well-formed proof the verifier rejects."""
    require_prover()
    if len(risks) != len(blindings):
        raise AccumulatorError("length_mismatch", "risks and blindings must have equal length")
    ceiling = _effective_ceiling(_as_units(b_max))
    sum_risk = 0
    sum_blind = 0
    for i in range(len(risks)):
        sum_risk += _as_units(risks[i])
        sum_blind = scalar_add(sum_blind, blindings[i])
    c_sum = add(mul(G, mod(sum_risk)), mul(H, sum_blind))
    v_pt = sub(mul(G, mod(ceiling)), c_sum)
    slack = ceiling - sum_risk
    r = _range_prove(lambda bits: _context_hash(N_BITS, ceiling, c_sum, bits), v_pt, slack, mod(-sum_blind))
    return _wire(r)


def verify_budget(commitment_sum: Any, b_max: Any, proof: Any) -> bool:
    """Never raises; malformed input is False. Ceilings above 2^N_BITS - 1 are clamped."""
    try:
        ceiling = _effective_ceiling(_as_units(b_max))
        c_sum = decode_point(commitment_sum)
        v_pt = sub(mul(G, mod(ceiling)), c_sum)
        return _range_verify(lambda bits: _context_hash(N_BITS, ceiling, c_sum, bits), v_pt, proof)
    except Exception:
        return False


def prove_risk_range(risk: Any, blinding: int) -> Dict[str, Any]:
    """Prove that commit_risk(risk, blinding) holds a value in [0, 2^N_BITS)."""
    require_prover()
    v = _as_units(risk)
    b = mod(blinding)
    c = add(mul(G, mod(v)), mul(H, b))
    r = _range_prove(lambda bits: _risk_context_hash(N_BITS, c, bits), c, v, b)
    return _wire(r)


def verify_risk_range(commitment: Any, proof: Any) -> bool:
    try:
        c = decode_point(commitment)
        return _range_verify(lambda bits: _risk_context_hash(N_BITS, c, bits), c, proof)
    except Exception:
        return False


def verify_bounded_budget(commitments: Any, range_proofs: Any, b_max: Any, budget_proof: Any) -> bool:
    """Every commitment carries a valid range proof and the budget proof verifies for their sum. Never raises."""
    try:
        if not isinstance(commitments, list) or not isinstance(range_proofs, list) or len(commitments) != len(range_proofs):
            return False
        for i in range(len(commitments)):
            if not verify_risk_range(commitments[i], range_proofs[i]):
                return False
        return verify_budget(add_commitments(commitments), b_max, budget_proof)
    except Exception:
        return False
