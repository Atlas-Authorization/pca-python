"""BBS signatures over BLS12-381, ciphersuite BLS12-381-SHA-256 (BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_), faithful to
draft-irtf-cfrg-bbs-signatures (core protocol and octet encodings). Signatures and generators live in G1 (48 bytes compressed),
public keys in G2 (96 bytes), scalars are 32 bytes big-endian. All curve work is blst's (through ctypes, see atlas_pca.bls12); the
scalar field is int arithmetic. Byte inputs are bytes, scalars are ints."""
from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import bls12 as B
from .bls12 import G1, G2, R

MAX_MESSAGES = 1024  # a verifier derives the message count from attacker-supplied lengths
CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
API_ID = CIPHERSUITE_ID + "H2G_HM2S_"
SCALAR_LEN = 32
POINT_LEN = 48
EXPAND_LEN = 48
H2S_DST = API_ID + "H2S_"
MAP_DST = API_ID + "MAP_MSG_TO_SCALAR_AS_HASH_"
SEED_DST = API_ID + "SIG_GENERATOR_SEED_"
GEN_DST = API_ID + "SIG_GENERATOR_DST_"
GEN_SEED = API_ID + "MESSAGE_GENERATOR_SEED"
KEYGEN_DST = API_ID + "KEYGEN_DST_"
# P1: the fixed G1 generator of the ciphersuite (draft 7.2.2)
P1_HEX = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9"

MALFORMED_SIGNATURE = "malformed-signature"
MALFORMED_PUBLIC_KEY = "malformed-public-key"
MALFORMED_PROOF = "malformed-proof"
DISCLOSED_LENGTH_MISMATCH = "disclosed-length-mismatch"
INVALID_DISCLOSED_INDEXES = "invalid-disclosed-indexes"
PAIRING_MISMATCH = "pairing-mismatch"
CHALLENGE_MISMATCH = "challenge-mismatch"


class Result:
    """A verification result: ok, or the stable machine-readable reason."""

    __slots__ = ("ok", "reason")

    def __init__(self, ok: bool, reason: Optional[str] = None):
        self.ok, self.reason = ok, reason

    def to_h(self) -> Dict[str, Any]:
        return {"ok": True} if self.ok else {"ok": False, "reason": self.reason}


OK = Result(True)


class ParsedSignature:
    def __init__(self, a: G1, e: int):
        self.a, self.e = a, e


class ParsedProof:
    def __init__(self, abar, bbar, d, e_hat, r1_hat, r3_hat, m_hat, c):
        self.abar, self.bbar, self.d, self.e_hat, self.r1_hat, self.r3_hat, self.m_hat, self.c = (
            abar, bbar, d, e_hat, r1_hat, r3_hat, m_hat, c)


_p1: Optional[G1] = None
_bp2: Optional[G2] = None


def p1_gen() -> G1:
    global _p1
    if _p1 is None:
        _p1 = G1.decode(bytes.fromhex(P1_HEX))
    return _p1


def bp2() -> G2:
    global _bp2
    if _bp2 is None:
        _bp2 = G2.generator()
    return _bp2


def _bytes_arg(v: Any, what: str) -> bytes:
    if not isinstance(v, (bytes, bytearray)):
        raise ValueError("bbs: %s must be bytes" % what)
    return bytes(v)


def hash_to_scalar(msg: bytes, dst) -> int:
    """hash_to_scalar(msg, dst) = OS2IP(expand_message_xmd(msg, dst, 48)) mod r (draft 4.2.2)."""
    return B.os2ip(B.expand_message_xmd(_bytes_arg(msg, "message"), dst, EXPAND_LEN)) % R


def map_message_to_scalar_as_hash(message: bytes) -> int:
    """MapMessageToScalarAsHash: one message octet string to one scalar (draft 4.2)."""
    return hash_to_scalar(message, MAP_DST)


def messages_to_scalars(messages: Sequence[bytes]) -> List[int]:
    return [map_message_to_scalar_as_hash(m) for m in messages]


def _gens(count: int) -> List[G1]:
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("bbs: generator count must be a non-negative integer")
    if count > MAX_MESSAGES + 1:
        raise ValueError("bbs: at most %d messages are supported" % MAX_MESSAGES)
    v = B.expand_message_xmd(GEN_SEED.encode(), SEED_DST, EXPAND_LEN)
    out = []
    for i in range(1, count + 1):
        v = B.expand_message_xmd(v + B.i2osp(i, 8), SEED_DST, EXPAND_LEN)
        out.append(G1.hash_to(v, GEN_DST))
    return out


def create_generators(count: int) -> List[bytes]:
    """create_generators(count): the compressed generator sequence (Q_1, H_1, ..., H_{count-1}) (draft 4.1)."""
    return [g.compress() for g in _gens(count)]


# ---- key generation ----

def key_gen(key_material: bytes, key_info: bytes = b"") -> int:
    """KeyGen (draft 3.4.1): at least 32 octets of key material. Never returns 0."""
    km = _bytes_arg(key_material, "key material")
    ki = _bytes_arg(key_info, "key info")
    if len(km) < 32:
        raise ValueError("bbs: key material must be at least 32 octets")
    if len(ki) > 65535:
        raise ValueError("bbs: key info must be at most 65535 octets")
    sk = hash_to_scalar(km + B.i2osp(len(ki), 2) + ki, KEYGEN_DST)
    if sk == 0:
        raise RuntimeError("bbs: derived SK is zero (retry with different key material)")
    return sk


def sk_to_pk(sk: int) -> bytes:
    """SkToPk: the 96-byte public key SK * BP2 (draft 3.4.2)."""
    return (bp2() * sk).compress()


def generate_key_pair() -> Dict[str, Any]:
    """A fresh {sk, pk} from the system CSPRNG; refuses an all-zero entropy source."""
    ikm = secrets.token_bytes(32)
    if not any(ikm):
        raise RuntimeError("bbs: entropy source returned all zeros (RNG failure); refusing to generate a key")
    sk = key_gen(ikm)
    return {"sk": sk, "pk": sk_to_pk(sk)}


def sk_to_bytes(sk: int) -> bytes:
    return B.i2osp(sk, SCALAR_LEN)


def sk_from_bytes(data: bytes) -> int:
    if not isinstance(data, (bytes, bytearray)) or len(data) != SCALAR_LEN:
        raise ValueError("bbs: SK must be 32 octets")
    sk = B.os2ip(data)
    if sk == 0 or sk >= R:
        raise ValueError("bbs: SK out of range")
    return sk


# ---- serialization (draft 4.2.4): points compressed, ("s", n) scalars 32 octets, ("i", n) integers 8 octets ----

def _serialize(els: Sequence[Any]) -> bytes:
    out = []
    for el in els:
        if isinstance(el, B.Point):
            out.append(el.compress())
        elif isinstance(el, tuple):
            out.append(B.i2osp(el[1], SCALAR_LEN if el[0] == "s" else 8))
        else:
            raise ValueError("bbs: cannot serialize")
    return b"".join(out)


# ---- signature octets ----

def signature_to_octets(a: G1, e: int) -> bytes:
    return a.compress() + B.i2osp(e, SCALAR_LEN)


def octets_to_signature(sig: bytes) -> ParsedSignature:
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != POINT_LEN + SCALAR_LEN:
        raise ValueError("bbs: signature must be 80 octets")
    s = bytes(sig)
    a = G1.decode(s[:POINT_LEN])
    if a.is_inf():
        raise ValueError("bbs: signature point A is the identity")
    e = B.os2ip(s[POINT_LEN:])
    if e <= 0 or e >= R:
        raise ValueError("bbs: signature scalar e out of range")
    return ParsedSignature(a, e)


# ---- domain (draft 4.2.3) ----

def _calculate_domain(pk: bytes, q1: G1, h: List[G1], header: bytes) -> int:
    dom_octs = _serialize([("i", len(h)), q1, *h]) + API_ID.encode()
    return hash_to_scalar(pk + dom_octs + B.i2osp(len(header), 8) + header, H2S_DST)


def _compute_b(q1: G1, h: List[G1], domain: int, scalars: Sequence[int]) -> G1:
    """B = P1 + Q_1*domain + sum H_i*msg_i."""
    b = p1_gen() + (q1 * domain)
    for i, m in enumerate(scalars):
        b = b + (h[i] * m)
    return b


# ---- Sign / Verify ----

def sign(sk: int, pk: bytes, header: bytes, messages: Sequence[bytes]) -> bytes:
    """Sign(SK, PK, header, messages): an 80-octet BBS signature over the ordered message vector."""
    if isinstance(sk, bool) or not isinstance(sk, int) or sk <= 0 or sk >= R:
        raise ValueError("bbs: SK out of range")
    pk = _bytes_arg(pk, "public key")
    header = _bytes_arg(header, "header")
    ms = messages_to_scalars(messages)
    g = _gens(len(ms) + 1)
    q1, h = g[0], g[1:]
    domain = _calculate_domain(pk, q1, h, header)
    e = hash_to_scalar(_serialize([("s", sk), *[("s", m) for m in ms], ("s", domain)]), H2S_DST)
    b = _compute_b(q1, h, domain, ms)
    return signature_to_octets(b * B.inv(sk + e), e)


def _decode_pk(pk: Any) -> Optional[G2]:
    """A decoded public key: strict G2, not the identity; None when malformed."""
    try:
        w = G2.decode(pk)
    except ValueError:
        return None
    return None if w.is_inf() else w


def verify_detailed(pk: bytes, signature: bytes, header: bytes, messages: Sequence[bytes]) -> Result:
    """Verify(PK, signature, header, messages) with a rejection reason; fails closed on any malformed input."""
    try:
        parsed = octets_to_signature(signature)
    except ValueError:
        return Result(False, MALFORMED_SIGNATURE)
    w = _decode_pk(pk)
    if w is None:
        return Result(False, MALFORMED_PUBLIC_KEY)
    if len(messages) > MAX_MESSAGES:
        return Result(False, DISCLOSED_LENGTH_MISMATCH)
    pk = bytes(pk)
    header = _bytes_arg(header, "header")
    ms = messages_to_scalars(messages)
    g = _gens(len(ms) + 1)
    q1, h = g[0], g[1:]
    domain = _calculate_domain(pk, q1, h, header)
    b = _compute_b(q1, h, domain, ms)
    # e(A, W + BP2*e) == e(B, BP2)
    return OK if B.pairing_eq(parsed.a, w + (bp2() * parsed.e), b, bp2()) else Result(False, PAIRING_MISMATCH)


def verify(pk: bytes, signature: bytes, header: bytes, messages: Sequence[bytes]) -> bool:
    return verify_detailed(pk, signature, header, messages).ok


# ---- challenge (draft 3.7.4) ----

def _calculate_challenge(abar, bbar, d, t1, t2, idx, msgs, domain, ph) -> int:
    els: List[Any] = [("i", len(idx))]
    for k, ix in enumerate(idx):
        els += [("i", ix), ("s", msgs[k])]
    els += [abar, bbar, d, t1, t2, ("s", domain)]
    return hash_to_scalar(_serialize(els) + B.i2osp(len(ph), 8) + ph, H2S_DST)


# ---- proof octets ----

def _proof_to_octets(p: ParsedProof) -> bytes:
    return b"".join([p.abar.compress(), p.bbar.compress(), p.d.compress(), B.i2osp(p.e_hat, SCALAR_LEN),
                     B.i2osp(p.r1_hat, SCALAR_LEN), B.i2osp(p.r3_hat, SCALAR_LEN),
                     *[B.i2osp(m, SCALAR_LEN) for m in p.m_hat], B.i2osp(p.c, SCALAR_LEN)])


def _read_scalar(proof: bytes, offset: int) -> int:
    v = B.os2ip(proof[offset:offset + SCALAR_LEN])
    if v >= R:
        raise ValueError("bbs: proof scalar out of range")
    return v


def octets_to_proof(proof: bytes) -> ParsedProof:
    if not isinstance(proof, (bytes, bytearray)):
        raise ValueError("bbs: malformed proof")
    pr = bytes(proof)
    fixed = 3 * POINT_LEN + 4 * SCALAR_LEN
    if len(pr) < fixed or (len(pr) - fixed) % SCALAR_LEN != 0:
        raise ValueError("bbs: malformed proof length")
    abar = G1.decode(pr[:POINT_LEN])
    bbar = G1.decode(pr[POINT_LEN:2 * POINT_LEN])
    d = G1.decode(pr[2 * POINT_LEN:3 * POINT_LEN])
    o = 3 * POINT_LEN
    e_hat = _read_scalar(pr, o)
    r1_hat = _read_scalar(pr, o + SCALAR_LEN)
    r3_hat = _read_scalar(pr, o + 2 * SCALAR_LEN)
    o += 3 * SCALAR_LEN
    u = (len(pr) - fixed) // SCALAR_LEN
    m_hat = [_read_scalar(pr, o + i * SCALAR_LEN) for i in range(u)]
    c = _read_scalar(pr, o + u * SCALAR_LEN)
    if abar.is_inf() or bbar.is_inf() or d.is_inf():
        raise ValueError("bbs: proof contains the identity point")
    return ParsedProof(abar, bbar, d, e_hat, r1_hat, r3_hat, m_hat, c)


# ---- index-set helpers ----

def _validate_indexes(indexes: Sequence[int], l: int) -> None:
    seen = set()
    for i in indexes:
        if isinstance(i, bool) or not isinstance(i, int) or i < 0 or i >= l:
            raise ValueError("bbs: disclosed index %r out of range [0, %d)" % (i, l))
        if i in seen:
            raise ValueError("bbs: duplicate disclosed index %d" % i)
        seen.add(i)


def _undisclosed_ascending(disclosed: Sequence[int], l: int) -> List[int]:
    ds = set(disclosed)
    return [i for i in range(l) if i not in ds]


# ---- ProofGen ----

def proof_gen(pk: bytes, signature: bytes, header: bytes, ph: bytes, messages: Sequence[bytes],
              disclosed_indexes: Sequence[int], fixed_random_scalars: Optional[Sequence[int]] = None) -> bytes:
    """ProofGen(PK, signature, header, ph, messages, disclosed_indexes): a zero-knowledge proof of knowledge of the signature that
    discloses the messages at the given indexes. fixed_random_scalars (5 + undisclosed count scalars) pins the randomness for test
    vectors ONLY; reusing it across proofs breaks zero-knowledge and unlinkability."""
    pk = _bytes_arg(pk, "public key")
    header = _bytes_arg(header, "header")
    ph = _bytes_arg(ph, "presentation header")
    sig = octets_to_signature(signature)
    a, e = sig.a, sig.e
    ms = messages_to_scalars(messages)
    l = len(ms)
    _validate_indexes(disclosed_indexes, l)
    disclosed = sorted(set(disclosed_indexes))
    undisclosed = _undisclosed_ascending(disclosed, l)
    u = len(undisclosed)

    g = _gens(l + 1)
    q1, h = g[0], g[1:]
    domain = _calculate_domain(pk, q1, h, header)
    b = _compute_b(q1, h, domain, ms)

    rs = list(fixed_random_scalars) if fixed_random_scalars is not None else [
        B.os2ip(secrets.token_bytes(EXPAND_LEN)) % R for _ in range(5 + u)]
    if len(rs) != 5 + u:
        raise ValueError("bbs: expected %d random scalars, got %d" % (5 + u, len(rs)))
    if rs[0] == 0 or rs[1] == 0:
        raise ValueError("bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)")

    r1, r2, e_tilde, r1_tilde, r3_tilde = rs[:5]
    m_tilde = rs[5:]

    d = b * r2
    abar = a * B.mul(r1, r2)
    bbar = (d * r1) - (abar * e)
    t1 = (abar * e_tilde) + (d * r1_tilde)
    t2 = d * r3_tilde
    for k, ix in enumerate(undisclosed):
        t2 = t2 + (h[ix] * m_tilde[k])

    c = _calculate_challenge(abar, bbar, d, t1, t2, disclosed, [ms[i] for i in disclosed], domain, ph)

    r3 = B.inv(r2)
    e_hat = B.add(e_tilde, B.mul(e, c))
    r1_hat = B.sub(r1_tilde, B.mul(r1, c))
    r3_hat = B.sub(r3_tilde, B.mul(r3, c))
    m_hat = [B.add(m_tilde[k], B.mul(ms[ix], c)) for k, ix in enumerate(undisclosed)]
    return _proof_to_octets(ParsedProof(abar, bbar, d, e_hat, r1_hat, r3_hat, m_hat, c))


# ---- ProofVerify ----

def proof_verify_detailed(pk: bytes, proof: bytes, header: bytes, ph: bytes, disclosed_messages: Sequence[bytes],
                          disclosed_indexes: Sequence[int]) -> Result:
    """ProofVerify with a rejection reason. disclosed_messages[k] corresponds to disclosed_indexes[k]."""
    try:
        p = octets_to_proof(proof)
    except ValueError:
        return Result(False, MALFORMED_PROOF)
    w = _decode_pk(pk)
    if w is None:
        return Result(False, MALFORMED_PUBLIC_KEY)
    if len(disclosed_messages) != len(disclosed_indexes):
        return Result(False, DISCLOSED_LENGTH_MISMATCH)
    pk = bytes(pk)
    header = _bytes_arg(header, "header")
    ph = _bytes_arg(ph, "presentation header")
    u = len(p.m_hat)
    l = len(disclosed_indexes) + u
    if l > MAX_MESSAGES:
        return Result(False, MALFORMED_PROOF)
    try:
        _validate_indexes(disclosed_indexes, l)
        scalars = messages_to_scalars(disclosed_messages)
    except ValueError:
        return Result(False, INVALID_DISCLOSED_INDEXES)
    order = sorted(((ix, k) for k, ix in enumerate(disclosed_indexes)))
    undisclosed = _undisclosed_ascending(disclosed_indexes, l)

    g = _gens(l + 1)
    q1, h = g[0], g[1:]
    domain = _calculate_domain(pk, q1, h, header)

    t1 = (p.bbar * p.c) + (p.abar * p.e_hat) + (p.d * p.r1_hat)
    bv = p1_gen() + (q1 * domain)
    sorted_idx: List[int] = []
    sorted_msgs: List[int] = []
    for ix, k in order:
        sorted_idx.append(ix)
        sorted_msgs.append(scalars[k])
        bv = bv + (h[ix] * scalars[k])
    t2 = (bv * p.c) + (p.d * p.r3_hat)
    for k, ix in enumerate(undisclosed):
        t2 = t2 + (h[ix] * p.m_hat[k])

    cv = _calculate_challenge(p.abar, p.bbar, p.d, t1, t2, sorted_idx, sorted_msgs, domain, ph)
    if cv != p.c:
        return Result(False, CHALLENGE_MISMATCH)
    return OK if B.pairing_eq(p.abar, w, p.bbar, bp2()) else Result(False, PAIRING_MISMATCH)


def proof_verify(pk: bytes, proof: bytes, header: bytes, ph: bytes, disclosed_messages: Sequence[bytes],
                 disclosed_indexes: Sequence[int]) -> bool:
    return proof_verify_detailed(pk, proof, header, ph, disclosed_messages, disclosed_indexes).ok
