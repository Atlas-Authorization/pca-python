"""Word-array kernels for the OT-extension hot path: AES-128-CTR column PRG, 32x32 bit transposes, GF(2^128) on four little-endian u32 words
(a list of unsigned ints), and the batched tweakable correlation-robust hash H(x, t) = pi(pi(x) ^ t) ^ pi(x) with a fixed-key AES-128 truncated
to 64 bits. AES comes from the ``cryptography`` package (mpc_libcrypto)."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import List, Optional

from .mpc_libcrypto import aes128_ctr_zeros, aes128_ecb

COLS = 128  # bit columns of the IKNP matrix (kappa)
M32 = 0xFFFFFFFF
TAG_PRG_KEY = b"atlas-pca-mpc/ot-prg-aes"
TAG_CRH_KEY = b"atlas-pca-mpc/ot-crh-aes-fixed-key"
TAG_TWEAK_DOMAIN = b"atlas-pca-mpc/ot-crh-tweak-domain/v2"
_CRH_KEY: Optional[bytes] = None


@dataclass
class OtTweak:
    """Tweak of a hash call: channel-global row offset plus the 2-word session domain."""

    offset: int
    domain: List[int]


class Otx:
    COLS = COLS
    M32 = M32
    OtTweak = OtTweak

    @staticmethod
    def big_to_bytes(v: int, n: int) -> bytes:
        """Little-endian bytes of a bigint, exactly n bytes (the low bytes; a negative value reads as two's complement)."""
        return (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")

    @staticmethod
    def bytes_to_big(b: bytes) -> int:
        return int.from_bytes(bytes(b), "little")

    @staticmethod
    def le_words(b: bytes, off: int, n: int) -> List[int]:
        s = bytes(b)[off:off + 4 * n]
        k = len(s) // 4
        return list(struct.unpack("<%dI" % k, s[:4 * k]))

    @staticmethod
    def le_bytes(w, n: int) -> bytes:
        ws = list(w[:n])
        return struct.pack("<%dI" % len(ws), *ws)

    @staticmethod
    def words_from_le_bytes(b: bytes, nwords: int) -> List[int]:
        return Otx.le_words(b, 0, nwords)

    @staticmethod
    def prg_key(seed: bytes) -> bytes:
        return hashlib.sha256(TAG_PRG_KEY + bytes(seed)).digest()[:16]

    @staticmethod
    def prg_column(seed: bytes, start_block: int, nwords: int) -> List[int]:
        """nwords u32 words of the PRG stream of seed from AES block start_block (high tail bits unmasked)."""
        iv = struct.pack(">QQ", 0, start_block & ((1 << 64) - 1))
        return Otx.le_words(aes128_ctr_zeros(Otx.prg_key(seed), iv, nwords * 4), 0, nwords)

    @staticmethod
    def mask_tail(col: list, nbits: int) -> list:
        """Clears the bits at positions >= nbits in a little-endian word column (in place)."""
        full = nbits >> 5
        rem = nbits & 31
        if rem != 0:
            col[full] &= (1 << rem) - 1
        for i in range(full + 1 if rem != 0 else full, len(col)):
            col[i] = 0
        return col

    @staticmethod
    def transpose32(a: list, off: int = 0) -> list:
        """In-place transpose of a 32x32 bit matrix held as 32 u32 words from off."""
        m = 0x0000FFFF
        j = 16
        while j != 0:
            k = 0
            while k < 32:
                t = (((a[off + k] >> j) ^ a[off + k + j]) & m) & M32
                a[off + k] = (a[off + k] ^ ((t << j) & M32)) & M32
                a[off + k + j] = (a[off + k + j] ^ t) & M32
                k = (k + j + 1) & ~j
            j >>= 1
            m = (m ^ (m << j)) & M32
        return a

    @staticmethod
    def transpose_cols(cols, w: int, rows: int) -> List[int]:
        """Transposes COLS bit-columns (each w words, concatenated) into rows rows of four words."""
        out = [0] * (rows * 4)
        blocks = (rows + 31) >> 5
        for rb in range(blocks):
            for cb in range(4):
                tmp = [cols[((cb * 32) + c) * w + rb] for c in range(32)]
                Otx.transpose32(tmp, 0)
                lim = min(32, rows - (rb * 32))
                for r in range(lim):
                    out[((rb * 32) + r) * 4 + cb] = tmp[r]
        return out

    @staticmethod
    def gf_xor_into(acc: list, v, vo: int = 0) -> list:
        """acc ^= the four-word element at v[vo..]."""
        for i in range(4):
            acc[i] ^= v[vo + i]
        return acc

    @staticmethod
    def gf_mul_x(acc: list) -> list:
        """acc *= x in GF(2^128) (x^128 = x^7 + x^2 + x + 1)."""
        carry = acc[3] >> 31
        acc[3] = ((acc[3] << 1) | (acc[2] >> 31)) & M32
        acc[2] = ((acc[2] << 1) | (acc[1] >> 31)) & M32
        acc[1] = ((acc[1] << 1) | (acc[0] >> 31)) & M32
        acc[0] = ((acc[0] << 1) ^ (0x87 if carry != 0 else 0)) & M32
        return acc

    @staticmethod
    def accum_column(col, off: int, n: int, chi, acc: list) -> list:
        """XORs into acc chi[j] (four words) for every set bit j of the word column col[off, n]."""
        for w in range(n):
            x = col[off + w]
            base = w << 5
            while x != 0:
                low = x & -x
                o = (base + low.bit_length() - 1) << 2
                acc[0] ^= chi[o]
                acc[1] ^= chi[o + 1]
                acc[2] ^= chi[o + 2]
                acc[3] ^= chi[o + 3]
                x ^= low
        return acc

    @staticmethod
    def kos_combine(cols, w: int, chi) -> List[int]:
        """sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the columns: the KOS combination of both roles."""
        acc = [0, 0, 0, 0]
        for i in range(COLS - 1, -1, -1):
            Otx.gf_mul_x(acc)
            part = [0, 0, 0, 0]
            Otx.accum_column(cols, i * w, w, chi, part)
            Otx.gf_xor_into(acc, part, 0)
        return acc

    @staticmethod
    def gf_from_big(v: int) -> List[int]:
        return [(v >> (32 * i)) & M32 for i in range(4)]

    @staticmethod
    def gf_to_big(w, off: int = 0) -> int:
        v = 0
        for i in (3, 2, 1, 0):
            v = (v << 32) | w[off + i]
        return v

    @staticmethod
    def crh_key() -> bytes:
        global _CRH_KEY
        if _CRH_KEY is None:
            _CRH_KEY = hashlib.sha256(TAG_CRH_KEY).digest()[:16]
        return _CRH_KEY

    @staticmethod
    def aes_ecb(buf: bytes) -> bytes:
        return aes128_ecb(Otx.crh_key(), buf)

    @staticmethod
    def ot_tweak_domain(binding: bytes) -> List[int]:
        """The 64-bit session domain of a channel: SHA-256(tag, binding)[0..8] as two little-endian words."""
        return Otx.le_words(hashlib.sha256(TAG_TWEAK_DOMAIN + bytes(binding)).digest(), 0, 2)

    @staticmethod
    def tmmo_crh(rows, n: int, tweak: Optional[OtTweak] = None) -> List[int]:
        """H(tweak, row_j) for n rows of four words: two u32 words per row (the low 64 bits of the TMMO hash)."""
        offset = 0 if tweak is None else tweak.offset
        dom = [0, 0] if tweak is None else tweak.domain
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > (1 << 53) - 1:
            raise ValueError("tmmoCrh: tweak offset must be a non-negative safe integer")
        if len(dom) != 2:
            raise ValueError("tmmoCrh: tweak domain must be 2 words")
        aw = Otx.le_words(Otx.aes_ecb(Otx.le_bytes(rows, n * 4)), 0, n * 4)
        b = [0] * (n * 4)
        for j in range(n):
            o = j * 4
            v = offset + j
            b[o] = aw[o] ^ (v & M32)
            b[o + 1] = aw[o + 1] ^ ((v >> 32) & M32)
            b[o + 2] = aw[o + 2] ^ dom[0]
            b[o + 3] = aw[o + 3] ^ dom[1]
        cw = Otx.le_words(Otx.aes_ecb(Otx.le_bytes(b, n * 4)), 0, n * 4)
        out = [0] * (n * 2)
        for j in range(n):
            out[2 * j] = cw[4 * j] ^ aw[4 * j]
            out[2 * j + 1] = cw[4 * j + 1] ^ aw[4 * j + 1]
        return out

    @staticmethod
    def word64(h, j: int) -> int:
        """The 64-bit value of the two words at index j of a tmmo_crh output."""
        return (h[(2 * j) + 1] << 32) | h[2 * j]
