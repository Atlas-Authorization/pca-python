"""FAME (Agrawal and Chase, ACM CCS 2017, ePrint 2017/807): ciphertext-policy ABE in the type-3 pairing setting, the group
arithmetic only (the wire format, validation and AEAD are in atlas_pca.abe). G1/G2 work is blst through ctypes, GT work is blst
through the GT shim (bls12.Gt). Same equations, hashing and span program as the TypeScript reference:

  Setup     MPK = (h^a1, h^a2, e(g,h)^(d1 a1 + d3), e(g,h)^(d2 a2 + d3)),  MSK = (a1, a2, b1, b2, g^d1, g^d2, g^d3)
  KeyGen    pow = (b1 r1, b2 r2, r1 + r2), K0 = h^pow,
            K_y,t = (H(y,0,t)^pow0 H(y,1,t)^pow1 H(y,2,t)^pow2 g^sigma_y)^(1/a_(t+1)), K_y,2 = g^-sigma_y,
            K'_t = (H0(0,0,t)^pow0 H0(0,1,t)^pow1 H0(0,2,t)^pow2 g^sigma')^(1/a_(t+1)) g^d_(t+1), K'_2 = g^-sigma' g^d3
  Encrypt   C0 = (h1^s1, h2^s2, h^(s1+s2)),
            C_i,l = H(rho(i),l,0)^s1 H(rho(i),l,1)^s2 prod_j (H0(j,l,0)^s1 H0(j,l,1)^s2)^M[i][j],  K = T1^s1 T2^s2
  Decrypt   K = prod_l e(keyProd_l, C0_l) / e(ctProd_l, K0_l) with the tree's Lagrange reconstruction weights

The span program is a Shamir sharing down the threshold tree (each t-of-n gate adds t-1 columns; child i gets its parent's row
plus i^k in the gate's k-th new column). rho must be injective: a policy naming one attribute twice is refused by the caller.
"""
from __future__ import annotations

import struct
from typing import Callable, Dict, List, NamedTuple, Optional, Sequence

from . import abe_policy as P
from . import bls12 as B
from .pca import utf8

# domain-separation tag of the attribute / column random oracles (RFC 9380 SSWU_RO into G1)
ATTR_DST = b"ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1"
R = B.R


class Mpk(NamedTuple):
    h1: B.G2
    h2: B.G2
    t1: bytes
    t2: bytes


class Msk(NamedTuple):
    a: list
    b: list
    g: list


class Key(NamedTuple):
    k0: list
    kp: list
    attrs: Dict[str, list]  # name -> [G1, G1, G1]


class Ciphertext(NamedTuple):
    ct0: list
    rows: list


class Master(NamedTuple):
    mpk: Mpk
    msk: Msk


class Encapsulation(NamedTuple):
    ct: Ciphertext
    k: bytes


class Row(NamedTuple):
    attr: str
    vec: Dict[int, int]


class Plan(NamedTuple):
    row: int
    xs: Optional[list]
    subs: Optional[list]


_gens: dict = {}


def g1() -> B.G1:
    if "g1" not in _gens:
        _gens["g1"] = B.G1.generator()
    return _gens["g1"]


def g2() -> B.G2:
    if "g2" not in _gens:
        _gens["g2"] = B.G2.generator()
    return _gens["g2"]


def mul(p, k: int):
    """k*P for k non-zero mod r; a zero scalar raises (the reference refuses it)."""
    if k % R == 0:
        raise ZeroDivisionError("scalar is zero")
    return p * k


# ---- random oracles ----

def hash_to_g1(msg: bytes) -> B.G1:
    return B.G1.hash_to(msg, ATTR_DST)


def h_attr(attr: str, l: int, t: int) -> B.G1:
    """H(y, l, t): kind byte 1, length-prefixed UTF-8 attribute, l, t."""
    a = utf8(attr)
    return hash_to_g1(struct.pack(">BI", 1, len(a)) + a + struct.pack(">BB", l, t))


def h_col(j: int, l: int, t: int) -> B.G1:
    """H0(j, l, t): the column-indexed oracle (kind byte 2)."""
    return hash_to_g1(struct.pack(">BIBB", 2, j, l, t))


# ---- setup / keygen ----

def setup(a: Sequence[int], b: Sequence[int], d: Sequence[int]) -> Master:
    egh = B.Gt.pairing(g1(), g2())
    mpk = Mpk(mul(g2(), a[0]), mul(g2(), a[1]),
              B.Gt.pow(egh, B.add(B.mul(d[0], a[0]), d[2])), B.Gt.pow(egh, B.add(B.mul(d[1], a[1]), d[2])))
    return Master(mpk, Msk(list(a), list(b), [mul(g1(), d[0]), mul(g1(), d[1]), mul(g1(), d[2])]))


def _key_term(pow_: list, sigma: int, a_inv: int, oracle: Callable[[int], B.G1]) -> B.G1:
    s = oracle(0) * pow_[0] + oracle(1) * pow_[1] + oracle(2) * pow_[2] + mul(g1(), sigma)
    return mul(s, a_inv)


def keygen(msk: Msk, attrs: Sequence[str], r: Sequence[int], sigmas: Sequence[int], sigma_prime: int) -> Key:
    pow_ = [B.mul(msk.b[0], r[0]), B.mul(msk.b[1], r[1]), B.add(r[0], r[1])]
    a_inv = [B.inv(msk.a[0]), B.inv(msk.a[1])]
    k0 = [mul(g2(), pow_[0]), mul(g2(), pow_[1]), mul(g2(), pow_[2])]
    out: Dict[str, list] = {}
    for i, y in enumerate(attrs):
        if i >= len(sigmas):
            raise ValueError("fameKeygen: one sigma per attribute is required")
        sg = sigmas[i]
        out[y] = [_key_term(pow_, sg, a_inv[0], lambda l, y=y: h_attr(y, l, 0)),
                  _key_term(pow_, sg, a_inv[1], lambda l, y=y: h_attr(y, l, 1)),
                  mul(g1(), B.sub(0, sg))]
    kp = [_key_term(pow_, sigma_prime, a_inv[0], lambda l: h_col(0, l, 0)) + msk.g[0],
          _key_term(pow_, sigma_prime, a_inv[1], lambda l: h_col(0, l, 1)) + msk.g[1],
          mul(g1(), B.sub(0, sigma_prime)) + msk.g[2]]
    return Key(k0, kp, out)


# ---- span program ----

def build_rows(tree: dict) -> List[Row]:
    """Leaves in depth-first order, each with its sparse span-program row (column 0 is the secret column, always 1)."""
    rows: List[Row] = []
    _walk_rows(tree, {0: 1}, rows, [1])
    return rows


def _walk_rows(node: dict, vec: dict, rows: list, ncols: list) -> None:
    if P.is_leaf(node):
        rows.append(Row(node["attr"], vec))
        return
    t = P.t(node)
    base = ncols[0]
    ncols[0] += t - 1
    for idx, child in enumerate(P.of(node)):
        cv = dict(vec)
        x = idx + 1
        pw = 1
        for k in range(1, t):
            pw = B.mul(pw, x)
            cv[base + k - 1] = pw
        _walk_rows(child, cv, rows, ncols)


def leaf_count(tree: dict) -> int:
    return 1 if P.is_leaf(tree) else sum(leaf_count(c) for c in P.of(tree))


def first_repeated_attribute(tree: dict) -> Optional[str]:
    """First attribute named by two leaves, or None (FAME needs an injective row labelling)."""
    seen = set()
    for a in P.leaves(tree):
        if a in seen:
            return a
        seen.add(a)
    return None


# ---- encrypt ----

def encrypt(mpk: Mpk, tree: dict, s: Sequence[int]) -> Encapsulation:
    rows = build_rows(tree)
    col_memo: dict = {}
    out = []
    for row in rows:
        comps = []
        for l in range(3):
            acc = mul(h_attr(row.attr, l, 0), s[0]) + mul(h_attr(row.attr, l, 1), s[1])
            for j, w in row.vec.items():
                col = col_memo.get((j, l))
                if col is None:
                    col = col_memo[(j, l)] = mul(h_col(j, l, 0), s[0]) + mul(h_col(j, l, 1), s[1])
                acc = acc + col * w
            comps.append(acc)
        out.append(comps)
    ct = Ciphertext([mul(mpk.h1, s[0]), mul(mpk.h2, s[1]), mul(g2(), B.add(s[0], s[1]))], out)
    return Encapsulation(ct, B.Gt.mul(B.Gt.pow(mpk.t1, s[0]), B.Gt.pow(mpk.t2, s[1])))


# ---- decrypt ----

def _plan(node: dict, has: Callable[[str], bool], offset: int) -> Optional[Plan]:
    """Bottom-up, the first t satisfiable children of every gate; None when the subtree is not satisfied."""
    if P.is_leaf(node):
        return Plan(offset, None, None) if has(node["attr"]) else None
    t = P.t(node)
    xs: list = []
    subs: list = []
    off = offset
    for i, child in enumerate(P.of(node)):
        sub = _plan(child, has, off)
        if sub is not None:
            xs.append(i + 1)
            subs.append(sub)
        if len(subs) >= t:
            break
        off += leaf_count(child)
    return None if len(subs) < t else Plan(-1, xs, subs)


def _weights(p: Plan, w: int, out: dict) -> bool:
    if p.subs is None:
        out[p.row] = w
        return True
    lam = lagrange_at_zero(p.xs)
    if lam is None:
        return False
    return all(_weights(sub, B.mul(w, lam[i]), out) for i, sub in enumerate(p.subs))


def lagrange_at_zero(xs: Sequence[int]) -> Optional[List[int]]:
    """Lagrange coefficients L_i(0) over Z_r; None on an empty set, a zero point, or coinciding points."""
    if not xs:
        return None
    seen = set()
    for x in xs:
        xr = x % R
        if xr == 0 or xr in seen:
            return None
        seen.add(xr)
    out = []
    for i in range(len(xs)):
        num = 1
        den = 1
        for j in range(len(xs)):
            if j == i:
                continue
            num = B.mul(num, xs[j])
            den = B.mul(den, B.sub(xs[j], xs[i]))
        out.append(B.mul(num, B.inv(den)))
    return out


def reconstruction_weights(tree: dict, has: Callable[[str], bool]) -> Optional[Dict[int, int]]:
    """Row index -> reconstruction weight over the rows the key can use; None when the attribute set does not satisfy the tree."""
    p = _plan(tree, has, 0)
    if p is None:
        return None
    out: Dict[int, int] = {}
    return out if _weights(p, 1, out) else None


def decrypt(key: Key, tree: dict, ct: Ciphertext) -> Optional[bytes]:
    """The KEM key (a GT element), or None when the key does not satisfy the tree (or a pairing input is the identity)."""
    rows = P.leaves(tree)
    if len(rows) != len(ct.rows):
        return None
    w = reconstruction_weights(tree, lambda a: a in key.attrs)
    if w is None:
        return None
    g1s: list = []
    g2s: list = []
    for l in range(3):
        ct_prod = B.G1()
        key_prod = key.kp[l]
        for row, wt in w.items():
            comp = key.attrs.get(rows[row])
            c_row = ct.rows[row] if row < len(ct.rows) else None
            if comp is None or c_row is None:
                return None
            ct_prod = ct_prod + c_row[l] * wt
            key_prod = key_prod + comp[l] * wt
        g1s += [key_prod, -ct_prod]
        g2s += [ct.ct0[l], key.k0[l]]
    try:
        return B.Gt.pairing_product(g1s, g2s)
    except ValueError:
        return None
