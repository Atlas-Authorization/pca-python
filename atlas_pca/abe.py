"""Proof-carrying encryption: ciphertext-policy ABE (FAME, see atlas_pca.fame) with the payload sealed under AES-256-GCM, the
whole header authenticated. Keys, ciphertexts and the master keys are dicts with the TypeScript reference's member names, so
material crosses languages unchanged. Every parser is fail closed: decrypt returns None on any deviation and never raises (except
Bls12LibraryMissing: no library).

Needs libblst built with the GT shim (see atlas_pca.bls12) and the `cryptography` package (AES-GCM, HKDF).
"""
from __future__ import annotations

import secrets
from typing import Any, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import abe_policy as P
from . import bls12 as B
from . import fame as F
from .pca import b64u as _b64u
from .pca import canonical_bytes_strict, canonicalize, decode_b64u_strict, strict_parse, utf8

ABE_ALG = "fame-cpabe-bls12381-type3/aes-256-gcm"
CEK_INFO = b"atlas-pca-abe/cek/v3"
SALT_LEN = 16
R = B.R


class PcaEncryptionError(ValueError):
    """An invalid policy, master public key or master secret key."""


# ---- wire helpers ----

def b64u(b: bytes) -> str:
    return _b64u(bytes(b))


def unb64u(o: Any) -> Optional[bytes]:
    """Canonical unpadded base64url only; None otherwise (an empty string is b'', not None)."""
    return decode_b64u_strict(o)


def _obj(o: Any) -> Optional[dict]:
    return o if isinstance(o, dict) else None


def _two(o: Any) -> bool:
    return not isinstance(o, bool) and isinstance(o, (int, float)) and o == 2


def _read_pt(cls, x: Any):
    b = unb64u(x)
    if b is None:
        return None
    try:
        p = cls.decode(b)
    except ValueError:
        return None
    return None if p.is_inf() else p


def _read_g1(x: Any):
    return _read_pt(B.G1, x)


def _read_g2(x: Any):
    return _read_pt(B.G2, x)


def _read_gt(x: Any) -> Optional[bytes]:
    b = unb64u(x)
    return b if b is not None and B.Gt.is_element(b) else None


def _tri(x: Any, read) -> Optional[list]:
    if not isinstance(x, list) or len(x) != 3:
        return None
    out = [read(e) for e in x]
    return None if any(e is None for e in out) else out


def _tri1(x: Any):
    return _tri(x, _read_g1)


def _tri2(x: Any):
    return _tri(x, _read_g2)


def _enc(points) -> List[str]:
    return [b64u(p.compress()) for p in points]


# ---- scalars ----

def random_scalar() -> int:
    while True:
        v = B.os2ip(secrets.token_bytes(64)) % R
        if v != 0:
            return v


def _scalar_b64(s: int) -> str:
    return b64u(B.i2osp(s, 32))


def _canonical_scalar(enc: Any) -> Optional[int]:
    """Exactly one encoding per scalar: 32 bytes, non-zero, and below r."""
    b = unb64u(enc)
    if b is None or len(b) != 32:
        return None
    x = B.os2ip(b)
    return None if x == 0 or x >= R else x


# ---- setup / keygen ----

def setup() -> dict:
    """A fresh master key pair: {'mpk': ..., 'msk': ...}."""
    a = [random_scalar(), random_scalar()]
    b = [random_scalar(), random_scalar()]
    d = [random_scalar(), random_scalar(), random_scalar()]
    m = F.setup(a, b, d)
    msk = {"v": 2, "curve": "bls12-381", "a": [_scalar_b64(x) for x in a], "b": [_scalar_b64(x) for x in b], "g": _enc(m.msk.g)}
    mpk = {"v": 2, "curve": "bls12-381", "h": _enc([m.mpk.h1, m.mpk.h2]), "t": [b64u(m.mpk.t1), b64u(m.mpk.t2)]}
    return {"mpk": mpk, "msk": msk}


def _scalar_pair(x: Any) -> Optional[list]:
    if not isinstance(x, list) or len(x) != 2:
        return None
    out = [_canonical_scalar(e) for e in x]
    return None if any(e is None for e in out) else out


def _parse_msk(o: Any) -> F.Msk:
    m = _obj(o)
    if m is None or not _two(m.get("v")):
        raise PcaEncryptionError("invalid master secret key")
    a, b, g = _scalar_pair(m.get("a")), _scalar_pair(m.get("b")), _tri1(m.get("g"))
    if a is None or b is None or g is None:
        raise PcaEncryptionError("invalid master secret key")
    return F.Msk(a, b, g)


def _parse_mpk(o: Any) -> F.Mpk:
    m = _obj(o)
    if m and _two(m.get("v")) and isinstance(m.get("h"), list) and len(m["h"]) == 2 and isinstance(m.get("t"), list) and len(m["t"]) == 2:
        h1, h2 = _read_g2(m["h"][0]), _read_g2(m["h"][1])
        t1, t2 = _read_gt(m["t"][0]), _read_gt(m["t"][1])
        if h1 is not None and h2 is not None and t1 is not None and t2 is not None:
            return F.Mpk(h1, h2, t1, t2)
    raise PcaEncryptionError("invalid master public key")


def keygen_for_attributes(msk: Any, attrs: list) -> dict:
    """Issue a decryption key for an explicit set of attribute tokens (empty or ill-formed names are dropped)."""
    m = _parse_msk(msk)
    names = list(dict.fromkeys(a for a in attrs if isinstance(a, str) and a != "" and not P.has_lone_surrogate(a)))
    sigmas = [random_scalar() for _ in names]
    key = F.keygen(m, names, [random_scalar(), random_scalar()], sigmas, random_scalar())
    return {"v": 2, "curve": "bls12-381", "k0": _enc(key.k0), "kp": _enc(key.kp),
            "attrs": {n: {"k": _enc(key.attrs[n])} for n in names}}


def keygen_for_capability(msk: Any, capability: dict, extra: Optional[list] = None, opts: Optional[dict] = None) -> dict:
    """Issue a key bound to a capability: its capability_attributes plus the extra tokens; the holder is recorded."""
    attrs = capability_attributes(capability, opts)
    attrs += [a for a in (extra or []) if isinstance(a, str) and a != ""]
    key = keygen_for_attributes(msk, attrs)
    if isinstance(capability.get("holder"), str):
        key["holder"] = capability["holder"]
    return key


def parse_key(o: Any) -> Optional[F.Key]:
    """An untrusted key; a malformed attribute component counts as not held. None if K0, K' or the container is malformed."""
    k = _obj(o)
    if k is None or not _two(k.get("v")) or _obj(k.get("attrs")) is None:
        return None
    k0, kp = _tri2(k.get("k0")), _tri1(k.get("kp"))
    if k0 is None or kp is None:
        return None
    attrs = {}
    for name, comp in k["attrs"].items():
        t = _tri1(comp.get("k")) if isinstance(comp, dict) else None
        if t is not None:
            attrs[name] = t
    return F.Key(k0, kp, attrs)


# ---- KDF / AEAD ----

def _kdf32(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 (RFC 5869), 32 bytes: the content-encryption key from the KEM key."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt if salt else None, info=info).derive(ikm)


def _seal(key: bytes, pt: bytes, aad: bytes):
    iv = secrets.token_bytes(12)
    sealed = AESGCM(key).encrypt(iv, pt, aad)
    return iv, sealed[:-16], sealed[-16:]


def _open_gcm(key: bytes, iv: bytes, ct: bytes, tag: bytes, aad: bytes) -> Optional[bytes]:
    if len(key) != 32 or len(iv) != 12 or len(tag) != 16:
        return None
    try:
        return AESGCM(key).decrypt(iv, ct + tag, aad)
    except InvalidTag:
        return None


def _aad(c: dict) -> bytes:
    """The authenticated header as canonical JSON; raises TypeError outside the canonical profile."""
    return canonical_bytes_strict({k: c.get(k) for k in ("v", "alg", "salt", "ct0", "tree", "rows")})


# ---- encrypt ----

def encrypt_for_policy(mpk: Any, policy: Any, plaintext) -> dict:
    """Encrypt so that only a key whose attributes satisfy policy opens it. Raises PcaEncryptionError on a bad policy or key."""
    norm = P.normalize(policy)
    if not norm["ok"]:
        raise PcaEncryptionError("invalid policy: %s" % norm["reason"])
    tree = norm["tree"]
    dup = F.first_repeated_attribute(tree)
    if dup is not None:
        raise PcaEncryptionError("invalid policy: attribute %s is named by more than one leaf (single-use attributes only)" % canonicalize(dup))
    pk = _parse_mpk(mpk)
    if isinstance(plaintext, str):
        plaintext = utf8(plaintext)
    salt = secrets.token_bytes(SALT_LEN)
    e = F.encrypt(pk, tree, [random_scalar(), random_scalar()])
    header = {"v": 2, "alg": ABE_ALG, "salt": b64u(salt), "ct0": _enc(e.ct.ct0), "tree": tree, "rows": [_enc(r) for r in e.ct.rows]}
    try:
        header_aad = _aad(header)
    except (TypeError, ValueError):
        raise PcaEncryptionError("policy cannot be authenticated (header outside the canonical JSON profile)") from None
    iv, ct, tag = _seal(_kdf32(e.k, salt, CEK_INFO), bytes(plaintext), header_aad)
    return {**header, "iv": b64u(iv), "ct": b64u(ct), "tag": b64u(tag)}


def encrypt_tool_payload(mpk: Any, policy: Any, payload: Any) -> dict:
    """Encrypt a JSON value (the payload layer of decrypt_with_capability)."""
    return encrypt_for_policy(mpk, policy, canonical_bytes_strict(payload))


# ---- parse ----

def _parse_tree(x: Any, gates: int, budget: list) -> Optional[dict]:
    m = _obj(x)
    budget[0] += 1
    if budget[0] > P.MAX_POLICY_NODES or m is None:
        return None
    kind = m.get("kind")
    if kind == "leaf":
        a = m.get("attr")
        if not isinstance(a, str) or a == "" or P.has_lone_surrogate(a) or len(m) != 2:
            return None
        return P.leaf(a)
    if kind == "gate":
        if gates + 1 > P.MAX_POLICY_DEPTH or len(m) != 3:
            return None
        t, of = m.get("t"), m.get("of")
        if not P.pos_int(t) or not isinstance(of, list) or not of:
            return None
        if P.num(t) > len(of) or len(of) >= P.MAX_POLICY_NODES:
            return None
        kids = []
        for b in of:
            sub = _parse_tree(b, gates + 1, budget)
            if sub is None:
                return None
            kids.append(sub)
        return P.gate(int(P.num(t)), kids)
    return None


def _str_tri(x: Any) -> Optional[list]:
    if not isinstance(x, list) or len(x) != 3 or any(unb64u(e) is None for e in x):
        return None
    return list(x)


def parse_ciphertext(o: Any) -> Optional[dict]:
    """Validate an untrusted value as a ciphertext; None (fail closed) on any deviation."""
    x = _obj(o)
    if x is None or not _two(x.get("v")) or x.get("alg") != ABE_ALG:
        return None
    if any(unb64u(x.get(k)) is None for k in ("salt", "iv", "ct", "tag")):
        return None
    ct0 = _str_tri(x.get("ct0"))
    tree = _parse_tree(x.get("tree"), 0, [0])
    if ct0 is None or tree is None or not isinstance(x.get("rows"), list):
        return None
    if len(x["rows"]) != F.leaf_count(tree) or F.first_repeated_attribute(tree) is not None:
        return None
    rows = [_str_tri(r) for r in x["rows"]]
    if any(r is None for r in rows):
        return None
    return {"v": 2, "alg": ABE_ALG, "salt": x["salt"], "ct0": ct0, "tree": tree, "rows": rows, "iv": x["iv"], "ct": x["ct"], "tag": x["tag"]}


# ---- decrypt ----

def decrypt(key: Any, ciphertext: Any) -> Optional[bytes]:
    """The plaintext iff the key's attributes satisfy the ciphertext's policy and the AEAD authenticates; otherwise None. Never raises."""
    try:
        ct = parse_ciphertext(ciphertext)
        if ct is None:
            return None
        pk = parse_key(key)
        if pk is None:
            return None
        salt, iv, body, tag = (unb64u(ct[k]) for k in ("salt", "iv", "ct", "tag"))
        ct0 = _tri2(ct["ct0"])
        rows = [_tri1(r) for r in ct["rows"]]
        if any(r is None for r in rows) or ct0 is None or salt is None or iv is None or body is None or tag is None:
            return None
        k = F.decrypt(pk, ct["tree"], F.Ciphertext(ct0, rows))
        if k is None:
            return None
        try:
            header_aad = _aad(ct)
        except (TypeError, ValueError):
            return None
        return _open_gcm(_kdf32(k, salt, CEK_INFO), iv, body, tag, header_aad)
    except (ValueError, TypeError, ArithmeticError, RecursionError):
        return None


def decrypt_text(key: Any, ciphertext: Any) -> Optional[str]:
    pt = decrypt(key, ciphertext)
    return None if pt is None else pt.decode("utf-8", "replace")


def decrypt_with_capability(key: Any, ciphertext: Any) -> dict:
    """{'ok': True, 'payload': ...} or {'ok': False, 'reason': ...}."""
    pt = decrypt(key, ciphertext)
    if pt is None:
        return {"ok": False, "reason": "capability does not satisfy the policy, or ciphertext is invalid"}
    try:
        # the strict wire parser (the core verifier's): refuses duplicate keys, lone surrogates, invalid UTF-8, non-JSON numbers
        return {"ok": True, "payload": strict_parse(pt)}
    except (ValueError, RecursionError):
        return {"ok": False, "reason": "decrypted payload is not valid JSON"}


# ---- capability attributes ----

def act(verb: str, resource: str) -> str:
    return "act:" + canonicalize([verb, resource])


def _verbs_of(v: Any) -> list:
    if isinstance(v, str):
        return [v]
    return [e for e in v if isinstance(e, str)] if isinstance(v, list) else []


def capability_attributes(cap: Any, opts: Optional[dict] = None) -> List[str]:
    """The canonical attribute set a capability possesses: holder, scope, and (from the ROOT only, never from a delegated hop's
    own caveats) act/verb/resource tokens. A delegated capability gets scope/act/verb/resource tokens only with a verified chain
    (root first, ending in the capability); a chain that fails verification yields none (fail closed). opts: 'chain',
    'principal', 'pqPins'. Returns the unique tokens in the reference's insertion order (holder, scopes, act, verb, resource);
    sort with abe_policy.js_sort for the canonical listing."""
    out: List[str] = []
    if not isinstance(cap, dict):
        return out
    opts = opts or {}
    scope_source = env_source = None
    if "chain" in opts:
        from .pca import verify_chain

        chain = opts["chain"]
        if not isinstance(chain, list) or not chain:
            return out
        root, last = _obj(chain[0]), _obj(chain[-1])
        if root is None or last is None or last.get("id") != cap.get("id"):
            return out
        principal = root.get("issuer") if opts.get("principal") is None else opts["principal"]
        pins = _obj(opts.get("pqPins"))
        ok, _reason = verify_chain(chain, principal if isinstance(principal, str) else None, None, pins, None)
        if not ok:
            return out
        scope_source, env_source = root.get("caveats"), root
    elif "parent" not in cap:
        scope_source, env_source = cap.get("caveats"), cap
    if isinstance(cap.get("holder"), str) and cap["holder"] != "":
        out.append("holder:" + cap["holder"])
    if isinstance(scope_source, list):
        for cv in scope_source:
            if not isinstance(cv, dict):
                continue
            if cv.get("type") == "scope" and isinstance(cv.get("value"), str):
                out.append("scope:" + cv["value"])
            if cv.get("type") == "scopes" and isinstance(cv.get("values"), list):
                out += ["scope:" + s for s in cv["values"] if isinstance(s, str)]
    from .authorize import read_envelope

    env = None if env_source is None else read_envelope(env_source)
    if env and isinstance(env.get("predicates"), list):
        # an array counts, and names no verb or resource
        preds = [p if isinstance(p, dict) else {} for p in env["predicates"] if isinstance(p, (dict, list))]
        for p in preds:
            if isinstance(p.get("resource"), str):
                out += [act(v, p["resource"]) for v in _verbs_of(p.get("verb"))]
        if len(preds) == 1:
            p = preds[0]
            out += ["verb:" + v for v in _verbs_of(p.get("verb"))]
            if isinstance(p.get("resource"), str):
                out.append("resource:" + p["resource"])
    return list(dict.fromkeys(out))
