"""SCITT receipts (atlas_pca.scitt, atlas_pca.scitt_log) replayed against vectors generated from the TypeScript reference
(@atlasauth/pca-scitt): the deterministic CBOR codec, the RFC 9162 tree, COSE Signed Statements and Receipts (EdDSA byte-exact,
ES256 by verification outcome), the in-memory and durable transparency services, and the file-backed log store."""
import base64
import hashlib
import os
import tempfile

import pytest

pytest.importorskip("cryptography")  # the dependency-free job has no cryptography; every other job replays this corpus

from atlas_pca import ed25519, scitt as S, scitt_log as L
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("scitt")
_N256_HALF = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 >> 1
_TMP = tempfile.mkdtemp(prefix="scitt-py-")
_n = [0]


def _b(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key(spec, priv):
    """A corpus key spec -> the native key: raw seed / public key bytes (EdDSA) or a `cryptography` P-256 key (ES256)."""
    if spec["alg"] == "EdDSA":
        return _b(spec["seed"] if priv else spec["pub"])
    from cryptography.hazmat.primitives.asymmetric import ec
    if priv:
        return ec.derive_private_key(int.from_bytes(_b(spec["d"]), "big"), ec.SECP256R1())
    return ec.EllipticCurvePublicNumbers(int.from_bytes(_b(spec["x"]), "big"), int.from_bytes(_b(spec["y"]), "big"), ec.SECP256R1()).public_key()


def _from_cj(v):
    if isinstance(v, dict):
        if "$map" in v:
            return {k: _from_cj(x) for k, x in v["$map"]}
        if "$tag" in v:
            return S.CborTag(v["$tag"], _from_cj(v["v"]))
        return v
    if isinstance(v, list):
        return [_from_cj(x) for x in v]
    return v


def _to_cj(v):
    if isinstance(v, S.CborTag):
        return {"$tag": v.tag, "v": _to_cj(v.value)}
    if isinstance(v, dict):
        return {"$map": [[k, _to_cj(x)] for k, x in v.items()]}
    if isinstance(v, list):
        return [_to_cj(x) for x in v]
    return v


def _sign_statement(payload, spec):
    extra = {"subject": spec["subject"]} if "subject" in spec else {}
    return S.sign_statement(payload, spec["alg"], _key(spec["key"], True), spec["issuer"], content_type=spec.get("contentType"), **extra)


def _build_receipt(root, proof, signer):
    extra = {"issuer": signer["issuer"]} if "issuer" in signer else {}
    return S.build_receipt(root, proof, signer["alg"], _key(signer["key"], True), **extra)


def _opts(op, signing=False):
    op = op or {}
    kw = dict(tree_root=op.get("treeRoot"), allow_high_s=op.get("allowHighS", False))
    # a key member that is present is passed (None / empty as is, so it is checked and refused); an absent one is omitted
    for js, py in (("verificationKey", "verification_key"), ("statementKey", "statement_key")):
        if js in op:
            kw[py] = _key(op[js], False) if op[js] else op[js]
    return kw


def _cbor_decode(b):
    try:
        return _to_cj(S.decode(b))
    except ValueError as e:
        if str(e) == "The encoded data was not valid for encoding utf-8":  # the reference's error carries a platform code
            err = ValueError(str(e))
            err.code = "ERR_ENCODING_INVALID_ENCODED_DATA"
            raise err from None
        raise


def _decode_cose(b):
    c = S.decode_cose_sign1(b)
    return {"protectedBytes": c["protectedBytes"], "protectedMap": _to_cj(c["protectedMap"]), "unprotected": _to_cj(c["unprotected"]),
            "payload": c["payload"], "signature": c["signature"]}


def _es256_sign_verify(key, payload, issuer):
    st = S.sign_statement(payload, "ES256", _key(key, True), issuer)
    c = S.decode_cose_sign1(st)
    pub = _key({"alg": "ES256", "x": key["x"], "y": key["y"]}, False)
    return {"check": S.check_statement(st, pub), "payload": S.statement_payload(st),
            "lowS": int.from_bytes(c["signature"][32:], "big") <= _N256_HALF, "protectedBytes": c["protectedBytes"]}


def _es256_receipt(key, n, index, ed_priv, wrong_pub):
    ts = L.TransparencyService("ES256", _key(key, True), "ts")
    sts = [ts.append_and_receipt({"i": i}, "EdDSA", _key(ed_priv, True), "iss")["statement"] for i in range(n)]
    pub = _key({"alg": "ES256", "x": key["x"], "y": key["y"]}, False)
    r = ts.get_receipt(index)
    st = sts[index]
    ed_pub = ed25519.public_key(_key(ed_priv, True))
    return {
        "key": S.verify_receipt(r["receipt"], st, verification_key=pub),
        "root": S.verify_receipt(r["receipt"], st, tree_root=r["root"]),
        "both": S.verify_receipt(r["receipt"], st, tree_root=r["root"], verification_key=pub, statement_key=ed_pub),
        "wrongKey": S.verify_receipt(r["receipt"], st, verification_key=_key(wrong_pub, False)),
        "otherStatement": S.verify_receipt(r["receipt"], sts[(index + 1) % n] if (index + 1) % n < len(sts) else bytes(3), verification_key=pub),
        "none": S.verify_receipt(r["receipt"], st),
    }


class _Faulty:
    """The reference's store fault injection over the in-memory store."""

    def __init__(self, f):
        self.inner, self.f = L.MemoryScittLogStore(), f

    def size(self):
        return -1 if self.f.get("negSize") else self.inner.size()

    def get_entry(self, i):
        return self.inner.get_entry(i)

    def get_node(self, level, i):
        if self.f.get("dropNode") and self.f["dropNode"] == [level, i]:
            return None
        if self.f.get("shortNode") and self.f["shortNode"] == [level, i]:
            return bytes(31)
        return self.inner.get_node(level, i)

    def append(self, n, e, nodes):
        return False if self.f.get("stale") else self.inner.append(n, e, nodes)


def _service(spec):
    key = _key(spec["key"], True)
    alg = spec["key"]["alg"]
    extra = {"issuer": spec["issuer"]} if "issuer" in spec else {}
    if spec["kind"] == "memory":
        svc = L.TransparencyService(alg, key, **extra)
    else:
        svc = L.DurableTransparencyService(_Faulty(spec["storeFault"]) if spec.get("storeFault") else L.MemoryScittLogStore(), alg, key, **extra)
    res = []
    for op in spec["ops"]:
        try:
            k = op["op"]
            if k == "append":
                kw = {"subject": op["subject"]} if "subject" in op else {}
                v = svc.append_and_receipt(op["payload"], "EdDSA", _key(spec["stmtKey"], True), "https://issuer.example",
                                           content_type=op.get("contentType"), **kw)
            elif k == "register":
                v = svc.register(op["statement"])
            elif k == "receipt":
                v = svc.get_receipt(op["i"])
            elif k == "consistency":
                v = svc.consistency_proof(op["m"])
            elif k == "entry":
                v = svc.get_entry(op["i"])
            elif k == "snapshot":
                v = svc.snapshot()
            elif k == "root":
                v = svc.root if spec["kind"] == "memory" else svc.root()
            elif k == "size":
                v = svc.size if spec["kind"] == "memory" else svc.size()
            else:
                raise ValueError("op")
            res.append({"ok": v})
        except Exception as e:  # noqa: BLE001 - the reference reports an error code or true
            res.append({"err": e.code if isinstance(getattr(e, "code", None), str) else True})
    return res


def _path():
    _n[0] += 1
    return os.path.join(_TMP, "f%d.log" % _n[0])


def _file_store_bytes(ops):
    p = _path()
    s = L.FileScittLogStore.open(p)
    try:
        for op in ops:
            nodes = [{"level": n[0], "index": n[1], "hash": _b(n[2])} for n in op["nodes"]]
            try:
                s.append(op["expected"], op["entry"], nodes)
            except Exception:  # noqa: BLE001 - a refused / malformed append writes nothing
                pass
    finally:
        s.close()
    with open(p, "rb") as fh:
        return fh.read()


def _file_store_open(blob):
    p = _path()
    with open(p, "wb") as fh:
        fh.write(blob)
    s = L.FileScittLogStore.open(p)
    try:
        size = s.size()
        out = {"size": size, "entries": [s.get_entry(i) for i in range(size)], "nodes0": [s.get_node(0, i) for i in range(size)]}
    finally:
        s.close()
    with open(p, "rb") as fh:
        out["after"] = fh.read()
    return out


def _check_store(kind):
    if kind == "memory":
        return L.check_scitt_log_store(L.MemoryScittLogStore)
    return L.check_scitt_log_store(lambda: L.FileScittLogStore.open(_path()))


MAP = {
    "cborEncode": lambda v: S.encode(_from_cj(v)),
    "cborDecode": _cbor_decode,
    "emptyRoot": S.empty_root,
    "leafHash": S.leaf_hash,
    "nodeHash": S.node_hash,
    "treeHash": S.tree_hash,
    "inclusionPath": S.inclusion_path,
    "rootFromInclusionPath": S.root_from_inclusion_path,
    "verifyInclusionPath": S.verify_inclusion_path,
    "consistencyPath": S.consistency_path,
    "verifyConsistencyPath": S.verify_consistency_path,
    "siblingSides": S.sibling_sides,
    "encodeInclusionProof": S.encode_inclusion_proof,
    "decodeInclusionProof": S.decode_inclusion_proof,
    "signStatement": _sign_statement,
    "decodeCoseSign1": _decode_cose,
    "checkStatement": lambda st, pub, op=None: S.check_statement(st, _key(pub, False), (op or {}).get("allowHighS", False)),
    "verifyStatement": lambda st, pub, op=None: S.verify_statement(st, _key(pub, False), (op or {}).get("allowHighS", False)),
    "statementPayload": S.statement_payload,
    "statementLeaf": S.statement_leaf,
    "buildReceipt": _build_receipt,
    "verifyReceipt": lambda r, st, op=None: S.verify_receipt(r, st, **_opts(op)),
    "verifyConsistencyProof": S.verify_consistency_proof,
    "constants": lambda: {k: getattr(S, k) for k in (
        "COSE_SIGN1_TAG", "HDR_ALG", "HDR_CONTENT_TYPE", "HDR_CWT_CLAIMS", "CWT_ISS", "CWT_SUB", "HDR_VDS", "HDR_VDS_PROOFS",
        "VDS_RFC9162_SHA256", "PROOF_TYPE_INCLUSION", "DEFAULT_CONTENT_TYPE")},
    "es256SignVerify": _es256_sign_verify,
    "es256Receipt": _es256_receipt,
    "service": _service,
    "fileStoreBytes": _file_store_bytes,
    "fileStoreOpen": _file_store_open,
    "checkScittLogStore": _check_store,
}


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_file_store_reopens_what_it_wrote():
    p = _path()
    s = L.FileScittLogStore.open(p)
    svc = L.DurableTransparencyService(s, "EdDSA", bytes(32))
    for i in range(5):
        svc.append_and_receipt({"i": i}, "EdDSA", bytes([1]) * 32, "iss")
    root = svc.root()
    s.close()
    again = L.DurableTransparencyService(L.FileScittLogStore.open(p), "EdDSA", bytes(32))
    assert again.size() == 5 and again.root() == root


def test_verify_receipt_present_but_empty_key_is_refused():
    """A key that is passed but None / empty is checked (and fails), never skipped; only an omitted key means "no key"."""
    seed = hashlib.sha256(b"scitt-empty-key").digest()
    ts = L.TransparencyService("EdDSA", seed, "ts")
    r0 = ts.append_and_receipt({"i": 0}, "EdDSA", seed, "iss")
    st, rc = r0["statement"], ts.get_receipt(0)
    pub = ed25519.public_key(seed)
    assert S.verify_receipt(rc["receipt"], st, verification_key=pub) is True
    assert S.verify_receipt(rc["receipt"], st, tree_root=rc["root"]) is True
    for bad in (b"", None):
        assert S.verify_receipt(rc["receipt"], st, verification_key=bad) is False, bad
        assert S.verify_receipt(rc["receipt"], st, tree_root=rc["root"], verification_key=bad) is False, bad
        assert S.verify_receipt(rc["receipt"], st, tree_root=rc["root"], statement_key=bad) is False, bad


def test_services_refuse_an_empty_signing_key():
    for bad in (None, b""):
        with pytest.raises(ValueError):
            L.TransparencyService("EdDSA", bad)
        with pytest.raises(ValueError):
            L.DurableTransparencyService(L.MemoryScittLogStore(), "EdDSA", bad)
