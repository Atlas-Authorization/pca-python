"""Replays the TS-reference oracle of FAME CP-ABE on BLS12-381 (test-data/ref-abe.json.gz): scheme arithmetic, decrypt, policies,
capability attributes. Needs libblst built together with the GT shim (PCA_BLST_LIB). The corpus carries no key bytes: master and
user keys are recipes ({"$abeMsk": label}, {"$abeKey": {msk, attrs, id}}, optionally edited by "$patch" / "$edits" or merged by
"$pool"), and the fixed scalars of the scheme cases are {"$seed": label}; every scalar is sha512("abe-oracle/" + label) mod r
(1 for 0), so the keys are re-derived here. The corpus is loaded WITHOUT base_oracle's seed resolution (that one turns a $seed into a
JWK member)."""
import copy
import hashlib
import os

import pytest

from atlas_pca import bls12 as B

try:
    B.gt_lib()
except B.Bls12LibraryMissing as _e:
    if os.environ.get("PCA_PAIRING_REQUIRED") == "1":
        raise
    pytest.skip("libblst with the GT shim is not loadable: %s" % _e, allow_module_level=True)

from atlas_pca import abe as A  # noqa: E402
from atlas_pca import abe_policy as P  # noqa: E402
from atlas_pca import fame as F  # noqa: E402
from base_oracle import HERE, b64e, covered, load, load_gen, merge_cases, require_gen, run  # noqa: E402

R = B.R


def sc(label):
    n = int.from_bytes(hashlib.sha512(("abe-oracle/" + label).encode("utf-8")).digest(), "big") % R
    return 1 if n == 0 else n


def _enc(points):
    return [b64e(p.compress()) for p in points]


_MSKS = {}


def msk_raw(label):
    if label not in _MSKS:
        s = lambda n: sc("%s/%s" % (label, n))  # noqa: E731
        _MSKS[label] = F.setup([s("a1"), s("a2")], [s("b1"), s("b2")], [s("d1"), s("d2"), s("d3")]).msk
    return _MSKS[label]


def seed_msk(label):
    m = msk_raw(label)
    return {"v": 2, "curve": "bls12-381", "a": [b64e(B.i2osp(x, 32)) for x in m.a], "b": [b64e(B.i2osp(x, 32)) for x in m.b], "g": _enc(m.g)}


def seed_key(spec):
    kid = spec["id"]
    names = list(dict.fromkeys(a for a in spec["attrs"] if isinstance(a, str) and a != "" and not P.has_lone_surrogate(a)))
    sigmas = [sc("%s/sg%d" % (kid, i)) for i in range(len(names))]
    key = F.keygen(msk_raw(spec["msk"]), names, [sc(kid + "/r1"), sc(kid + "/r2")], sigmas, sc(kid + "/sgp"))
    return {"v": 2, "curve": "bls12-381", "k0": _enc(key.k0), "kp": _enc(key.kp), "attrs": {n: {"k": _enc(key.attrs[n])} for n in names}}


def _at(v, path):
    for p in path:
        v = v[int(p)] if isinstance(v, list) else v[p]
    return v


def _set(v, path, val, delete):
    if not path:
        return val
    if isinstance(v, dict):
        k = path[0]
        if len(path) == 1 and delete:
            v.pop(k, None)
        else:
            v[k] = _set(v.get(k), path[1:], val, delete)
    elif isinstance(v, list):
        i = int(path[0])
        if i == len(v):
            v.append(None)
        v[i] = None if (len(path) == 1 and delete) else _set(v[i], path[1:], val, delete)
    else:
        raise ValueError("path through a scalar")
    return v


def resolve(v):
    """Replaces every key recipe inside v by the derived key."""
    if isinstance(v, list):
        return [resolve(e) for e in v]
    if not isinstance(v, dict):
        return v
    if isinstance(v.get("$abeMsk"), str):
        return seed_msk(v["$abeMsk"])
    if isinstance(v.get("$abeKey"), dict):
        return seed_key(v["$abeKey"])
    if isinstance(v.get("$pool"), list):
        base = resolve(v["$pool"][0])
        for o in v["$pool"][1:]:
            base["attrs"].update(resolve(o)["attrs"])
        return base
    if "$patch" in v:
        base = resolve(v["$patch"])
        edits = v["$edits"]
        vals = []
        for e in edits:  # a $ref reads the base as it was before any edit
            val = e["value"]
            vals.append(copy.deepcopy(_at(base, val["$ref"])) if isinstance(val, dict) and isinstance(val.get("$ref"), list) else val)
        for e, val in zip(edits, vals):
            base = _set(base, e["path"], val, isinstance(val, dict) and "$undefined" in val)
        return base
    return {k: resolve(e) for k, e in v.items()}


_COUNT, _RAW = load("abe", os.path.join(HERE, "test-data", "ref-abe.json.gz"), unseed=False)
_GEN = load_gen("abe", unseed=False)
CASES = {fn: [dict(c, args=resolve(c["args"])) for c in cs] for fn, cs in merge_cases(_RAW, _GEN).items()}


def fame(policy, attrs, scalars):
    n = P.normalize(policy)
    if not n["ok"]:
        raise ValueError(n["reason"])
    if "$seed" in scalars:  # a corpus that kept the label instead of the scalars
        label = scalars["$seed"]
        s = lambda x: sc(label + x)  # noqa: E731
        sc_ = {"a": [s("a1"), s("a2")], "b": [s("b1"), s("b2")], "d": [s("d1"), s("d2"), s("d3")], "r": [s("r1"), s("r2")],
               "s": [s("s1"), s("s2")], "sigma": [s("sg%d" % i) for i in range(len(attrs))], "sigmaPrime": s("sgp")}
    else:  # the generator's scalars, as hex
        sc_ = {k: ([int(h, 16) for h in v] if isinstance(v, list) else int(v, 16)) for k, v in scalars.items()}
    master = F.setup(sc_["a"], sc_["b"], sc_["d"])
    key = F.keygen(master.msk, attrs, sc_["r"], sc_["sigma"], sc_["sigmaPrime"])
    e = F.encrypt(master.mpk, n["tree"], sc_["s"])
    dec = F.decrypt(key, n["tree"], e.ct)
    w = lambda pts: [p.compress() for p in pts]  # noqa: E731
    return {"h": w([master.mpk.h1, master.mpk.h2]), "t": [master.mpk.t1, master.mpk.t2], "mskg": w(master.msk.g),
            "k0": w(key.k0), "kp": w(key.kp), "key": {a: w(c) for a, c in key.attrs.items()}, "ct0": w(e.ct.ct0),
            "rows": [w(r) for r in e.ct.rows], "k": e.k, "dec": dec}


MAP = {
    "fame": fame,
    "gtIsElement": lambda b: B.Gt.is_element(b),
    "gtPow": lambda b, s: B.Gt.pow(b, int(s, 16)),
    "gtMul": lambda a, b: B.Gt.mul(a, b),
    "pairingProduct": lambda g1s, g2s: B.Gt.pairing_product([B.G1.decode(b) for b in g1s], [B.G2.decode(b) for b in g2s]),
    "normalizePolicy": lambda p: P.normalize(p),
    "satisfies": lambda tree, attrs: P.satisfies(tree, attrs),
    "policyAttributes": lambda tree: P.policy_attributes(tree),
    "parseCiphertext": lambda x: A.parse_ciphertext(x),
    "decrypt": lambda k, c: A.decrypt(k, c),
    "decryptText": lambda k, c: A.decrypt_text(k, c),
    "decryptWithCapability": lambda k, c: A.decrypt_with_capability(k, c),
    "encryptAccepts": lambda mpk, policy: A.encrypt_for_policy(mpk, policy, b"x") is not None,
    "keygenForAttributes": lambda msk, attrs: list(A.keygen_for_attributes(msk, attrs)["attrs"].keys()),
    "keygenForCapability": lambda msk, cap, extra, opts: _kfc(msk, cap, extra, opts),
    "capabilityAttributes": lambda cap, opts: P.js_sort(A.capability_attributes(cap, opts)),
}


def _kfc(msk, cap, extra, opts):
    k = A.keygen_for_capability(msk, cap, extra, opts)
    return {"holder": k.get("holder"), "attrs": list(k["attrs"].keys())}


def test_corpus_is_covered():
    assert covered(CASES, _GEN, MAP)


def test_secret_corpus_present():
    if _GEN is None:
        require_gen("abe")


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    if fn not in CASES:
        require_gen("abe")
    ran, _skipped = run(CASES[fn], MAP[fn])
    assert ran > 0


def test_round_trip_and_collusion():
    m = A.setup()
    policy = {"allOf": [{"attr": "a"}, {"attr": "b"}]}
    ct = A.encrypt_for_policy(m["mpk"], policy, b"hello")
    both = A.keygen_for_attributes(m["msk"], ["a", "b"])
    one_a = A.keygen_for_attributes(m["msk"], ["a"])
    one_b = A.keygen_for_attributes(m["msk"], ["b"])
    assert A.decrypt(both, ct) == b"hello"
    assert A.decrypt(one_a, ct) is None
    other = A.setup()
    assert A.decrypt(A.keygen_for_attributes(other["msk"], ["a", "b"]), ct) is None
    colluding = dict(one_a, attrs={**one_a["attrs"], **one_b["attrs"]})
    assert A.decrypt(colluding, ct) is None
    last = ct["ct"][-1]
    tampered = dict(ct, ct=ct["ct"][:-1] + ("B" if last == "A" else "A"))
    assert A.decrypt(both, tampered) is None


@pytest.mark.parametrize("text", [
    b'{"a":1,"a":2}',                 # duplicate key (JSON.parse keeps the last; the strict parser refuses)
    b'{"a":"\\ud800"}',               # lone surrogate
    b'{"a":NaN}', b'{"a":1e2}', b'{"a":-0}',  # not strict-profile numbers
    b'{"a":"\xff"}',                  # invalid UTF-8
])
def test_decrypt_with_capability_refuses_non_strict_payloads(text):
    m = A.setup()
    ct = A.encrypt_for_policy(m["mpk"], {"attr": "a"}, text)
    r = A.decrypt_with_capability(A.keygen_for_attributes(m["msk"], ["a"]), ct)
    assert r["ok"] is False
    good = A.encrypt_tool_payload(m["mpk"], {"attr": "a"}, {"x": [1, "y"]})
    assert A.decrypt_with_capability(A.keygen_for_attributes(m["msk"], ["a"]), good) == {"ok": True, "payload": {"x": [1, "y"]}}
