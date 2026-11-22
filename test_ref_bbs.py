"""Replays the TS-reference oracle of BBS (BLS12-381-SHA-256) and the capability-credential layer (test-data/ref-bbs.json.gz).
Needs a built libblst through ctypes (PCA_BLST_LIB or on the loader path). The corpus carries no secret keys: {"$bbssk": n} stands
for KeyGen(32 bytes of n, empty key info), derived here."""
import os
from collections.abc import Sequence

import pytest

from atlas_pca import bbs as B
from atlas_pca import bbs_credential as C
from atlas_pca import bls12
from base_oracle import b64e, load_ref, run

try:
    bls12.lib()
except bls12.Bls12LibraryMissing:
    if os.environ.get("PCA_PAIRING_REQUIRED") == "1":
        raise
    pytest.skip("libblst not available (set PCA_BLST_LIB)", allow_module_level=True)


def _hex(n):
    return "%064x" % n


def _unbbs(v):
    if isinstance(v, dict):
        if len(v) == 1 and "$bbssk" in v:
            return _hex(B.key_gen(bytes([v["$bbssk"]]) * 32))
        return {k: _unbbs(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_unbbs(x) for x in v]
    return v


COUNT, _RAW = load_ref("bbs")


class _Derived(Sequence):
    """The cases of one fn with the {"$bbssk"} keys derived as each case is read (the corpus is decoded lazily, case by case)."""

    def __init__(self, cs):
        self._cs = cs

    def __len__(self):
        return len(self._cs)

    def __getitem__(self, i):
        return [_unbbs(c) for c in self._cs[i]] if isinstance(i, slice) else _unbbs(self._cs[i])

    def __iter__(self):
        return (_unbbs(c) for c in self._cs)


CASES = {fn: _Derived(_RAW[fn]) for fn in _RAW}


def _unhex(s):
    return int(s, 16)


def _ints(xs):
    return [x if x is None else int(x) for x in xs]  # a null index reaches the library, which refuses it


MAP = {
    "hashToScalar": lambda m, dst: _hex(B.hash_to_scalar(m, dst)),
    "mapMessageToScalarAsHash": lambda m: _hex(B.map_message_to_scalar_as_hash(m)),
    "createGenerators": lambda n: [g for g in B.create_generators(int(n))],
    "keyGen": lambda km, ki: _hex(B.key_gen(km, ki)),
    "skToPk": lambda sk: B.sk_to_pk(_unhex(sk)),
    "sign": lambda sk, pk, hd, ms: B.sign(_unhex(sk), pk, hd, ms),
    "verifyDetailed": lambda pk, sig, hd, ms: B.verify_detailed(pk, sig, hd, ms).to_h(),
    "proofGen": lambda pk, sig, hd, ph, ms, idx, rs: B.proof_gen(pk, sig, hd, ph, ms, _ints(idx), [_unhex(x) for x in rs]),
    "proofVerifyDetailed": lambda pk, pr, hd, ph, ms, idx: B.proof_verify_detailed(pk, pr, hd, ph, ms, _ints(idx)).to_h(),
    "capabilityAttributes": C.capability_attributes,
    "issueCapabilityCredential": lambda cap, sk, pk, hd: C.issue_capability_credential(cap, _unhex(sk), pk, hd),
    "verifyCredential": C.verify_credential,
    "verifyPresentation": lambda pres, opts: C.verify_presentation(
        pres, pk=opts.get("pk"), disclosed=opts.get("disclosed"), presentation_header=opts.get("presentationHeader")),
}


def test_corpus_is_covered():
    assert COUNT == 278 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_present_round_trip():
    """The randomized presenter: round trip, context binding, unknown attribute, unlinkability."""
    sk = B.key_gen(bytes(32))
    pk = B.sk_to_pk(sk)
    cap = {"issuer": "i", "holder": "h", "caveats": [{"type": "amount"}]}
    cred = C.issue_capability_credential(cap, sk, pk, None)
    assert C.verify_credential(cred)
    pres = C.present_credential(cred, ["iss"], b"\x01")
    assert C.verify_presentation(pres)
    assert C.verify_presentation(pres, pk=pk, presentation_header=b"\x01")
    assert not C.verify_presentation(pres, presentation_header=b"\x02")
    with pytest.raises(ValueError):
        C.present_credential(cred, ["nope"], None)
    assert pres["proof"] != C.present_credential(cred, ["iss"], b"\x01")["proof"]
