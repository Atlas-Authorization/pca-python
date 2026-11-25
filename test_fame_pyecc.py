"""FAME group elements against an independent implementation (py_ecc): setup, keygen and encrypt with fixed scalars, byte for byte.
Needs libblst built together with the GT shim (PCA_BLST_LIB)."""
import json
import os

import pytest

from atlas_pca import bls12 as B

try:
    B.gt_lib()
except B.Bls12LibraryMissing as _e:
    if os.environ.get("PCA_PAIRING_REQUIRED") == "1":
        raise
    pytest.skip("libblst with the GT shim is not loadable: %s" % _e, allow_module_level=True)

from atlas_pca import abe_policy as P  # noqa: E402
from atlas_pca import fame as F  # noqa: E402

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-data", "fame-pyecc", "fame-pyecc.json")


def _hex(points):
    return [p.compress().hex() for p in points]


def _scalars(lst):
    return [int(s, 16) for s in lst]


def test_matches_pyecc():
    with open(FILE, encoding="utf-8") as fh:
        cases = json.load(fh)["cases"]
    assert cases
    for c in cases:
        name = c["name"]
        n = P.normalize(c["policy"])
        assert n["ok"], name
        s = c["scalars"]
        ms = F.setup(_scalars(s["a"]), _scalars(s["b"]), _scalars(s["d"]))
        key = F.keygen(ms.msk, c["attrs"], _scalars(s["r"]), _scalars(s["sigma"]), int(s["sigmaPrime"], 16))
        e = F.encrypt(ms.mpk, n["tree"], _scalars(s["s"]))
        assert c["h"] == _hex([ms.mpk.h1, ms.mpk.h2]), name + " h"
        assert c["mskg"] == _hex(ms.msk.g), name + " mskg"
        assert c["k0"] == _hex(key.k0), name + " k0"
        assert c["kp"] == _hex(key.kp), name + " kp"
        for attr, want in c["key"].items():
            assert want == _hex(key.attrs[attr]), "%s key %s" % (name, attr)
        assert c["ct0"] == _hex(e.ct.ct0), name + " ct0"
        assert c["rows"] == [_hex(r) for r in e.ct.rows], name + " rows"
        # the reference decrypted these with the attribute set it was issued; so must the native
        if P.satisfies(n["tree"], c["attrs"]):
            assert F.decrypt(key, n["tree"], e.ct) == e.k, name + " decrypt"
