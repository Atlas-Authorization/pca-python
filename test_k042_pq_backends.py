"""Kill tests for atlas_pca.pq_backends with fake ctypes libraries and patched backends: lengths, dispatch, discovery order,
ctypes binding signatures, probing, the OpenSSL verify call sequence and resource release, the LESS library check. Runs
without any PQ backend (the CI runners have none): every ctypes object is a recording fake."""
import ctypes
import os
import types

import pytest

from atlas_pca import pq_backends as pq

VP, SZ, CP = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p


class Fn:
    def __init__(self, handler=None):
        self.handler = handler
        self.calls = []
        self.restype = "unset"
        self.argtypes = "unset"

    def __call__(self, *a):
        self.calls.append(a)
        if self.handler is None:
            return 0
        return self.handler(*a)


class FakeLib:
    def __init__(self, **handlers):
        self._h = handlers
        self._f = {}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in self._f:
            self._f[name] = Fn(self._h.get(name))
        return self._f[name]


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    monkeypatch.setattr(pq, "_lib", None)
    monkeypatch.setattr(pq, "_tried", False)
    monkeypatch.setattr(pq, "_probed", {})
    monkeypatch.setattr(pq, "_less", None)
    monkeypatch.setattr(pq, "_less_tried", False)
    monkeypatch.delenv("ATLAS_PCA_LIBCRYPTO", raising=False)
    monkeypatch.delenv("ATLAS_PCA_LIBLESS", raising=False)


# ---- lengths ------------------------------------------------------------------------------------------------------------

def test_tables():
    assert pq.KEY_TYPES == {"ML-DSA-65": (1952, 3309), "ML-DSA-87": (2592, 4627), "SLH-DSA-SHA2-128f": (32, 17088),
                            "SLH-DSA-SHA2-256s": (64, 29792), "LESS-cat1": (97484, 1329)}
    assert pq.LESS_SIGNATURE_MIN_BYTES == 1153 and pq.LESS_SIGNATURE_STEP_BYTES == 16


@pytest.mark.parametrize("kt", ["ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-256s"])
def test_sig_len_fixed(kt):
    n = pq.KEY_TYPES[kt][1]
    assert pq.sig_len_ok(kt, n) is True
    assert pq.sig_len_ok(kt, n - 1) is False and pq.sig_len_ok(kt, n + 1) is False and pq.sig_len_ok(kt, 0) is False
    assert pq.sig_len_ok(kt, n - 16) is False and pq.sig_len_ok(kt, n + 16) is False


def test_sig_len_less():
    ok = {1153 + 16 * i for i in range(12)}
    assert max(ok) == 1329
    for n in range(1100, 1400):
        assert pq.sig_len_ok("LESS-cat1", n) is (n in ok), n
    assert pq.sig_len_ok("LESS-cat1", 1329) is True and pq.sig_len_ok("LESS-cat1", 1153) is True
    assert pq.sig_len_ok("LESS-cat1", 1137) is False and pq.sig_len_ok("LESS-cat1", 1345) is False


def test_sig_len_unknown_type():
    assert pq.sig_len_ok("nope", 3309) is False and pq.sig_len_ok("", 0) is False


# ---- discovery -------------------------------------------------------------------------------------------------------------

def test_candidates_order(monkeypatch):
    seen = []

    def fake_glob(pat):
        seen.append(pat)
        return ["/z/" + pat[-6:], "/a/" + pat[-6:]] if pat.endswith("*.dylib") else []

    monkeypatch.setattr(pq.glob, "glob", fake_glob)
    monkeypatch.setattr(pq.ctypes.util, "find_library", lambda n: "libcrypto-found" if n == "crypto" else None)
    monkeypatch.setenv("ATLAS_PCA_LIBCRYPTO", os.pathsep.join(["/env/one", "", "/env/two"]))
    got = pq._candidates()
    assert got[:2] == ["/env/one", "/env/two"]
    assert got[-1] == "libcrypto-found"
    assert seen == ["/opt/homebrew/opt/openssl@3/lib/libcrypto*.dylib", "/opt/homebrew/lib/libcrypto*.dylib",
                    "/usr/local/opt/openssl@3/lib/libcrypto*.dylib", "/usr/lib/libcrypto.so.3",
                    "/usr/lib/x86_64-linux-gnu/libcrypto.so.3", "/usr/lib/aarch64-linux-gnu/libcrypto.so.3",
                    "/lib/x86_64-linux-gnu/libcrypto.so.3"]
    # each glob's matches are sorted
    dy = [p for p in got if p.endswith(".dylib")]
    assert dy == sorted(dy[:2]) + sorted(dy[2:4]) + sorted(dy[4:6])


def test_candidates_no_env_no_find(monkeypatch):
    monkeypatch.setattr(pq.glob, "glob", lambda p: [])
    monkeypatch.setattr(pq.ctypes.util, "find_library", lambda n: None)
    assert pq._candidates() == []
    monkeypatch.setenv("ATLAS_PCA_LIBCRYPTO", "")
    assert pq._candidates() == []


def test_less_candidates(monkeypatch):
    monkeypatch.setattr(pq.ctypes.util, "find_library", lambda n: "atlas_less-found" if n == "atlas_less" else None)
    monkeypatch.setenv("ATLAS_PCA_LIBLESS", os.pathsep.join(["/x/a", "", "/x/b"]))
    got = pq._less_candidates()
    assert got[:2] == ["/x/a", "/x/b"] and got[-1] == "atlas_less-found" and len(got) == 6
    base = os.path.join(os.path.dirname(os.path.abspath(pq.__file__)), "..", "..", "pca-less-c", "build")
    assert got[2:5] == [os.path.join(base, n) for n in ("libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll")]
    monkeypatch.delenv("ATLAS_PCA_LIBLESS")
    monkeypatch.setattr(pq.ctypes.util, "find_library", lambda n: None)
    assert len(pq._less_candidates()) == 3


# ---- binding / probing ---------------------------------------------------------------------------------------------------------

def test_bind_signatures(monkeypatch):
    lib = FakeLib()
    opened = []
    monkeypatch.setattr(pq.ctypes, "CDLL", lambda p: opened.append(p) or lib)
    assert pq._bind("/some/libcrypto.so") is lib and opened == ["/some/libcrypto.so"]
    assert lib.EVP_PKEY_new_raw_public_key_ex.restype is VP
    assert lib.EVP_PKEY_new_raw_public_key_ex.argtypes == [VP, CP, CP, CP, SZ]
    assert lib.EVP_MD_CTX_new.restype is VP and lib.EVP_MD_CTX_new.argtypes == []
    assert lib.EVP_DigestVerifyInit_ex.restype is ctypes.c_int
    assert lib.EVP_DigestVerifyInit_ex.argtypes == [VP, VP, CP, VP, CP, VP, VP]
    assert lib.EVP_DigestVerify.restype is ctypes.c_int and lib.EVP_DigestVerify.argtypes == [VP, CP, SZ, CP, SZ]
    assert lib.EVP_PKEY_free.restype is None and lib.EVP_PKEY_free.argtypes == [VP]
    assert lib.EVP_MD_CTX_free.restype is None and lib.EVP_MD_CTX_free.argtypes == [VP]


def test_builds(monkeypatch):
    lib = FakeLib(EVP_PKEY_new_raw_public_key_ex=lambda *a: 1234)
    assert pq._builds(lib, "ML-DSA-65") is True
    assert lib.EVP_PKEY_new_raw_public_key_ex.calls == [(None, b"ML-DSA-65", None, bytes(1952), 1952)]
    assert lib.EVP_PKEY_free.calls == [(1234,)]
    lib = FakeLib(EVP_PKEY_new_raw_public_key_ex=lambda *a: 0)
    assert pq._builds(lib, "SLH-DSA-SHA2-128f") is False and lib.EVP_PKEY_free.calls == []
    assert lib.EVP_PKEY_new_raw_public_key_ex.calls == [(None, b"SLH-DSA-SHA2-128f", None, bytes(32), 32)]
    assert pq._builds(lib, "unknown-type") is False  # KeyError is caught
    boom = FakeLib(EVP_PKEY_new_raw_public_key_ex=lambda *a: (_ for _ in ()).throw(OSError("x")))
    assert pq._builds(boom, "ML-DSA-87") is False


def test_libcrypto_selection_and_cache(monkeypatch):
    good, bad = FakeLib(), FakeLib()
    libs = {"/bad": bad, "/good": good}
    monkeypatch.setattr(pq, "_candidates", lambda: ["/missing", "/bad", "/good", "/never"])

    def bind(p):
        if p == "/missing":
            raise OSError("no such file")
        if p == "/never":
            raise AssertionError("must stop at the first usable library")
        return libs[p]

    monkeypatch.setattr(pq, "_bind", bind)
    monkeypatch.setattr(pq, "_builds", lambda lib, kt: lib is good and kt == "ML-DSA-65")
    assert pq._libcrypto() is good
    assert pq._libcrypto() is good  # cached
    # none usable: None, and tried only once
    monkeypatch.setattr(pq, "_lib", None)
    monkeypatch.setattr(pq, "_tried", False)
    monkeypatch.setattr(pq, "_builds", lambda lib, kt: False)
    monkeypatch.setattr(pq, "_candidates", lambda: ["/bad"])
    assert pq._libcrypto() is None and pq._tried is True
    monkeypatch.setattr(pq, "_candidates", lambda: (_ for _ in ()).throw(AssertionError("second probe")))
    assert pq._libcrypto() is None


def test_openssl_available_probes_once_per_type(monkeypatch):
    lib = object()
    calls = []
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    monkeypatch.setattr(pq, "_builds", lambda l, kt: calls.append(kt) or kt == "SLH-DSA-SHA2-128f")
    assert pq._openssl_available("SLH-DSA-SHA2-128f") is True
    assert pq._openssl_available("SLH-DSA-SHA2-128f") is True
    assert pq._openssl_available("SLH-DSA-SHA2-256s") is False
    assert calls == ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-256s"]
    monkeypatch.setattr(pq, "_probed", {})
    monkeypatch.setattr(pq, "_libcrypto", lambda: None)
    assert pq._openssl_available("SLH-DSA-SHA2-128f") is False


def _verify_lib(init=1, verify=1, new_key=99, new_ctx=77):
    return FakeLib(EVP_PKEY_new_raw_public_key_ex=lambda *a: new_key, EVP_MD_CTX_new=lambda: new_ctx,
                   EVP_DigestVerifyInit_ex=lambda *a: init, EVP_DigestVerify=lambda *a: verify)


def test_openssl_verify_sequence(monkeypatch):
    lib = _verify_lib()
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    monkeypatch.setattr(pq, "_openssl_available", lambda kt: True)
    assert pq._openssl_verify("SLH-DSA-SHA2-128f", b"K" * 32, b"msg", b"S" * 5) is True
    assert lib.EVP_PKEY_new_raw_public_key_ex.calls == [(None, b"SLH-DSA-SHA2-128f", None, b"K" * 32, 32)]
    assert lib.EVP_DigestVerifyInit_ex.calls == [(77, None, None, None, None, 99, None)]
    assert lib.EVP_DigestVerify.calls == [(77, b"S" * 5, 5, b"msg", 3)]
    assert lib.EVP_MD_CTX_free.calls == [(77,)] and lib.EVP_PKEY_free.calls == [(99,)]


@pytest.mark.parametrize("ret", [0, 2, -1, 1])
def test_openssl_verify_result_must_be_exactly_one(monkeypatch, ret):
    lib = _verify_lib(verify=ret)
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    monkeypatch.setattr(pq, "_openssl_available", lambda kt: True)
    assert pq._openssl_verify("SLH-DSA-SHA2-128f", b"K" * 32, b"m", b"s") is (ret == 1)
    assert lib.EVP_MD_CTX_free.calls == [(77,)] and lib.EVP_PKEY_free.calls == [(99,)]


@pytest.mark.parametrize("init", [0, 2, -1])
def test_openssl_verify_init_must_be_exactly_one(monkeypatch, init):
    lib = _verify_lib(init=init)
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    monkeypatch.setattr(pq, "_openssl_available", lambda kt: True)
    assert pq._openssl_verify("SLH-DSA-SHA2-128f", b"K" * 32, b"m", b"s") is False
    assert lib.EVP_DigestVerify.calls == []
    assert lib.EVP_MD_CTX_free.calls == [(77,)] and lib.EVP_PKEY_free.calls == [(99,)]


def test_openssl_verify_failures(monkeypatch):
    monkeypatch.setattr(pq, "_openssl_available", lambda kt: True)
    monkeypatch.setattr(pq, "_libcrypto", lambda: None)
    assert pq._openssl_verify("SLH-DSA-SHA2-128f", b"K" * 32, b"m", b"s") is False
    lib = _verify_lib(new_key=0)
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    assert pq._openssl_verify("SLH-DSA-SHA2-128f", b"K" * 32, b"m", b"s") is False
    assert lib.EVP_MD_CTX_new.calls == [] and lib.EVP_PKEY_free.calls == []
    lib = _verify_lib(new_ctx=0)
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    assert pq._openssl_verify("SLH-DSA-SHA2-128f", b"K" * 32, b"m", b"s") is False
    assert lib.EVP_PKEY_free.calls == [(99,)] and lib.EVP_MD_CTX_free.calls == []
    lib = _verify_lib()
    monkeypatch.setattr(pq, "_libcrypto", lambda: lib)
    monkeypatch.setattr(pq, "_openssl_available", lambda kt: False)
    assert pq._openssl_verify("SLH-DSA-SHA2-128f", b"K" * 32, b"m", b"s") is False
    assert lib.EVP_PKEY_new_raw_public_key_ex.calls == []


# ---- LESS library --------------------------------------------------------------------------------------------------------------

def _less_lib(sizes=(97484, 1153, 1329), verify=1):
    return FakeLib(atlas_less_cat1_public_key_bytes=lambda: sizes[0], atlas_less_cat1_signature_min_bytes=lambda: sizes[1],
                   atlas_less_cat1_signature_max_bytes=lambda: sizes[2], atlas_less_cat1_verify=lambda *a: verify)


def test_libless_selection(monkeypatch, tmp_path):
    f = tmp_path / "libx.so"
    f.write_bytes(b"")
    wrong = _less_lib(sizes=(97484, 1153, 1330))
    right = _less_lib()
    opened = []
    libs = {"nofile/path": None, str(f): right, "bare-name": wrong}
    monkeypatch.setattr(pq, "_less_candidates", lambda: [os.path.join("nonexistent", "dir", "lib.so"), "bare-name", str(f)])

    def cdll(p):
        opened.append(p)
        if p == "bare-name":
            return wrong
        if p == str(f):
            return right
        raise AssertionError("a missing path must be skipped without opening it: " + p)

    monkeypatch.setattr(pq.ctypes, "CDLL", cdll)
    assert pq._libless() is right
    assert opened == ["bare-name", str(f)]
    for name in ("atlas_less_cat1_public_key_bytes", "atlas_less_cat1_signature_min_bytes", "atlas_less_cat1_signature_max_bytes"):
        assert getattr(right, name).restype is SZ and getattr(right, name).argtypes == []
    assert right.atlas_less_cat1_verify.restype is ctypes.c_int
    assert right.atlas_less_cat1_verify.argtypes == [CP, SZ, CP, SZ, CP, SZ]
    assert pq._libless() is right  # cached


@pytest.mark.parametrize("sizes", [(97485, 1153, 1329), (97484, 1152, 1329), (97484, 1154, 1329), (97484, 1153, 1328), (1, 2, 3)])
def test_libless_requires_exact_sizes(monkeypatch, sizes):
    monkeypatch.setattr(pq, "_less_candidates", lambda: ["bare"])
    monkeypatch.setattr(pq.ctypes, "CDLL", lambda p: _less_lib(sizes=sizes))
    assert pq._libless() is None and pq._less_tried is True


def test_libless_symbol_failure_skips(monkeypatch):
    class NoSyms:
        def __getattr__(self, n):
            raise AttributeError(n)

    monkeypatch.setattr(pq, "_less_candidates", lambda: ["a", "b"])
    monkeypatch.setattr(pq.ctypes, "CDLL", lambda p: NoSyms() if p == "a" else _less_lib())
    assert pq._libless() is not None


# ---- availability / verify dispatch -----------------------------------------------------------------------------------------------

def test_available(monkeypatch):
    monkeypatch.setattr(pq, "ml_dsa65_available", lambda: False)
    monkeypatch.setattr(pq, "_ML_DSA_87", None)
    monkeypatch.setattr(pq, "_libless", lambda: None)
    monkeypatch.setattr(pq, "_openssl_available", lambda kt: kt == "SLH-DSA-SHA2-256s")
    assert pq.available("LESS-cat1") is False
    assert pq.available("ML-DSA-65") is False and pq.available("ML-DSA-87") is False
    assert pq.available("SLH-DSA-SHA2-128f") is False and pq.available("SLH-DSA-SHA2-256s") is True
    assert pq.available("nope") is False
    monkeypatch.setattr(pq, "_libless", lambda: object())
    assert pq.available("LESS-cat1") is True
    monkeypatch.setattr(pq, "ml_dsa65_available", lambda: True)
    assert pq.available("ML-DSA-65") is True and pq.available("ML-DSA-87") is False
    monkeypatch.setattr(pq, "_ML_DSA_87", object())
    assert pq.available("ML-DSA-87") is True
    # the OpenSSL probe also backs ML-DSA when no Python backend exists
    monkeypatch.setattr(pq, "ml_dsa65_available", lambda: False)
    monkeypatch.setattr(pq, "_ML_DSA_87", None)
    monkeypatch.setattr(pq, "_openssl_available", lambda kt: kt in ("ML-DSA-65", "ML-DSA-87"))
    assert pq.available("ML-DSA-65") is True and pq.available("ML-DSA-87") is True


def _args(kt, extra_sig=0):
    pk, sg = pq.KEY_TYPES[kt]
    if kt == "LESS-cat1":
        sg = 1153
    return b"P" * pk, b"msg", b"S" * (sg + extra_sig)


def test_verify_input_validation(monkeypatch):
    monkeypatch.setattr(pq, "_openssl_verify", lambda *a: True)
    pk, msg, sig = _args("SLH-DSA-SHA2-128f")
    assert pq.verify("SLH-DSA-SHA2-128f", pk, msg, sig) is True
    assert pq.verify("nope", pk, msg, sig) is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk[:-1], msg, sig) is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk + b"x", msg, sig) is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk, msg, sig[:-1]) is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk, msg, sig + b"x") is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk, "msg", sig) is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk, None, sig) is False
    assert pq.verify("SLH-DSA-SHA2-128f", "P" * 32, msg, sig) is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk, msg, "S" * 17088) is False
    assert pq.verify("SLH-DSA-SHA2-128f", None, msg, sig) is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk, msg, None) is False
    assert pq.verify("SLH-DSA-SHA2-128f", bytearray(pk), bytearray(msg), bytearray(sig)) is True
    assert pq.verify("SLH-DSA-SHA2-128f", memoryview(pk), msg, sig) is False
    assert pq.verify("SLH-DSA-SHA2-128f", pk, b"", sig) is True  # an empty message is a message


def test_verify_dispatch(monkeypatch):
    seen = {}
    monkeypatch.setattr(pq, "_openssl_verify", lambda kt, pk, msg, sig: seen.setdefault("ossl", []).append((kt, type(pk), type(msg), type(sig))) or True)
    monkeypatch.setattr(pq, "ml_dsa65_available", lambda: True)
    monkeypatch.setattr(pq, "ml_dsa65_verify", lambda pk, m, s: seen.setdefault("d65", []).append((len(pk), m, len(s))) or 1)
    fake87 = types.SimpleNamespace(verify=lambda pk, m, s: seen.setdefault("d87", []).append((len(pk), m, len(s))) or 5)
    monkeypatch.setattr(pq, "_ML_DSA_87", fake87)
    monkeypatch.setattr(pq, "_libless", lambda: types.SimpleNamespace(atlas_less_cat1_verify=lambda *a: seen.setdefault("less", []).append(a) or 1))
    pk, m, s = _args("ML-DSA-65")
    assert pq.verify("ML-DSA-65", pk, m, s) == 1 and seen["d65"] == [(1952, b"msg", 3309)] and "ossl" not in seen
    pk, m, s = _args("ML-DSA-87")
    assert pq.verify("ML-DSA-87", pk, m, s) is True and seen["d87"] == [(2592, b"msg", 4627)]  # bool() of the backend's value
    pk, m, s = _args("LESS-cat1")
    assert pq.verify("LESS-cat1", pk, m, s) is True
    assert seen["less"] == [(pk, 97484, m, 3, s, 1153)]
    pk, m, s = _args("SLH-DSA-SHA2-256s")
    assert pq.verify("SLH-DSA-SHA2-256s", bytearray(pk), bytearray(m), bytearray(s)) is True
    assert seen["ossl"] == [("SLH-DSA-SHA2-256s", bytes, bytes, bytes)]
    # no Python backend: ML-DSA falls through to OpenSSL
    monkeypatch.setattr(pq, "ml_dsa65_available", lambda: False)
    monkeypatch.setattr(pq, "_ML_DSA_87", None)
    seen.clear()
    pk, m, s = _args("ML-DSA-65")
    assert pq.verify("ML-DSA-65", pk, m, s) is True and len(seen["ossl"]) == 1
    pk, m, s = _args("ML-DSA-87")
    assert pq.verify("ML-DSA-87", pk, m, s) is True and len(seen["ossl"]) == 2


def test_verify_less_without_library_and_wrong_result(monkeypatch):
    pk, m, s = _args("LESS-cat1")
    monkeypatch.setattr(pq, "_libless", lambda: None)
    assert pq.verify("LESS-cat1", pk, m, s) is False
    for ret, want in ((0, False), (2, False), (-1, False), (1, True)):
        monkeypatch.setattr(pq, "_libless", lambda r=ret: types.SimpleNamespace(atlas_less_cat1_verify=lambda *a: r))
        assert pq.verify("LESS-cat1", pk, m, s) is want
    assert pq.verify("LESS-cat1", pk, m, _args("LESS-cat1", 1)[2]) is False  # 1,154 bytes is not a LESS length


def test_verify_never_raises(monkeypatch):
    monkeypatch.setattr(pq, "_openssl_verify", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    pk, m, s = _args("SLH-DSA-SHA2-128f")
    assert pq.verify("SLH-DSA-SHA2-128f", pk, m, s) is False


def test_verify_real_dilithium_roundtrip():
    dil = pytest.importorskip("dilithium_py.ml_dsa")
    for kt, alg in (("ML-DSA-65", dil.ML_DSA_65), ("ML-DSA-87", dil.ML_DSA_87)):
        if not pq.available(kt):
            continue
        pk, sk = alg.keygen()
        sig = alg.sign(sk, b"hello")
        assert pq.verify(kt, pk, b"hello", sig) is True
        assert pq.verify(kt, pk, b"hellp", sig) is False
        bad = bytearray(sig)
        bad[0] ^= 1
        assert pq.verify(kt, pk, b"hello", bytes(bad)) is False
