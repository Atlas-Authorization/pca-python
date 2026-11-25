"""Mutation-kill tests that conftest.py orders before every other test: each one decides, with an ordinary assertion, a mutant that
any later test would turn into a crash (a NULL pointer handed to libcrypto or memset, a misplaced OSSL_PARAM field read as a char
pointer, or a modular inverse computed without its modulus).

They call only the pieces under test, with stand-ins (a fake libcrypto, a recording memset), so no mutant of another function can
make them hang. Nothing runs at import."""
import ctypes

import pytest

from atlas_pca import ed25519 as E
from atlas_pca import pq_backends as PB


# ---- ed25519 field arithmetic ----------------------------------------------------------------------------------------------

def test_field_inverse_of_minus_one_is_reduced():
    # pow(-1, p - 2, p) == p - 1; without the modulus the result is -1, so a dropped modulus fails here instead of exhausting memory
    # on a real field element later
    assert E._inv(-1) == E._p - 1


def test_square_root_recovery_of_the_base_point():
    # tests run in any order inside this file: the inverse is decided first here too, before _recover_x calls it on a field element
    assert E._inv(-1) == E._p - 1
    # unwrapped on purpose: an exponentiation without its modulus must exhaust memory or time HERE (a run error the run-error ledger
    # names), never inside a deadline wrapper that would turn it into a nondeterministic kill
    assert E._recover_x(E._gy, 0) == E._gx


# ---- OpenSSL parameters and seeded key generation (fake libcrypto) -----------------------------------------------------------

def test_params_is_one_entry_and_the_end_marker():
    buf = ctypes.create_string_buffer(b"abc", 3)
    arr = PB._params(b"seed", PB._OSSL_PARAM_OCTET_STRING, buf)
    assert len(arr) == 2
    p = arr[0]
    # the fields a mutant could misplace are compared before `key` is read (a bogus char* would crash the process)
    assert (p.data_type, p.data, p.data_size, p.return_size) == \
        (PB._OSSL_PARAM_OCTET_STRING, ctypes.addressof(buf), 3, PB._OSSL_PARAM_UNMODIFIED)
    assert p.key == b"seed"
    end = arr[1]
    assert (end.key, end.data_type, end.data, end.data_size, end.return_size) == (None, 0, None, 0, 0)


class _Fn:
    def __init__(self, f):
        self.f = f

    def __call__(self, *a):
        return self.f(*a)


class _Lib:
    """A stand-in libcrypto: EVP_* functions return 1 unless a test supplies its own."""

    def __init__(self, **impl):
        self.impl = impl
        self.calls = []

    def __getattr__(self, name):
        if not name.startswith("EVP_"):
            raise AttributeError(name)
        f = self.impl.get(name, lambda *a: 1)
        fn = _Fn(lambda *a, _n=name, _f=f: self.calls.append((_n, a)) or _f(*a))
        self.__dict__[name] = fn
        return fn


def _seeded(monkeypatch, key_type, seed, set_params_result):
    seen, cleared = [], []
    real_memset = ctypes.memset

    def memset(dst, c, n):
        assert isinstance(dst, ctypes.Array), "memset target %r" % (dst,)  # a NULL target would crash the process
        cleared.append(dst)
        return real_memset(dst, c, n)

    def set_params(ctx, params):
        p = params[0]
        rec = {"ctx": ctx, "type": p.data_type, "size": p.data_size, "ret": p.return_size, "data": p.data}
        if p.data_type == PB._OSSL_PARAM_OCTET_STRING and p.data_size == len(seed) and p.data:
            rec["key"], rec["bytes"] = p.key, ctypes.string_at(p.data, p.data_size)
        seen.append(rec)
        return set_params_result

    def generate(ctx, ref):
        ref._obj.value = 4242
        return 1

    lib = _Lib(EVP_PKEY_CTX_new_from_name=lambda *a: 99, EVP_PKEY_CTX_set_params=set_params, EVP_PKEY_generate=generate)
    monkeypatch.setattr(PB, "_libcrypto", lambda: lib)
    monkeypatch.setattr(PB, "_openssl_available", lambda t: True)
    monkeypatch.setattr(ctypes, "memset", memset)
    return lib, seen, cleared


def test_seeded_key_generation_hands_the_seed_over_and_clears_it(monkeypatch):
    seed = bytes(range(1, 33))
    lib, seen, cleared = _seeded(monkeypatch, "ML-DSA-65", seed, 1)
    k = PB.OpensslKey("ML-DSA-65", seed)
    assert len(seen) == 1
    r = seen[0]
    assert r["ctx"] == 99
    assert (r["type"], r["size"], r["ret"]) == (PB._OSSL_PARAM_OCTET_STRING, 32, PB._OSSL_PARAM_UNMODIFIED)
    assert r["key"] == b"seed" and r["bytes"] == seed
    assert len(cleared) == 1 and r["data"] == ctypes.addressof(cleared[0]) and cleared[0].raw == bytes(32)
    assert k._pkey.value == 4242


def test_refused_seed_raises_and_still_clears_it(monkeypatch):
    seed = bytes(range(1, 49))
    lib, seen, cleared = _seeded(monkeypatch, "SLH-DSA-SHA2-128f", seed, 0)
    with pytest.raises(RuntimeError) as e:
        PB.OpensslKey("SLH-DSA-SHA2-128f", seed)
    assert str(e.value) == "unsupported_suite: SLH-DSA-SHA2-128f (seeded key generation failed)"
    assert [r["ctx"] for r in seen] == [99] and seen[0]["bytes"] == seed
    assert len(cleared) == 1 and cleared[0].raw == bytes(48)
    names = [n for n, _ in lib.calls]
    assert "EVP_PKEY_generate" not in names and ("EVP_PKEY_CTX_free", (99,)) in lib.calls
