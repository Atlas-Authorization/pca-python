"""Mutation-kill tests (batch A): ed25519, the strict JSON parser / canonicalizer helpers, base64url, _PinnedPq and
the FastAPI / Django adapters. Every assertion pins an exact value, message or boundary the corpus never reaches."""
import asyncio

import pytest

from atlas_pca import ed25519
from atlas_pca.ed25519 import _ID, _G, _decode, _eq, _is_small_order, _p, _q, _recover_x
from atlas_pca.pca import (
    MAX_JSON_CHARS, StrictJsonError, _PinnedPq, _has_surrogate, _plain, _resolve_pq_key,
    _utf8_key, canonical_bytes, canonicalize, strict_number_error, strict_parse, suite_available, unb64u,
)


# ---- ed25519 --------------------------------------------------------------------------

def _keypair_sig(msg):
    """RFC 8032 Ed25519 key + signature over `msg` for the seed bytes(range(32)). Uses `cryptography` (the optional
    `fast` extra) when installed, else a test-only RFC 8032 signer over the verifier's own curve arithmetic -- the
    no-optional-dependencies job has no `cryptography`, and Ed25519 signing is deterministic, so both paths yield
    the same bytes."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        return _pure_keypair_sig(bytes(range(32)), msg)
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pub, sk.sign(msg)


def _pure_keypair_sig(seed, msg):
    import hashlib

    def enc(P):
        zi = ed25519._inv(P[2])
        x, y = P[0] * zi % _p, P[1] * zi % _p
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = enc(ed25519._mul(a, _G))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % _q
    R = enc(ed25519._mul(r, _G))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % _q
    return A, R + ((r + k * a) % _q).to_bytes(32, "little")


def test_recover_x_zero_x2_branch():
    # y = +-1 gives x^2 == 0: x = 0 is the only root, and the sign bit set on x = 0 is non-canonical.
    assert _recover_x(1, 0) == 0
    assert _recover_x(1, 1) is None
    assert _recover_x(_p - 1, 0) == 0
    assert _recover_x(_p - 1, 1) is None
    assert _recover_x(_p, 0) is None
    gx = _recover_x(_G[1], 0)
    assert gx == _G[0] and _recover_x(_G[1], 1) == _p - gx


def test_eq_projective():
    # (1/3, 2/3) == (2/6, 4/6): equality must cross-multiply (exact integers), never divide.
    assert _eq((1, 2, 3, 0), (2, 4, 6, 0)) is True
    assert _eq((2, 4, 6, 0), (1, 2, 3, 0)) is True
    assert _eq((1, 2, 3, 0), (1, 4, 6, 0)) is False
    assert _eq((1, 2, 3, 0), (2, 5, 6, 0)) is False
    assert _eq(_G, _G) and not _eq(_G, _ID)


def test_decode_invalid_returns_none():
    assert _decode(b"\xff" * 32) is None  # y >= p after masking the sign bit
    assert _decode(b"\x01" + b"\x00" * 30 + b"\x80") is None  # y = 1 with the sign bit: x = 0 is non-canonical
    assert _decode(b"\x00" * 31) is None
    ident = _decode(b"\x01" + b"\x00" * 31)
    assert ident == (0, 1, 1, 0)


def test_is_small_order_exact():
    two_torsion = (0, _p - 1, 1, 0)  # order 2
    assert _is_small_order(two_torsion) is True
    assert _is_small_order(_ID) is True
    assert _is_small_order(_G) is False


def test_verify_accepts_valid_and_rejects_every_failure_path():
    msg = b"atlas pca mutation kill"
    pub, sig = _keypair_sig(msg)
    assert ed25519.verify(pub, msg, sig) is True
    assert ed25519.verify(pub, msg + b"!", sig) is False
    assert ed25519.verify(pub[:31], msg, sig) is False
    assert ed25519.verify(pub + b"\0", msg, sig) is False
    assert ed25519.verify(pub, msg, sig[:63]) is False
    assert ed25519.verify(pub, msg, sig + b"\0") is False
    # S = q (non-canonical) and S + q (the malleated twin) are refused
    assert ed25519.verify(pub, msg, sig[:32] + _q.to_bytes(32, "little")) is False
    s = int.from_bytes(sig[32:], "little")
    assert ed25519.verify(pub, msg, sig[:32] + (s + _q).to_bytes(32, "little")) is False
    # small-order key / R
    assert ed25519.verify(b"\x01" + b"\x00" * 31, msg, sig) is False
    assert ed25519.verify(pub, msg, b"\x01" + b"\x00" * 31 + sig[32:]) is False
    # an exception inside (len(None)) is a refusal, never an accept
    assert ed25519.verify(None, msg, sig) is False
    assert ed25519.verify(pub, msg, None) is False
    assert ed25519.verify(pub, None, sig) is False


# ---- base64url ------------------------------------------------------------------------

def test_unb64u_exact():
    assert unb64u("AA") == b"\x00" and unb64u("YWI") == b"ab"
    for bad in ("A", "AB", "YQ==", "a+b/", None):
        with pytest.raises(ValueError) as e:
            unb64u(bad)
        assert str(e.value) == "bad base64url"


# ---- strict JSON parser ---------------------------------------------------------------

def _perr(text):
    with pytest.raises(StrictJsonError) as e:
        strict_parse(text)
    assert type(e.value) is StrictJsonError
    return str(e.value)


def test_has_surrogate_bounds():
    assert _has_surrogate("\ud800") and _has_surrogate("\udfff") and _has_surrogate("a\udc00")
    assert not _has_surrogate("퟿") and not _has_surrogate("") and not _has_surrogate("")


def test_strict_parse_invalid_utf8_message():
    assert _perr(b"\xff") == "invalid UTF-8"
    assert _perr(bytearray(b'"\xc3"')) == "invalid UTF-8"
    assert strict_parse(b'"\xc3\xa9"') == "é"


def test_strict_parse_size_boundary():
    exact = '"' + "a" * (MAX_JSON_CHARS - 2) + '"'
    assert len(exact.encode("utf-8")) == MAX_JSON_CHARS
    assert strict_parse(exact) == "a" * (MAX_JSON_CHARS - 2)
    assert _perr('"' + "a" * (MAX_JSON_CHARS - 1) + '"') == "input too large"
    assert _perr(b'"' + b"a" * (MAX_JSON_CHARS - 1) + b'"') == "input too large"


def test_strict_parse_raw_surrogates():
    assert _perr('"\ud800"') == "lone surrogate in string (at offset 1)"
    assert _perr('"\udfff"') == "lone surrogate in string (at offset 1)"
    assert _perr('"ab\ud800"') == "lone surrogate in string (at offset 3)"
    assert _perr('["x", "ab\udbff"]') == "lone surrogate in string (at offset 9)"
    assert strict_parse('"퟿"') == "퟿"


def test_strict_parse_escaped_surrogate_bounds():
    assert strict_parse('"\\ue000"') == ""
    assert strict_parse('"\\ud7ff"') == "퟿"
    assert _perr('"\\udfff"').startswith("lone surrogate in string")
    assert _perr('"\\udc00"').startswith("lone surrogate in string")
    assert strict_parse('"\\ud83d\\ude00"') == "\U0001F600"


def test_strict_parse_underflowing_decimal_is_zero():
    # Mirrors strict-json.ts (`v !== 0 && |v| < 1e-6`): a literal that underflows to 0 is not refused by that rule.
    v = strict_parse("0." + "0" * 400 + "1")
    assert v == 0.0 and isinstance(v, float)
    assert _perr("0.0000001").startswith("non-integer magnitude below 1e-6 is not allowed")
    assert strict_parse("0.000001") == 1e-6
    assert strict_parse("1.5") == 1.5


# ---- canonicalization -----------------------------------------------------------------

def test_utf8_key_surrogatepass():
    assert _utf8_key("\ud800") == b"\xed\xa0\x80"
    assert _utf8_key("a\udfff") == b"a\xed\xbf\xbf"
    assert canonicalize({"\ud800": 1, "a": 2, "": 3}) == '{"a":2,"\ud800":1,"":3}'


def test_strict_number_error_negative_digit_count():
    assert strict_number_error(-1.2345678901234) is None
    assert strict_number_error(-0.123456789012345) is None
    assert strict_number_error(1.2345678901234) is None
    assert strict_number_error(-1.2345678901234567) == "non-integer number has more than 15 significant digits"


def test_plain_non_finite_passthrough():
    assert _plain(float("inf")) == "inf"
    assert _plain(float("-inf")) == "-inf"
    assert _plain(float("nan")) == "nan"
    assert _plain(0.5) == "0.5" and _plain(-0.0) == "-0.0"


def test_num_float_forms():
    assert canonicalize(1.0) == "1"
    assert canonicalize(0.0) == "0"
    assert canonicalize(-0.0) == "0"
    assert canonicalize(5.0) == "5"
    assert canonicalize(-7.0) == "-7"
    assert canonicalize([0.0, 1.0, 2.5]) == "[0,1,2.5]"
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(TypeError) as e:
            canonicalize(bad)
        assert type(e.value) is TypeError and str(e.value) == "canonicalize: non-finite number"


def test_ser_type_errors_exact():
    with pytest.raises(TypeError) as e:
        canonicalize({1: 2})
    assert str(e.value) == "canonicalize: non-string key"
    with pytest.raises(TypeError) as e:
        canonicalize({"a": {None: 1}})
    assert str(e.value) == "canonicalize: non-string key"
    with pytest.raises(TypeError) as e:
        canonicalize(b"x")
    assert str(e.value) == "canonicalize: unsupported type bytes"
    with pytest.raises(TypeError) as e:
        canonicalize([object()])
    assert str(e.value) == "canonicalize: unsupported type object"


def test_canonical_bytes_lenient():
    assert canonical_bytes({"a": "\ud800"}) == b'{"a":"\xed\xa0\x80"}'
    assert canonical_bytes(1) == b"1"
    assert canonical_bytes({"b": [True, None], "a": "é"}) == b'{"a":"\xc3\xa9","b":[true,null]}'


# ---- _PinnedPq ------------------------------------------------------------------------

def test_pinned_pq_mint_and_fields():
    for args in (("k", "s"), ("k", "s", object())):
        with pytest.raises(TypeError) as e:
            _PinnedPq(*args)
        assert str(e.value) == "_PinnedPq is minted only by _resolve_pq_key"
    pq = _PinnedPq("k", "trusted", _PinnedPq._MINT)
    assert pq.key == "k" and pq.source == "trusted"
    assert _resolve_pq_key("id", "AP", trusted_pk="TP").source == "trusted"
    r = _resolve_pq_key("id", "AP", pq_pins={"id": "AP"})
    assert r.key == "AP" and r.source == "pin"


# ---- FastAPI / Django adapters --------------------------------------------------------

def test_fastapi_default_detail(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi import HTTPException

    import atlas_pca.fastapi as fa
    from atlas_pca.server import PCAResult

    monkeypatch.setattr(fa, "require_pca",
                        lambda **kw: (lambda headers, body: PCAResult(ok=False, status=401, error=None)))

    class Req:
        headers = {}

        async def body(self):
            return b""

        class state:  # noqa: N801
            pass

    with pytest.raises(HTTPException) as ei:
        asyncio.run(fa.RequirePCA(audience="a", resolve_grant=lambda r: None, signature_only=True)(Req()))
    assert ei.value.status_code == 401
    assert ei.value.detail == "proof-carrying authority required"
    assert ei.value.doc == "https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md"
    assert ei.value.headers is None


def test_django_pca_now_defaults_to_none():
    pytest.importorskip("django")
    from test_server_exact import _django
    from test_server import _resolver

    settings = _django()
    saved = {k: getattr(settings, k) for k in ("PCA_AUDIENCE", "PCA_RESOLVE_GRANT", "PCA_NOW") if hasattr(settings, k)}
    try:
        if hasattr(settings, "PCA_NOW"):
            del settings.PCA_NOW
        assert not hasattr(settings, "PCA_NOW")
        settings.PCA_AUDIENCE = "rs"
        settings.PCA_RESOLVE_GRANT = _resolver
        from atlas_pca.django import PCAMiddleware

        mw = PCAMiddleware(lambda r: None)
        assert mw._now is None
    finally:
        for k, v in saved.items():
            setattr(settings, k, v)


# ---- batch A2 -------------------------------------------------------------------------

def test_strict_parse_non_string_message():
    for bad in (123, None, ["x"]):
        assert _perr(bad) == "input is not a string"


def test_strict_parse_whitespace_set():
    assert strict_parse(" \t\n\r1 \t\n\r") == 1
    assert _perr("X1") == "unexpected token (at offset 0)"
    assert _perr("[1X]") == 'expected "," or "]" (at offset 2)'


def test_strict_parse_backslash_at_end():
    assert _perr('"\\') == "unknown escape (at offset 2)"
    assert _perr('"a\\') == "unknown escape (at offset 3)"


def test_strict_parse_escaped_pair_bounds():
    # 0xDC00 is a LOW surrogate: it can never open a pair (combining it would yield cp 0x110000)
    assert _perr('"\\udc00\\udc00"') == "lone surrogate in string (at offset 7)"
    assert strict_parse('"\\udbff\\udfff"') == "\U0010FFFF"
    # 0xE000 is not a low surrogate: a high surrogate followed by  is lone
    assert _perr('"\\ud800\\ue000"') == "lone surrogate in string (at offset 7)"


def test_negative_decimal_digit_count():
    assert strict_parse("-1.23456789012345") == -1.23456789012345
    assert strict_parse("-0.123456789012345") == -0.123456789012345
    assert _perr("-1.234567890123456").startswith("more than 15 significant digits")
    assert strict_number_error(-1.23456789012345) is None


def test_strict_canonical_refuses_surrogate_key():
    from atlas_pca.pca import canonicalize_strict

    for v in ({"\ud800": 1}, {"a": {"b\udfff": 1}}):
        with pytest.raises(TypeError) as e:
            canonicalize_strict(v)
        assert str(e.value) == "canonicalize: lone surrogate in string"
    assert canonicalize({"\ud800": 1}) == '{"\ud800":1}'


def test_params_digest_uses_params():
    from atlas_pca.pca import EMPTY_PARAMS_DIGEST, hash_canonical, params_digest

    assert params_digest({"a": 1}) == hash_canonical({"a": 1}) != EMPTY_PARAMS_DIGEST
    assert params_digest(None) == hash_canonical({}) == EMPTY_PARAMS_DIGEST


def test_signable_hop_body_pq_pk_binding():
    from atlas_pca.pca import _signable_hop_body

    base = {"issuer": "i", "holder": "h", "caveats": [], "parent": None}
    want = {"issuer": "i", "holder": "h", "caveats": [], "parent": None, "alg": "ml-dsa-65"}
    if suite_available("ml-dsa-65"):
        assert _signable_hop_body({**base, "alg": "ml-dsa-65"}) == (want, None)
        assert _signable_hop_body({**base, "alg": "ml-dsa-65", "pq_pk": 5}) == (want, None)
        assert _signable_hop_body({**base, "alg": "ml-dsa-65", "pq_pk": "PK"}) == ({**want, "pq_pk": "PK"}, None)
    else:  # no ML-DSA backend (no dilithium-py, OpenSSL < 3.5): the suite fails closed before any body is built
        for c in ({**base, "alg": "ml-dsa-65"}, {**base, "alg": "ml-dsa-65", "pq_pk": "PK"}):
            assert _signable_hop_body(c) == (None, "unsupported_suite: ml-dsa-65")
    assert _signable_hop_body({**base, "pq_pk": "PK"}) == (base, None)


def test_hop_well_typed_non_dict():
    from atlas_pca.pca import _hop_well_typed

    for c in ("x", None, [], 1):
        assert _hop_well_typed(c) is False
