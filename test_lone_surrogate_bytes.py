"""A lone surrogate is written as U+FFFD (EF BF BD) before hashing or signing, as the reference's TextEncoder does; never as ED B0 80."""
import hashlib
import json

from atlas_pca import pca as P


def test_utf8_writes_replacement_not_surrogatepass():
    assert P.utf8("a\udc00b") == b"a\xef\xbf\xbdb"
    assert P.utf8("\ud800") == b"\xef\xbf\xbd"
    assert P.utf8("\U0001f600") == b"\xf0\x9f\x98\x80"


def test_lenient_canonical_bytes_hash_matches_js():
    # JSON.stringify-style canonical form of {"k":"a<lone DC00>b"} through TextEncoder
    want = hashlib.sha256(b'{"k":"a\xef\xbf\xbdb"}').hexdigest()
    got = hashlib.sha256(P.canonical_bytes({"k": "a\udc00b"})).hexdigest()
    assert got == want


def test_key_order_ties_between_lone_surrogates_follow_utf16_order():
    # "\ud800", "\ud801" and U+FFFD all encode alike: the tie is broken by code-unit order
    ks = ["�", "\ud801", "\ud800"]
    assert sorted(ks, key=P._utf8_key) == ["\ud800", "\ud801", "�"]


def test_json_parser_keeps_escaped_lone_surrogates():
    s = json.loads('"x\\udc00"')
    assert s == "x\udc00" and P.utf8(s) == b"x\xef\xbf\xbd"
    # the strict wire profile refuses an escaped lone surrogate (it is not JSON.parse); the corpus {"$utf16"} decode lands in the same str
    import pytest
    with pytest.raises(P.StrictJsonError):
        P.strict_parse('"\\udc00"')
    from base_oracle import _unseed
    assert _unseed({"$utf16": [0xDC00]}) == "\udc00" and _unseed({"$utf16": [0xD83D, 0xDE00]}) == "\U0001f600"


def test_percent_encoders_refuse_a_lone_surrogate_like_encodeURIComponent():
    import pytest
    from urllib.parse import quote
    from atlas_pca import gateway as G
    with pytest.raises(ValueError):
        G._encode_uri_component("a\udc00")
    with pytest.raises(UnicodeEncodeError):  # the library's other encoders are quote(): strict, so it refuses too
        quote("a\udc00", safe="-_.!~*'()")
    assert G._encode_uri_component("a b\U0001f600") == "a%20b%F0%9F%98%80"


def test_decode_uri_component_passes_a_lone_surrogate_and_checks_each_escape_run():
    import pytest
    from atlas_pca import connect as C
    assert C._decode_uri_component("a\udc00%41") == "a\udc00A"
    assert C._decode_uri_component("%E2%82%AC") == "\u20ac"
    for bad in ("%E2%82", "%E2x", "%", "%zz", "%C0%80"):
        with pytest.raises(ValueError):
            C._decode_uri_component(bad)


def test_ciba_directory_key_file_hashes_the_textencoder_bytes():
    import hashlib
    from atlas_pca.ciba_store import create_directory_kv
    import tempfile, os
    d = tempfile.mkdtemp()
    kv = create_directory_kv(d)
    assert kv.put_if_equals("k\udc00", None, "v") is True
    assert os.path.exists(os.path.join(d, hashlib.sha256(b"k\xef\xbf\xbd").hexdigest()))
