"""A lenient JSON segment past 16 MiB is refused before parsing: `<ctx>: malformed JSON segment: input too large`."""
import base64

import pytest

from atlas_pca import attest_common as C

LIMIT = 16 * 1024 * 1024


def test_the_limit_itself_parses_and_one_more_is_refused():
    ok = " " * (LIMIT - 2) + "[]"
    assert len(ok) == LIMIT
    assert C.js_json_loads(ok) == []
    with pytest.raises(C.JsError) as e:
        C.js_json_loads(" " + ok)
    assert str(e.value) == "input too large"


def test_the_refusal_is_not_a_parse_error(monkeypatch):
    monkeypatch.setattr(C.json, "loads", lambda *a, **k: pytest.fail("parsed an oversized segment"))
    with pytest.raises(C.JsError) as e:
        C.js_json_loads("x" * (LIMIT + 1))
    assert str(e.value) == "input too large"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_a_jws_with_an_oversized_segment_is_a_malformed_segment():
    big = b64u(b" " * (LIMIT + 1))
    with pytest.raises(TypeError) as e:
        C.parse_jws("%s.%s.%s" % (big, b64u(b"{}"), b64u(b"sig")), "verifyX")
    assert str(e.value) == "verifyX: malformed JSON segment: input too large"


def test_a_multibyte_segment_is_measured_in_bytes():
    seg = ("é" * (LIMIT // 2 + 1)).encode("utf-8")  # LIMIT + 2 bytes, only LIMIT/2 + 1 characters
    with pytest.raises(TypeError) as e:
        C.parse_jws("%s.%s.%s" % (b64u(seg), b64u(b"{}"), b64u(b"sig")), "verifyX")
    assert str(e.value) == "verifyX: malformed JSON segment: input too large"
    with pytest.raises(TypeError) as e:
        C.parse_jws("%s.%s.%s" % (b64u(b"{}"), b64u(seg), b64u(b"sig")), "verifyX")
    assert str(e.value) == "verifyX: malformed JSON segment: input too large"


def test_signed_intel_json_over_the_limit_is_refused_first():
    from atlas_pca import attest_intel as I
    assert I._verify_signed_json(" " * (LIMIT + 1), "tcbInfo", None) == {"error": "tcbInfo: malformed JSON segment: input too large"}
    assert I._verify_signed_json(" " * LIMIT, "tcbInfo", None) == {"error": "tcbInfo not found / malformed"}
