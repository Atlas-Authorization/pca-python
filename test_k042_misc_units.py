"""Kill tests: PCA-Action header decoding (refusal texts, UTF-8 handling), and predicate-leaf edge cases (regex budget
exhaustion is unknown, one-character collection paths, params-rooted refs)."""
import base64

import pytest

from atlas_pca import predicates as P
from atlas_pca.pca import PcaHeaderError, decode_pca_header


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_header_ok_and_texts():
    assert decode_pca_header(b64u(b'{"a":1}')) == '{"a":1}'
    assert decode_pca_header(b64u("é".encode())) == "é"
    assert decode_pca_header(b64u(b"\xef\xbb\xbfx")) == "﻿x"  # a leading BOM is kept
    for bad in ("", None, 5, b"abc", [], {}):
        with pytest.raises(PcaHeaderError) as e:
            decode_pca_header(bad)
        assert str(e.value) == "PCA-Action header is empty"
    for bad in ("a", "abcde", "ab=", "ab cd", " abcd", "abcd ", "ab+/", "a\nb", "YQ==", "YR"):
        with pytest.raises(PcaHeaderError) as e:
            decode_pca_header(bad)
        assert str(e.value) == "PCA-Action header is not strict unpadded base64url", bad
    for raw in (b"\xff", b"\xc0\xaf", b"\xed\xa0\x80", b"\xe2\x82", b"ok\x80"):
        with pytest.raises(PcaHeaderError) as e:
            decode_pca_header(b64u(raw))
        assert str(e.value) == "PCA-Action header does not decode to UTF-8 text", raw
    assert PcaHeaderError.code == "invalid_pca_header"


CTX = {"action": {"verb": "v", "resource": "r", "params": {"x": 1}}, "subject": {"id": "a"}, "env": {"g": {"a": "b"}}}


def tri(cond, ctx=CTX):
    return P.evaluate_condition_tri(cond, ctx)


def test_matches_unknown_when_the_engine_gives_up(monkeypatch):
    cond = {"field": "action.resource", "op": "matches", "value": "r"}
    assert tri(cond) == "true"
    monkeypatch.setattr(P, "safe_regex_full_match", lambda pat, s: None)
    assert tri(cond) == "unknown"
    monkeypatch.setattr(P, "safe_regex_full_match", lambda pat, s: False)
    assert tri(cond) == "false"


def test_member_of_collection_path():
    cond = {"field": "subject.id", "op": "member_of", "collection": "env.g", "value": "b"}
    assert tri(cond) == "true"
    assert tri(dict(cond, collection="")) == "unknown"
    assert tri(dict(cond, collection=5)) == "unknown"
    assert tri(dict(cond, collection=None)) == "unknown"
    assert tri({k: v for k, v in cond.items() if k != "collection"}) == "unknown"
    assert tri(dict(cond, value=5)) == "unknown"
    assert tri(dict(cond, value=[])) == "unknown"
    assert tri(dict(cond, value=["zz", "b"])) == "true"
    assert tri(dict(cond, value="zz")) == "false"


def test_leaf_requires_field_and_op():
    base = {"field": "action.verb", "op": "eq", "value": "v"}
    assert tri(base) == "true"
    for bad in ({"op": "eq", "value": "v"}, {"field": "action.verb", "value": "v"}, dict(base, field=""), dict(base, field=5),
                dict(base, op=5), dict(base, op=None), dict(base, op="nope")):
        assert tri(bad) == "unknown", bad


def test_params_rooted_refs_fail_closed_without_params():
    no_params = {"action": {"verb": "v", "resource": "r"}}
    cond = {"field": "action.verb", "op": "eq", "ref": "action.params.x"}
    assert tri(cond, no_params) == "unknown"
    assert tri({"field": "action.verb", "op": "eq", "ref": "action.params"}, no_params) == "unknown"
    assert tri({"field": "action.params.x", "op": "exists"}, no_params) == "unknown"
    assert tri({"field": "action.params", "op": "exists"}, no_params) == "unknown"
    assert tri({"field": "action.verb", "op": "eq", "ref": "action.resource"}, no_params) == "false"
    assert tri({"field": "action.resource", "op": "eq", "ref": "action.resource"}, no_params) == "true"
    assert tri({"field": "action.paramsX", "op": "exists"}, no_params) == "false"
    assert tri(cond, CTX) == "false"


def test_exists_still_honours_a_params_rooted_ref():
    no_params = {"action": {"verb": "v", "resource": "r"}}
    assert tri({"field": "action.verb", "op": "exists", "ref": "action.params.x"}, no_params) == "unknown"
    assert tri({"field": "action.verb", "op": "exists", "ref": "action.params"}, no_params) == "unknown"
    assert tri({"field": "action.verb", "op": "exists", "ref": "action.paramsX"}, no_params) == "true"
    assert tri({"field": "action.verb", "op": "exists", "ref": "ACTION.PARAMS.x"}, no_params) == "true"
    assert tri({"field": "action.verb", "op": "exists", "ref": 5}, no_params) == "true"
