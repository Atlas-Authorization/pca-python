"""K3 kill tests of the 0.5 full mutation baseline: exact refusal dicts on the paths the shared k3 vectors do not reach
(threshold 0, a malformed `last`, a flow_rules_digest that is not a string, a batch longer than its signed head, a
malformed receiver state, a cursor with a non-string bind, a bind that cannot be digested), compare_version over
unequal lengths, authority_ok bounds and UTF-16 ordering in authority_digest."""
import base64
import copy
import json

from atlas_pca import k3 as K
from test_k3_vectors import DOC


def _vec(kind, name):
    return copy.deepcopy(next(e for e in DOC[kind] if e["name"] == name))


def test_bundle_refusals_off_the_vectors():
    i = _vec("bundle_verify", "2-of-3 accepted")["input"]
    o = i["options"]
    assert K.verify_bundle(i["bundle"], o["signers"], 0, o["verifierVersion"]) == {
        "ok": False, "code": "malformed", "reason": "bad sigs or threshold"}
    assert K.verify_bundle(i["bundle"], o["signers"], o["threshold"], o["verifierVersion"], {"digest": "x"}) == {
        "ok": False, "code": "malformed", "reason": "malformed"}
    for k in ("schema_digest", "constitution_digest", "flow_rules_digest"):
        assert K.verify_bundle(dict(i["bundle"], **{k: 5}), o["signers"], o["threshold"], o["verifierVersion"]) == {
            "ok": False, "code": "malformed", "reason": "bad " + k}


def test_batch_refusals_off_the_vectors():
    e = _vec("log_batch_verify", "the whole log")
    i = e["input"]
    b, st = i["batch"], i["state"]
    assert K.verify_batch(b, {"next": st["next"]}, i["signer"]) == {"ok": False, "reason": "malformed batch"}
    extra = dict(b["records"][-1], seq=e["expect"]["next"], prev=e["expect"]["lastCommit"])
    longer = dict(b, records=b["records"] + [extra])
    assert K.verify_batch(longer, st, i["signer"]) == {"ok": False, "reason": "batch is longer than the signed head"}


def _b64u(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")


def test_cursor_refusals_off_the_vectors():
    assert K.verify_list_cursor(_b64u({"v": 1, "bind": 5, "skip": 0, "signer": "s"}) + ".AAAA", "s") == {"ok": False, "reason": "malformed"}
    assert K.verify_list_cursor(_b64u({"v": 2, "bind": "b", "skip": 0, "signer": "s"}) + ".AAAA", "s") == {"ok": False, "reason": "malformed"}
    assert K.verify_list_cursor("!!.AAAA", "s") == {"ok": False, "reason": "malformed"}
    i = _vec("list_cursor_verify", "valid and bound to its inputs")["input"]
    assert K.verify_list_cursor(i["cursor"], i["signer"], {}) == {"ok": False, "reason": "bind"}


def test_compare_version_unequal_lengths():
    assert K.compare_version("1", "1.0") == 0 and K.compare_version("1.0", "1") == 0
    assert K.compare_version("1", "1.1") == -1 and K.compare_version("1.0.1", "1") == 1


def test_authority_ok_bounds():
    assert K.authority_ok({"verbs": ["v"] * 256, "resources": []}) is True
    assert K.authority_ok({"verbs": ["v"] * 257, "resources": []}) is False
    assert K.authority_ok({"verbs": [], "resources": [], "limits": {"x": 1}}) is True
    assert K.authority_ok({"verbs": [], "resources": [], "limits": {"x": -1}}) is False


def test_authority_digest_sorts_in_utf16_order():
    astral, bmp = "\U0001F600", "！"   # code-point order puts bmp first, UTF-16 order puts the astral one first
    a = {"verbs": [bmp, astral], "resources": [bmp, astral]}
    want = K.hash_canonical({"d": "atlas-pca/authority/v1", "a": {"verbs": [astral, bmp], "resources": [astral, bmp]}})
    assert K.authority_digest(a) == want


def test_need_approval_garbage_is_bad_request():
    for j in (None, 7, "x", [], {}, {"v": 1}, [None]):
        assert K.verify_need_approval(j, j, j, j, True) == {"ok": False, "code": "bad_request"}
