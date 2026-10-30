"""Mutation kills for provenance by default: every boundary of atlas_pca.arg_provenance pinned with literal expectations (the
token boundary on both sides and for non-ASCII, the trusted-context shortcut, the prev link of receipt 0, the issued_at
direction, the last-receipt binding of verb / resource / params, the pin lookup on mediator AND kid, the floor fallback), plus
one hybrid post-quantum receipt chain."""
import copy
import os

import pytest

from atlas_pca.arg_provenance import (MAX_PROV_CONTENT_BYTES, MAX_PROV_RECEIPTS, PROV_ACTION_DOMAIN, PROV_HEADER, PROV_LEVELS,
                                      PROV_ORIGINS, PROV_RECEIPT_DOMAIN, PROV_RECEIPT_REF_DOMAIN, READ_SAFE_TRAITS,
                                      create_provenance_recorder, decide_arg_provenance, is_prov_mediator_pin,
                                      occurs_as_token, prov_action_info_error, prov_envelope_error, prov_leaves,
                                      prov_receipt_wire_error, read_provenance_bundle)
from atlas_pca.pca import b64u

KEY = bytes([5]) * 32
SESSION = b64u(bytes([6]) * 32)
OP = {"verb": "v", "resource": "r", "params": {"a": "x"}}


def rec(now=lambda: 10):
    return create_provenance_recorder(mediator="m", kid="k", secret_key=KEY, session=SESSION, now=now)


PIN = rec().pin


def decide(bundle, op=OP, pins=None, **kw):
    return decide_arg_provenance(dict({"bundle": bundle, "operation": op, "mediators": [PIN] if pins is None else pins}, **kw))


def principal_only(op=OP, text="x"):
    r = rec()
    r.principal(text)
    return r.for_action(op)


def test_constants():
    assert [PROV_RECEIPT_DOMAIN, PROV_RECEIPT_REF_DOMAIN, PROV_ACTION_DOMAIN, PROV_HEADER] == [
        "atlas-pca/prov-receipt/v1\x00", "atlas-pca/prov-receipt-ref/v1", "atlas-pca/prov-action/v1", "PCA-Provenance"]
    assert [MAX_PROV_RECEIPTS, MAX_PROV_CONTENT_BYTES] == [256, 65536]
    assert PROV_ORIGINS == ("principal", "tool", "retrieval", "web", "action")
    assert PROV_LEVELS == ("trusted", "first_party", "tool", "web", "agent")
    assert READ_SAFE_TRAITS == ("pca.financial_data_read", "pca.pii_access", "pca.regulated_data")


# ---- token boundaries --------------------------------------------------------------------------------------------------
EDGES = [("/", True), ("0", False), ("9", False), (":", True), ("@", True), ("A", False), ("Z", False), ("[", True),
         ("`", True), ("a", False), ("z", False), ("{", True), ("_", False), ("^", True), ("\u007f", True), ("\u0080", False)]


@pytest.mark.parametrize("c,boundary", EDGES)
def test_token_edge_both_sides(c, boundary):
    assert occurs_as_token(c + "x", "x") is boundary
    assert occurs_as_token("x" + c, "x") is boundary


def test_token_needle_edges_and_types():
    assert occurs_as_token("a.b", ".b") is True
    assert occurs_as_token("a.bc", ".b") is False
    assert occurs_as_token("ab.", "b.") is False
    assert occurs_as_token("cb.", "b.") is False
    assert occurs_as_token(" b.", "b.") is True
    assert occurs_as_token(1, "1") is False and occurs_as_token("1", 1) is False and occurs_as_token("x", "") is False


def test_token_non_ascii_in_utf16_code_units():
    assert occurs_as_token("éa", "a") is False and occurs_as_token("aé", "a") is False
    # an astral character is two code units, both word characters: no boundary on either side
    assert occurs_as_token("\U0001F600a", "a") is False and occurs_as_token("a\U0001F600", "a") is False
    assert occurs_as_token("\U0001F600 a", "a") is True
    # a lone high surrogate needle is found inside the pair, but the low surrogate after it is a word unit: no token (as in UTF-16)
    assert occurs_as_token("\U0001F600", "\ud83d") is False and occurs_as_token("\U0001F600 x", "\U0001F600") is True
    # a later occurrence is found after an earlier one fails
    assert occurs_as_token("xa a", "a") is True and occurs_as_token("xa ab", "a") is False


# ---- leaves ------------------------------------------------------------------------------------------------------------

def test_leaves_limits():
    def nest(n):
        return "x" if n == 0 else [nest(n - 1)]
    assert prov_leaves(nest(32)) == ["x"]
    assert prov_leaves(nest(33)) is None
    obj = {"k%d" % i: "v" for i in range(2048)}
    assert len(prov_leaves(obj)) == 4096
    assert prov_leaves(dict(obj, extra="v")) is None
    assert prov_leaves(dict(obj, extra=[])) is None
    assert prov_leaves({"b": 1, "1": True, "a": None}) == ["1", "true", "b", "1", "a", "null"]  # JS key order
    assert prov_leaves(float("nan")) is None and prov_leaves(-0.0) is None and prov_leaves(2 ** 53) is None


# ---- wire bounds -------------------------------------------------------------------------------------------------------

def test_receipt_wire_bounds():
    r = rec().principal("p")
    assert prov_receipt_wire_error(dict(r, mediator="m" * 256)) is None
    assert "mediator" in prov_receipt_wire_error(dict(r, mediator="m" * 257))
    assert prov_receipt_wire_error(dict(r, kid="k" * 64)) is None
    assert "kid" in prov_receipt_wire_error(dict(r, kid="k" * 65))
    assert "source" in prov_receipt_wire_error(dict(r, source="s" * 257))
    assert prov_receipt_wire_error(dict(r, seq=0)) is None
    assert prov_receipt_wire_error(dict(r, issued_at=0)) is None
    assert "issued_at" in prov_receipt_wire_error(dict(r, issued_at=-1))
    assert "v: 1" in prov_receipt_wire_error(dict(r, v=2))
    assert "v: 1" in prov_receipt_wire_error(dict(r, v=True))
    assert "v: 1" in prov_receipt_wire_error(dict(r, kind="x"))
    assert "session" in prov_receipt_wire_error(dict(r, session="x"))
    assert "content_digest" in prov_receipt_wire_error(dict(r, content_digest="x"))
    assert "origin" in prov_receipt_wire_error(dict(r, origin="model"))
    assert "unknown member" in prov_receipt_wire_error(dict(r, extra=1))
    assert prov_receipt_wire_error(dict(r, pq_pk="x")) is not None  # an ed25519 receipt carries no PQ members


def test_action_info_bounds():
    assert prov_action_info_error({"effects": ["e"] * 64}) is None
    assert prov_action_info_error({"effects": ["e"] * 65}) is not None
    assert prov_action_info_error({"traits": ["t" * 128]}) is None
    assert prov_action_info_error({"traits": ["t" * 129]}) is not None
    assert prov_action_info_error({"params": {"p" * 129: "tool"}}) is not None
    assert prov_action_info_error({"params": {"p": "trusted"}}) is not None
    assert prov_action_info_error({"params": []}) is not None
    assert prov_action_info_error({"extra": 1}) is not None
    assert prov_action_info_error(None) is not None


def test_pins_and_envelopes():
    assert is_prov_mediator_pin(dict(PIN, pq_pk="")) is False
    assert is_prov_mediator_pin(dict(PIN, pq_pk="x")) is True
    assert is_prov_mediator_pin(dict(PIN, pq_pk=None)) is False
    assert is_prov_mediator_pin(dict(PIN, kid="")) is False
    assert prov_envelope_error({"mediators": [PIN] * 16}) is None
    assert prov_envelope_error({"mediators": [PIN] * 17}) is not None
    assert prov_envelope_error({"mode": "enforce"}) is None and prov_envelope_error({"mode": "insecure_off"}) is None
    assert prov_envelope_error({"mode": "off"}) is not None
    assert prov_envelope_error({"mediators": [{}]}) is not None
    assert prov_envelope_error({"extra": 1}) is not None
    assert prov_envelope_error(None) is not None


# ---- decision boundaries -----------------------------------------------------------------------------------------------

def test_256_receipts_pass_and_the_recorder_refuses_more():
    r = rec()
    for _ in range(MAX_PROV_RECEIPTS - 1):
        r.principal("x")
    b = r.for_action(OP)
    assert len(b["receipts"]) == 256 and decide(b)["outcome"] == "pass"
    with pytest.raises(ValueError):
        r.for_action(OP)
    big = copy.deepcopy(b)
    big["receipts"].append(big["receipts"][-1])
    assert decide(big)["code"] == "malformed_bundle"
    assert decide(dict(b, receipts=[]))["code"] == "malformed_bundle"


def test_principal_content_size_boundary():
    r = rec()
    r.principal("é" * (MAX_PROV_CONTENT_BYTES // 2))
    r.principal("y" * (MAX_PROV_CONTENT_BYTES + 1))
    b = r.for_action(OP)
    assert list(b["contents"]) == ["0"]
    assert decide(b)["outcome"] == "pass"
    big = copy.deepcopy(b)
    big["contents"] = {"1": "y" * (MAX_PROV_CONTENT_BYTES + 1)}
    assert decide(big)["code"] == "malformed_bundle"


def test_contents_keys_and_digests():
    b = principal_only()
    assert decide(dict(b, contents={"0": "other"}))["code"] == "content_mismatch"
    assert decide(dict(b, contents={"1": "x"}))["code"] == "malformed_bundle"  # the action receipt is not principal
    assert decide(dict(b, contents={"5": "x"}))["code"] == "malformed_bundle"
    assert decide(dict(b, contents={"00": "x"}))["code"] == "malformed_bundle"
    assert decide(dict(b, contents={"0": 1}))["code"] == "malformed_bundle"
    assert decide(dict(b, contents={"0": "\ud800"}))["code"] == "content_mismatch"
    assert decide(dict(b, contents=[]))["code"] == "malformed_bundle"


def test_issued_at_is_non_decreasing_in_this_direction():
    b = principal_only()
    assert b["receipts"][0]["issued_at"] == b["receipts"][1]["issued_at"]
    assert decide(b)["outcome"] == "pass"
    times = iter([10, 9])
    older = rec(now=lambda: next(times))
    older.principal("x")
    ob = older.for_action(OP)  # the recorder never goes back in time
    assert ob["receipts"][1]["issued_at"] == 10 and decide(ob)["outcome"] == "pass"
    forged = copy.deepcopy(b)
    forged["receipts"][1]["issued_at"] -= 1  # the last receipt: the link still holds (the signature is checked later)
    d = decide(forged)
    assert (d["code"], d["reason"]) == ("broken_chain", "receipt 1 is older than its predecessor")
    newer = copy.deepcopy(b)
    newer["receipts"][0]["issued_at"] = 9  # older predecessor: the link breaks, never the time rule
    assert decide(newer)["reason"] != "receipt 1 is older than its predecessor"


def test_prev_of_receipt_zero_is_null():
    b = copy.deepcopy(principal_only())
    b["receipts"][0]["prev"] = b["receipts"][0]["content_digest"]
    d = decide(b)
    assert (d["code"], d["reason"]) == ("broken_chain", "receipt 0 does not link to its predecessor")


def test_a_gap_in_seq_is_a_broken_chain():
    b = copy.deepcopy(principal_only())
    b["receipts"][1]["seq"] = 2
    d = decide(b)
    assert (d["code"], d["reason"]) == ("broken_chain", "receipt 1 has seq 2")


@pytest.mark.parametrize("op2", [dict(OP, verb="w"), dict(OP, resource="s"), dict(OP, params={"a": "y"}), dict(OP, params={})])
def test_last_receipt_binds_verb_resource_and_params(op2):
    d = decide(principal_only(), op=op2)
    assert (d["outcome"], d["code"]) == ("deny", "unbound_action")


def test_the_last_receipt_must_be_the_action():
    r = rec()
    r.principal("x")
    b = r.for_action(OP)
    b2 = dict(b, receipts=b["receipts"][:1])
    assert decide(b2)["code"] == "unbound_action"


def test_pin_matches_mediator_and_kid_first_match_wins():
    b = principal_only()
    assert decide(b, pins=[dict(PIN, pk=rec().pin["pk"])])["verified"] is True
    assert decide(b, pins=[dict(PIN, pk=b64u(bytes(32))), PIN])["code"] == "bad_signature"
    other_kid = decide(b, pins=[dict(PIN, kid="k2")])
    other_med = decide(b, pins=[dict(PIN, mediator="m2")])
    for d in (other_kid, other_med):
        assert (d["outcome"], d["verified"], d["path"]) == ("escalate", False, ["unlabelled"])


def test_trusted_context_shortcut_and_an_observed_tool_raises_it():
    op = {"verb": "v", "resource": "r", "params": {"a": "never-typed"}}
    b = principal_only(op, text="do it")
    d = decide(b, op=op)
    assert (d["outcome"], d["control"], d["labels"]) == ("pass", "trusted", {"a": "trusted"})
    d = decide(b, op=op, observed=[{"origin": "tool", "source": "t"}])
    assert (d["outcome"], d["code"], d["control"], d["labels"], d["path"]) == (
        "escalate", "untrusted_control_and_args", "tool", {"a": "tool"}, ["tool:t"])
    d = decide(b, op=op, observed=[{"origin": "retrieval", "source": "r1"}])
    assert d["labels"] == {"a": "tool"}
    assert decide(b, op=op, observed=[{"origin": "principal", "source": "x"}])["code"] == "malformed_config"


def test_floor_fallback_for_sensitive_and_read_only():
    def d(action):
        r = rec()
        r.tool("t", "x")
        kw = {"principal_control": True}
        if action is not None:
            kw["action"] = action
        return decide(r.for_action(OP), **kw)
    assert d({"effects": ["read"]})["tainted"] == []
    assert d({"effects": ["read"], "params": {"a": "first_party"}})["tainted"] == ["a"]
    assert d({"effects": ["send"]})["tainted"] == ["a"]
    assert d(None)["tainted"] == ["a"]
    assert d({"effects": ["send"], "params": {"a": "tool"}})["tainted"] == []
    assert d({"effects": ["send"], "params": {"a": "agent"}})["tainted"] == []
    assert d({"effects": ["send"], "params": {"b": "agent"}})["tainted"] == ["a"]


def test_read_only_never_escalates_on_control_alone():
    d = decide(None, op=dict(OP, params={}), action={"effects": ["read"]})
    assert (d["outcome"], d["sensitive"], d["control"]) == ("pass", False, "agent")


def test_reason_text_derives_derive_and_brackets():
    two = {"verb": "v", "resource": "r", "params": {"a": "x", "b": "y"}}
    r = rec()
    r.tool("t", "x")
    assert decide(r.for_action(two), op=two, principal_control=True)["reason"] == \
        "a, b derive from untrusted content [tool:t]: the principal must confirm (prompt-injection path)"
    r2 = rec()
    r2.tool("t", "x")
    assert decide(r2.for_action(OP), principal_control=True)["reason"] == \
        "a derives from untrusted content [tool:t]: the principal must confirm (prompt-injection path)"


def test_path_sorted_and_deduplicated():
    r = rec()
    r.web("z", "x")
    r.tool("b", "x")
    r.tool("b", "y")
    d = decide(r.for_action(OP), observed=[{"origin": "retrieval", "source": "a"}, {"origin": "tool", "source": "b"}])
    assert d["path"] == ["retrieval:a", "tool:b", "web:z"]


def test_verbatim_match_needs_the_stored_principal_content():
    r = rec()
    r.principal("send x")
    r.tool("t", "y")
    b = r.for_action(OP)
    assert decide(b, principal_control=True)["outcome"] == "pass"
    no_contents = {k: v for k, v in b.items() if k != "contents"}
    assert decide(no_contents, principal_control=True)["tainted"] == ["a"]


def test_principal_plan_trusts_everything_principal_control_only_the_choice():
    r = rec()
    r.web("w", "x")
    b = r.for_action(OP)
    assert decide(b, principal_plan=True)["outcome"] == "pass"
    d = decide(b, principal_control=True)
    assert (d["outcome"], d["code"], d["control"]) == ("escalate", "untrusted_args", "trusted")
    assert decide(b, principal_plan=1)["outcome"] == "escalate"  # only True counts


def test_malformed_inputs_deny_with_defaults():
    for inp, code in [(None, "malformed_config"), ({"mediators": "x", "operation": OP}, "malformed_config"),
                      ({"mediators": [], "operation": {"verb": "", "resource": "r", "params": {}}}, "malformed_operation"),
                      ({"mediators": [], "operation": {"verb": "v", "resource": 1, "params": {}}}, "malformed_operation"),
                      ({"mediators": [], "operation": OP, "action": None}, "malformed_action"),
                      ({"mediators": [], "operation": OP, "observed": "x"}, "malformed_config")]:
        d = decide_arg_provenance(inp)
        assert (d["outcome"], d["code"], d["sensitive"], d["verified"], d["control"], d["labels"], d["tainted"], d["path"]) == (
            "deny", code, True, False, "agent", {}, [], [])
    # a deny after the sensitivity step keeps it (read-only facts, forged chain)
    b = copy.deepcopy(principal_only())
    b["receipts"][1]["seq"] = 7
    assert decide(b, action={"effects": ["read"]})["sensitive"] is False


def test_bundle_reader():
    b = principal_only()
    import json as _json
    hdr = {"pca-provenance": b64u(_json.dumps(b).encode("utf-8"))}
    assert read_provenance_bundle(hdr, None) == b
    assert read_provenance_bundle({}, _json.dumps({"pca_provenance": b})) == b
    assert read_provenance_bundle({}, b"not json") is None and read_provenance_bundle({}, None) is None
    assert read_provenance_bundle({"PCA-Provenance": ""}, None) is None
    with pytest.raises(ValueError):
        read_provenance_bundle({"PCA-Provenance": "%%%"}, None)
    with pytest.raises(ValueError):
        read_provenance_bundle({"PCA-Provenance": b64u(b"{not json")}, None)


# ---- a hybrid post-quantum receipt chain -------------------------------------------------------------------------------

def test_hybrid_pq_receipt_chain_verifies_only_under_the_pinned_pq_key():
    from atlas_pca import pq_backends
    from atlas_pca.agent import UnsupportedSuite, generate_pq_keypair
    if not pq_backends.available("ML-DSA-65"):
        if os.environ.get("PCA_REQUIRE_PQ") == "1":
            pytest.fail("PCA_REQUIRE_PQ=1 but no ML-DSA-65 backend")
        pytest.skip("no ML-DSA-65 backend in this runtime")
    try:
        pq = generate_pq_keypair("ML-DSA-65")
    except UnsupportedSuite as e:  # pragma: no cover - a backend that verifies but cannot sign
        pytest.skip(str(e))
    r = create_provenance_recorder(mediator="m", kid="k", secret_key=KEY, session=SESSION, now=lambda: 10,
                                   alg="hybrid-ed25519-ml-dsa-65", pq=pq)
    r.principal("send x")
    b = r.for_action(OP)
    assert r.pin["pq_pk"] == pq.public and all(x["alg"] == "hybrid-ed25519-ml-dsa-65" and "pq_sig" in x for x in b["receipts"])
    assert decide(b, pins=[r.pin])["outcome"] == "pass"
    # the Ed25519 half alone is not enough: without the pinned PQ key the hybrid receipt does not verify
    assert decide(b, pins=[{k: v for k, v in r.pin.items() if k != "pq_pk"}])["code"] == "bad_signature"
    other = generate_pq_keypair("ML-DSA-65")
    assert decide(b, pins=[dict(r.pin, pq_pk=other.public)])["code"] == "bad_signature"
    tampered = copy.deepcopy(b)
    tampered["receipts"][-1]["pq_sig"] = tampered["receipts"][0]["pq_sig"]  # the last receipt: no later prev link breaks first
    assert decide(tampered, pins=[r.pin])["code"] == "bad_signature"


def test_clip_halves_by_utf16_units_and_refuses_a_split_pair():
    from atlas_pca.arg_provenance import _clip
    E, F = "\u00e9", "\U0001F600"
    assert _clip("a" * 300) == "a" * 150
    assert _clip("a" * 256) == "a" * 256
    assert _clip("") == "-"
    assert _clip(E * 100 + F * 41 + "b") == E * 91
    assert _clip(F * 64 + E) == F * 32
    with pytest.raises(ValueError):
        _clip(F * 50 + E * 30 + "x")
