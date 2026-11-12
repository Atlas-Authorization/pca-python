"""Kill tests (attest_common, attest_intel, attest_xml, intent_map, ledger, pq_backends, predicates, safe_regex, actions,
actions_registry): exact messages, argument hand-offs and early exits the existing suites do not pin."""
import collections
from collections import OrderedDict

import pytest

from atlas_pca import actions as AC
from atlas_pca import actions_registry as AR
from atlas_pca import attest_common as C
from atlas_pca import intent_map as M
from atlas_pca import ledger as LG
from atlas_pca import predicates as PR
from atlas_pca import pq_backends as PB
from atlas_pca import safe_regex as SR


# ---- attest_common

def test_blank_json_is_the_end_of_input():
    for t in ("", " ", " \t\r\n "):
        with pytest.raises(C.JsError) as e:
            C.js_json_loads(t)
        assert str(e.value) == "Unexpected end of JSON input", repr(t)


def test_trailing_comma_names_the_closing_bracket(monkeypatch):
    import json
    with pytest.raises(C.JsError) as e:
        C.js_json_loads("[1,]")
    assert "Unexpected token ']'" in str(e.value)

    # Python 3.13 reports "Illegal trailing comma" at the comma; older versions never do, so script it
    def boom(*a, **k):
        raise json.JSONDecodeError("Illegal trailing comma before end of array", "[1,]", 2)

    monkeypatch.setattr(C.json, "loads", boom)
    with pytest.raises(C.JsError) as e:
        C.js_json_loads("[1,]")
    assert "Unexpected token ']'" in str(e.value)

    def boom2(*a, **k):
        raise json.JSONDecodeError("Illegal trailing comma before end of array", "[1, ]", 2)

    monkeypatch.setattr(C.json, "loads", boom2)  # one blank between the comma and the bracket: skipped exactly once
    with pytest.raises(C.JsError) as e:
        C.js_json_loads("[1, ]")
    assert "Unexpected token ']'" in str(e.value)


def test_result_merges_its_keywords():
    assert C.result(True, a=1, b="x") == {"ok": True, "a": 1, "b": "x"}
    assert C.result(False) == {"ok": False}


def test_key_type_names_an_ec_key():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ec
    assert C.key_type(ec.generate_private_key(ec.SECP256R1()).public_key()) == "ec"

    class Fake:  # recognised by isinstance only: its class name would not reduce to "ec"
        pass

    ec.EllipticCurvePublicKey.register(Fake)
    assert C.key_type(Fake()) == "ec"


def test_big_int_refusals_name_the_value():
    for v, text in ((None, "null"), ("abc", "abc"), ("1.5", "1.5"), (1.5, "1.5"), ({}, "[object Object]")):
        with pytest.raises(C.JsError) as e:
            C.big_int(v)
        assert str(e.value) == "Cannot convert %s to a BigInt" % C.js_str(v), v


# ---- attest_intel

def test_signer_chain_is_checked_at_the_supplied_clock():
    pytest.importorskip("cryptography")
    from atlas_pca import attest_intel as AI
    from test_k05_kill_intel import _chain, _ms, _pem, _pin
    root, inter, leaf = _chain()
    pem = "".join(_pem(d) for d in (leaf, inter, root))
    assert AI._signer_key_from_chain(pem, _pin(), _ms(2024, 12, 31), set()) == {"error": "issuer chain certificate outside its validity period"}


def test_signer_chain_uses_the_supplied_clock_not_the_wall_clock(monkeypatch):
    pytest.importorskip("cryptography")
    import time
    from atlas_pca import attest_intel as AI
    from test_k05_kill_intel import _chain, _ms, _pem, _pin
    root, inter, leaf = _chain()
    pem = "".join(_pem(d) for d in (leaf, inter, root))
    monkeypatch.setattr(time, "time", lambda: 4_102_444_800)  # 2100: past every certificate
    assert "key" in AI._signer_key_from_chain(pem, _pin(), _ms(2026, 6, 1), set())


def test_tdx_module_advisories_are_reported():
    pytest.importorskip("cryptography")
    from test_k05_kill_attest_intel import _ev, _ident, _lvl
    ident = _ident(tcbLevels=[{"tcb": {"isvsvn": 0}, "tcbStatus": "UpToDate", "advisoryIDs": ["INTEL-SA-9"]}])
    assert _ev([_lvl()], minor=1, tdxModuleIdentities=[ident]) == {"platform": "UpToDate", "module": "UpToDate", "advisories": ["INTEL-SA-9"]}


def test_tdx_seam_attributes_are_the_eight_bytes_at_112(monkeypatch):
    pytest.importorskip("cryptography")
    from atlas_pca import attest_intel as AI
    from test_k05_kill_intel import _real, _vcol
    q = _real()[0]
    seen = []
    monkeypatch.setattr(AI, "_evaluate_tcb", lambda info, pck, td: seen.append(td) or {"error": "stop"})
    _vcol()
    body = AI.parse_dcap_quote(q)["tdReportBody"]
    assert len(seen) == 1 and seen[0]["seamAttributes"] == body[112:120] and len(seen[0]["seamAttributes"]) == 8


# ---- attest_xml

def test_xml_whitespace_after_a_doctype_is_text_outside_the_root():
    from atlas_pca import attest_xml as X
    d = X.parse_xml("<!DOCTYPE r>\n<r/>")
    assert d.violations == ["DTD / DOCTYPE is not permitted"] and d.root.qname == "r"


# ---- intent_map

def test_an_exact_value_wins_over_a_later_prefix():
    h = {"verb": "v", "first": 1, "cells": 3, "dims": [{"kind": "cat", "path": "action.resource", "values": [
        {"kind": "exact", "value": "ab"}, {"kind": "prefix", "value": "a"}, {"kind": "other", "value": "z"}]}]}
    assert M.map_cell_of(h, "ab", {}) == {"cell": [0], "flat": 0}
    assert M.map_cell_of(h, "ac", {}) == {"cell": [1], "flat": 1}


# ---- ledger

def test_consistency_with_an_undecodable_old_root_is_refused():
    from atlas_pca.pca import b64u
    proof = {"oldSize": 4, "newSize": 8, "path": [b64u(bytes(32))]}
    assert LG.verify_ledger_consistency("!", b64u(bytes(32)), proof) is False


def test_witness_threshold_stops_at_the_first_quorum(monkeypatch):
    calls = []
    monkeypatch.setattr(LG, "verify_witness_cosignature", lambda *a: calls.append(a) or True)
    sth = {"witnesses": [{"key": "a", "sig": "s"}, {"key": "b", "sig": "s"}, {"key": "c", "sig": "s"}]}
    assert LG.verify_witness_cosignatures(sth, {"threshold": 1, "witnessKeys": ["a", "b", "c"]}) is True
    assert len(calls) == 1


# ---- pq_backends

def test_the_less_library_is_resolved_once(monkeypatch):
    n = []
    monkeypatch.setattr(PB, "_less_tried", False)
    monkeypatch.setattr(PB, "_less", None)
    monkeypatch.setattr(PB, "_less_candidates", lambda: n.append(1) or [])
    PB._libless()
    PB._libless()
    assert len(n) == 1


# ---- predicates

def test_deep_equality_refuses_a_non_string_key():
    with pytest.raises(PR._NotCanonical):
        PR._jeq({1: 1}, {1: 1}, 0)


# ---- safe_regex

def test_an_exploding_repeat_is_refused_while_it_is_emitted():
    assert SR.compile_safe_regex("((((a{64}){64}){64}){64}){64}") is None


def test_the_regex_cache_evicts_the_least_recently_used(monkeypatch):
    monkeypatch.setattr(SR, "_cache", OrderedDict())
    for i in range(SR.REGEX_CACHE_MAX_ENTRIES):
        SR.compile_safe_regex_cached("k%d" % i)
    SR.compile_safe_regex_cached("k0")           # a hit refreshes k0
    SR.compile_safe_regex_cached("k-new")        # evicts the oldest, which is now k1
    assert "k0" in SR._cache and "k1" not in SR._cache and "k-new" in SR._cache


# ---- actions

def test_closure_expands_each_trait_once():
    class Reg(dict):
        def __init__(self, *a):
            super().__init__(*a)
            self.gets = collections.Counter()

        def get(self, k, d=None):
            self.gets[k] += 1
            return super().get(k, d)

    reg = Reg({"x.t0": {"implies": []}, "x.t1": {"implies": ["x.t0"]}, "x.t2": {"implies": ["x.t0"]}, "x.t3": {"implies": ["x.t1", "x.t2"]}})
    assert AC.closure(reg, ["x.t3"]) == ["x.t0", "x.t1", "x.t2", "x.t3"]
    assert reg.gets["x.t0"] == 1


def test_json_copy_is_deep():
    v = {"a": [1, {"b": 2}], "c": {"d": [3]}}
    c = AC._json_copy(v)
    assert c == v and c is not v and c["a"] is not v["a"] and c["a"][1] is not v["a"][1] and c["c"]["d"] is not v["c"]["d"]


def test_reapproval_is_false_when_the_signature_check_faults(monkeypatch):
    r = {"v": 1, "kind": AR.REAPPROVAL_KIND, "grant": "g", "verb": "v", "diff": "d", "sig": {"alg": "ed25519", "value": "x"}}

    def boom(*a):
        raise RuntimeError("boom")

    monkeypatch.setattr(AR, "_pinned_suite_error", boom)
    assert AR.reapproval_valid(r, "g", "issuer", "v", "d") is False
