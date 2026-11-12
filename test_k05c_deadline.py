"""Deadline and unbounded-recursion kill tests for the loops, recursions and allocations a mutant could stop from terminating.

A mutation run counts a timeout, a RecursionError or a MemoryError as a run error: no test decided it (BRIEF: timeouts are
not kills). Every test here calls the unmutated function on an input that reaches the loop and demands that it finishes
inside a hard wall-clock deadline with the exact answer; a mutant that no longer advances its loop variable, loses a
recursion base case or grows a list without bound fails the test (a decided failure) instead of timing out."""
import importlib
import signal

import pytest

DEADLINE_S = 1.5  # the unmutated functions below take milliseconds; this only trips on a non-terminating mutant


class _Deadline(BaseException):  # not an Exception: the code under test has `except Exception` fallbacks that must not swallow the alarm
    pass


def bounded(fn, *a, _secs=DEADLINE_S, **kw):
    """Run fn under a wall-clock alarm. A non-terminating run, a RecursionError or a MemoryError is a plain test failure
    raised OUTSIDE the except block (so the failure carries no crash exception as its context)."""
    def _alarm(_s, _f):
        raise _Deadline()

    if not hasattr(signal, "SIGALRM"):  # Windows: no alarm, the call simply runs (mutation runs are Linux)
        return fn(*a, **kw)
    prev = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, _secs)
    problem = None
    out = None
    try:
        out = fn(*a, **kw)
    except (_Deadline, RecursionError, MemoryError) as e:
        problem = type(e).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)
    if problem is not None:
        pytest.fail("did not terminate within the deadline (%s)" % problem, pytrace=False)
    return out


# ---------------------------------------------------------------------------------------------------- safe_regex

from atlas_pca import safe_regex as sr  # noqa: E402

_PATTERNS = [
    "abc", "a|b|c", "ab|cd|ef", "a*", "a+", "a?", "a{2,3}", "a{2}", "a{2,}", "a*?", "a+?b", "a??", "(?:ab)+c", "(ab|cd)e",
    "ab.c", "ab^c", "ab$c", "ab[c]d", "ab\\dc", "ab(c)d", "ab(?:c)d", "[a-c]x", "[^a]b", "[\\d-z]q", "[\\]a]b", "[a\\-z]c", ".x", "^ab$", "\\d\\w\\s\\D\\W\\S", "\\t\\n\\v\\f\\r\\0",
    "\\x41\\u0042\\cA", "\\.\\*\\+", "[\\b\\x41\\u0042\\cA]x",
]


def test_every_parser_advance_terminates():
    for p in _PATTERNS:
        assert bounded(sr.compile_safe_regex, p) is not None, p


def test_empty_classes_are_parsed_to_the_end():
    for p in ("[]", "a[]", "[^]", "x[^]y"):  # only that the parser ends (the verdict is not pinned here)
        assert bounded(sr.compile_safe_regex, p) is None or True


def test_parser_tail_positions():
    for p in ["a{2,3}b{1,2}c{4}", "(?:a(?:b|c)d)e", "((a)(b))c", "x*y+z?w{1,2}"]:
        assert bounded(sr.compile_safe_regex, p) is not None, p
    for p in ["[ab", "(ab", "a{2", "\\x4", "\\u00", "\\c1", "a)"]:
        assert bounded(sr.compile_safe_regex, p) is None, p


def test_charset_binary_search_terminates():
    cs = sr.CharSet(sr.WORD, False)
    for c in (0x30, 0x35, 0x39, 0x41, 0x5A, 0x5F, 0x61, 0x7A):
        assert bounded(cs.has, c) is True, c
    for c in (0x00, 0x2F, 0x3A, 0x40, 0x5B, 0x60, 0x7B, 0xFFFF):
        assert bounded(cs.has, c) is False, c
    assert bounded(sr.CharSet(sr.WORD, True).has, 0x2F) is True


def test_lone_surrogate_scan_terminates():
    assert bounded(sr.units_have_lone_surrogate, "abcd") is False
    assert bounded(sr.units_have_lone_surrogate, "ab" + chr(0xD83D) + chr(0xDE00) + "cd") is False
    assert bounded(sr.units_have_lone_surrogate, "abc\ud83d") is True
    assert bounded(sr.units_have_lone_surrogate, "a\ude00bc") is True


def test_matcher_epsilon_cycle_terminates():
    # (?:a*)* has an empty loop: add() must mark each pc once per generation or it spins on the jump cycle
    rx = bounded(sr.compile_safe_regex, "(?:a*)*")
    assert rx is not None
    assert bounded(sr.run_safe_regex, rx, "aaa") is True
    assert bounded(sr.run_safe_regex, rx, "aab") is False
    rx = bounded(sr.compile_safe_regex, "(?:a|b*)*c")
    assert bounded(sr.run_safe_regex, rx, "abbac") is True


def test_cache_evicts_to_its_bound():
    def fill():
        for i in range(sr.REGEX_CACHE_MAX_ENTRIES + 5):
            sr.compile_safe_regex_cached("k05c%d" % i)
        return len(sr._cache)
    assert bounded(fill) <= sr.REGEX_CACHE_MAX_ENTRIES


# ---------------------------------------------------------------------------------------------------- predicates

from atlas_pca import predicates as pr  # noqa: E402

_SAFE_SOURCES = [
    "abcd", "a(b)c", "((a))b", "xy(z)w", "\\d\\w\\s\\S", "[abc][^d]e", "[\\]a]bc", "[^\\]]bc", "(?:ab|cd)ef", "(ab)cd", "a|b|c", "a*bc", "a+?bc", "a?bc",
    "a{2,3}bc", "a{2}bc", "x(?:y|z)w", "(a(?:b|c)d)e",
]


def test_safe_regex_source_scan_terminates():
    for s in _SAFE_SOURCES:
        assert bounded(pr._is_safe_regex_source, pr.to_units(s), s) is True, s
    for s in ["[]", "a[]b", "[^]"]:  # an empty class: only that the scan ends
        assert bounded(pr._is_safe_regex_source, pr.to_units(s), s) in (True, False), s
    for s in ["a**", "(a+)+", "\\1a", "a{3,2}", "(?=a)b", "[ab"]:
        assert bounded(pr._is_safe_regex_source, pr.to_units(s), s) is False, s


def test_glob_tokeniser_and_matcher_terminate():
    assert bounded(pr._parse_glob, "a*b?\\*c**d") == [
        ("lit", "a"), ("star",), ("lit", "b"), ("one",), ("lit", "*"), ("lit", "c"), ("star",), ("lit", "d")]
    assert bounded(pr._parse_glob, "ab\\") is None
    assert bounded(pr._glob_match, "a*b*c", "aXXbYYc") is True
    assert bounded(pr._glob_match, "a*b*c", "aXXbYY") is False
    assert bounded(pr._glob_match, "*a?c*", "zzabcyy") is True
    assert bounded(pr._glob_match, "a*", "abcdef") is True
    assert bounded(pr._glob_match, "*x", "abcdef") is False
    assert bounded(pr._glob_match, "abc", "abc") is True


def test_deep_not_chain_is_unwound_iteratively():
    # 1500 nested `not` over a true leaf: the reference decides it (even count -> true); recursing instead would hit the
    # interpreter limit and turn the verdict into unknown
    leaf = {"field": "action.params.x", "op": "exists"}
    ctx = {"action": {"verb": "read", "resource": "/r", "params": {"x": 0}}, "env": {}}
    for depth, want in ((1500, "true"), (1501, "false")):
        c = leaf
        for _ in range(depth):
            c = {"not": c}
        assert bounded(pr.evaluate_condition_tri, c, ctx) == want, depth


# ---------------------------------------------------------------------------------------------------- Merkle shapes

import hashlib  # noqa: E402

from atlas_pca import actions as AC  # noqa: E402
from atlas_pca import agent as AG  # noqa: E402
from atlas_pca import intent_map as IM  # noqa: E402
from atlas_pca import ledger as LG  # noqa: E402
from atlas_pca import pca as P  # noqa: E402
PG = importlib.import_module("atlas_pca.provenance_gate")  # the package binds a function of that name
from atlas_pca.pca import b64u, decode_b64u_strict  # noqa: E402


def _hs(n):
    return [hashlib.sha256(b"k05c-leaf-%d" % i).digest() for i in range(n)]


def _split(n):  # RFC 6962: the largest power of two strictly below n
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(hs, node):
    if len(hs) == 1:
        return hs[0]
    k = _split(len(hs))
    return node(_mth(hs[:k], node), _mth(hs[k:], node))


def _incl(m, hs, node):  # RFC 6962 PATH(m, D), bottom-up
    if len(hs) == 1:
        return []
    k = _split(len(hs))
    if m < k:
        return _incl(m, hs[:k], node) + [_mth(hs[k:], node)]
    return _incl(m - k, hs[k:], node) + [_mth(hs[:k], node)]


def _cons(m, hs, b, node):  # RFC 6962 SUBPROOF(m, D, b)
    n = len(hs)
    if m == n:
        return [] if b else [_mth(hs, node)]
    k = _split(n)
    if m <= k:
        return _cons(m, hs[:k], b, node) + [_mth(hs[k:], node)]
    return _cons(m - k, hs[k:], False, node) + [_mth(hs[:k], node)]


def test_split_and_roots_terminate_and_agree_with_rfc6962():
    for fn in (P._split, IM._split):
        assert [bounded(fn, n) for n in (1, 2, 3, 4, 5, 8, 9, 17)] == [1, 1, 2, 2, 4, 4, 8, 16]
    for n in range(1, 18):
        h = _hs(n)
        want = _mth(h, P._node_hash)
        assert bounded(P._build, h) == want, n
        assert bounded(AC._subroot, h) == want, n
        assert bounded(IM._tree_root, h) == _mth(h, IM.map_node_hash), n


def test_path_shape_terminates_and_matches_the_audit_path():
    assert bounded(P._path_shape, 0, 1) == []
    assert bounded(P._path_shape, 4, 5) == ["L"]
    assert bounded(P._path_shape, 0, 5) == ["R", "R", "R"]
    assert bounded(P._path_shape, 3, 4) == ["L", "L"]
    for n in range(1, 18):
        for i in range(n):
            assert len(bounded(P._path_shape, i, n)) == len(_incl(i, _hs(n), P._node_hash))


def test_agent_prove_and_map_audit_path_terminate_and_verify():
    for n in range(1, 14):
        h = _hs(n)
        root = _mth(h, P._node_hash)
        for i in range(n):
            out = []
            bounded(AG._prove, h, i, out)
            r = h[i]
            for st in out:
                sib = decode_b64u_strict(st["hash"], 32)
                r = P._node_hash(sib, r) if st["side"] == "L" else P._node_hash(r, sib)
            assert r == root, (n, i)
            raw = []
            bounded(IM._audit_path, h, i, raw)
            assert raw == _incl(i, h, IM.map_node_hash), (n, i)


def test_map_root_from_path_terminates_for_every_index():
    for n in range(1, 40):
        h = _hs(n)
        root = _mth(h, IM.map_node_hash)
        for i in range(n):
            path = _incl(i, h, IM.map_node_hash)
            assert bounded(IM.map_root_from_path, i, n, h[i], path) == root, (i, n)


def test_rfc9162_inclusion_and_consistency_terminate():
    for n in range(1, 18):
        h = _hs(n)
        root = _mth(h, PG._node)
        for i in range(n):
            assert bounded(PG.verify_rfc9162_inclusion, h[i], i, n, _incl(i, h, PG._node), root) is True, (i, n)
    h = _hs(12)
    for second in range(1, 13):
        for first in range(1, second + 1):
            old, new = _mth(h[:first], P._node_hash), _mth(h[:second], P._node_hash)
            proof = {"oldSize": first, "newSize": second, "path": [b64u(x) for x in _cons(first, h[:second], True, P._node_hash)]}
            assert bounded(LG.verify_ledger_consistency, b64u(old), b64u(new), proof) is True, (first, second)
    bad = dict(proof, path=[b64u(bytes(32))] + proof["path"][1:])
    assert bounded(LG.verify_ledger_consistency, b64u(old), b64u(new), bad) is False


# ---------------------------------------------------------------------------------------------------- strict JSON

import json  # noqa: E402


def test_strict_json_parser_terminates_on_every_token_kind():
    obj = {"a\nA\U0001F600\\\"/\b\f\r\t": [1, -2, 1.5, {"k": None, "t": True, "f": False}, "x y"], "z": {}, "e": []}
    text = " \n\t" + json.dumps(obj) + "\r\n"
    assert bounded(P.strict_parse, text) == obj
    assert bounded(P.strict_parse, '"a\\/b\\u0041\\ud83d\\ude00"') == "a/bA\U0001F600"
    for bad in ('"abc\\', '"a\\ud83d"', '"a\\ud83d\\u0041"', '"ab', '{"a":1,}', '[1 2]', '{"a" 1}', 'tru', '"\\x"', '[1,'):
        with pytest.raises(P.StrictJsonError):
            bounded(P.strict_parse, bad)
    assert bounded(P.strict_parse, "[true, false, null]") == [True, False, None]


def test_existing_strict_parse_cases_terminate():
    import test_mutation_kill_a as T
    for t in (T.test_strict_parse_backslash_at_end, T.test_strict_parse_escaped_pair_bounds, T.test_strict_parse_raw_surrogates):
        bounded(t, _secs=10)
    import test_mutation_extra as E
    bounded(E.test_merkle_and_shape, _secs=10)


def test_js_json_loads_literal_scan_terminates():
    from atlas_pca import attest_common as C
    for bad in ('{"a":tru}', '{"a":nul}', '[fals]', '{"a":trux}'):
        with pytest.raises(C.JsError):
            bounded(C.js_json_loads, bad)


# ---------------------------------------------------------------------------------------------------- recursion / helpers

def test_js_string_of_nested_lists_terminates():
    from atlas_pca import intent_v2 as IV
    assert bounded(IV._js_string, [1, [2, 3], None, "x", []]) == "1,2,3,,x,"
    assert bounded(IV._js_string, [[["a"]], "b"]) == "a,b"


def test_workflow_ancestors_and_registry_cycle_terminate():
    from atlas_pca import workflow as WF
    steps = [{"id": "a", "deps": []}, {"id": "b", "deps": ["a"]}, {"id": "c", "deps": ["a", "b"]}, {"id": "d", "deps": ["c", "b"]}]
    assert bounded(WF.ancestors, {"steps": steps}) == {"a": set(), "b": {"a"}, "c": {"a", "b"}, "d": {"a", "b", "c"}}
    assert bounded(WF.ancestors, {"steps": [{"id": "x", "deps": ["y"]}, {"id": "y", "deps": ["x"]}]}) is None
    assert bounded(WF.ancestors, {"steps": [{"id": "x", "deps": ["x"]}]}) is None
    import test_k05_kill_workflow as W
    bounded(W.test_ancestors_visits_each_step_once, _secs=10)
    import test_k05_kill_actions as K
    bounded(K.test_registry_depth_cycle_and_diamond, _secs=10)
    bounded(K.test_decide_pin_removed_and_added_records_never_chain, _secs=10)
    bounded(K.test_decide_pin_first_parent_wins_in_a_blocked_diamond, _secs=10)


def test_existing_cases_that_recursed_or_spun_terminate():
    import test_k05_kill_agent as A
    bounded(A.test_agent_act_headers_and_options, _secs=10)
    import test_k05_parity_audit as PA
    bounded(PA.test_empty_merkle_inputs_raise_instead_of_recursing, _secs=10)
    import test_k05_kill_intent as KI
    bounded(KI.test_prov_clip_counts_utf16_units, _secs=10)
    import test_k042_server_units as SU
    bounded(SU.test_intent_v2_callable_failure_result, _secs=10)
    import test_k042_pred_tail as PT
    bounded(PT.test_glob_tokeniser, _secs=10)
    import test_k05_kill_attest_intel as KT
    bounded(KT.test_tcb_levels_compare_tdx_components_from_the_right_index, _secs=10)
    bounded(KT.test_tcb_levels_compare_every_sgx_component_and_continue_past_a_miss, _secs=10)
    import test_k05_kill_attest_nv as NV
    bounded(NV.test_spdm_opaque_entry_that_fills_the_data_exactly, _secs=10)


def test_clip_halving_terminates():
    from atlas_pca import arg_provenance as AP
    assert bounded(AP._clip, "a" * 1000) == "a" * 250
    assert bounded(AP._clip, "\U0001F600" * 200) == "\U0001F600" * 50
    assert bounded(AP._clip, "") == "-"
    assert bounded(AP._clip, "ok") == "ok"


def test_occurs_as_token_scan_terminates():
    from atlas_pca import arg_provenance as AP
    assert bounded(AP.occurs_as_token, "afoo foob foo", "foo") is True
    assert bounded(AP.occurs_as_token, "afoo foob _foo", "foo") is False
    assert bounded(AP.occurs_as_token, "foo", "foo") is True


def test_ocsp_strip_zeros_terminates():
    from atlas_pca import attest_ocsp as O
    assert bounded(O._strip_zeros, b"\x00\x00\x01\x00") == b"\x01\x00"
    assert bounded(O._strip_zeros, b"\x00\x00\x00") == b"\x00"
    assert bounded(O._strip_zeros, b"\x05") == b"\x05"


def test_intel_raw_json_object_scan_terminates():
    from atlas_pca import attest_intel as I
    text = '{"tcbInfo": {"a":"x\\"}","b":{"c":1}}, "signature":"ab"}'
    assert bounded(I._raw_json_object, text, "tcbInfo") == '{"a":"x\\"}","b":{"c":1}}'
    assert bounded(I._raw_json_object, '{"tcbInfo": {"a":1', "tcbInfo") is None
    assert bounded(I._raw_json_object, '{"other": {}}', "tcbInfo") is None


def test_xml_parser_and_unescape_terminate_on_every_construct():
    from atlas_pca import attest_xml as X
    got = bounded(X.parse_xml, '<?xml version="1.0"?><!-- c --><!DOCTYPE r [<!ENTITY a "b">]>'
                  '<r a="x &amp; y&#65;&#x42;" b=\'q\'>t &lt;&#65;&#x42;<![CDATA[raw<]]><c/><d>z</d></r>\n  ')
    assert got.violations == ["XML processing instructions are not permitted", "XML comments are not permitted",
                              "DTD / DOCTYPE is not permitted"]
    assert got.root.qname == "r"
    assert got.root.get_attribute("a") == "x & yAB" and got.root.get_attribute("b") == "q"
    assert got.root.text_content() == "t <ABraw<z"
    for bad in ("<a><!-- x", "<a><?pi", "<a><![CDATA[x", "<!DOCTYPE a [", "<a b='c", "text<a/>"):
        with pytest.raises(X.XmlError):
            bounded(X.parse_xml, bad)
    assert bounded(X._unescape, "a&amp;b&#65;c&#x42;d&lt;e", False) == "a&bAc" + "Bd<e"
    assert bounded(X._unescape, "t\tu\r\nv", True) == "t u  v"


# ---------------------------------------------------------------------------------------------------- stores / samplers

def test_sqlite_kv_honours_its_busy_timeout_and_commits(tmp_path):
    import sqlite3
    from atlas_pca.atomic_kv import SqliteAtomicKv
    path = str(tmp_path / "kv.db")
    kv = SqliteAtomicKv(path, timeout=0.05)
    holder = sqlite3.connect(path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")

    def contend():
        try:
            kv.update("k", lambda _p: 1)
        except sqlite3.OperationalError:
            return "locked"
        return "ran"

    assert kv._conn().execute("PRAGMA busy_timeout").fetchone() == (50,)  # the configured wait, not sqlite's 5 s default (read without waiting)
    assert bounded(contend) == "locked"
    holder.execute("ROLLBACK")
    holder.close()
    assert bounded(kv.update, "k", lambda _p: 7) == 7
    other = sqlite3.connect(path, timeout=0.05, isolation_level=None)
    assert other.execute("SELECT value FROM pca_kv WHERE key = 'k'").fetchone() == ("7",)  # committed, visible to a second handle
    other.execute("BEGIN IMMEDIATE")  # and the write lock is free again
    other.execute("ROLLBACK")
    other.close()


def test_seeded_draws_advance_their_block_and_laplace_cap_terminates(monkeypatch):
    from atlas_pca import read_vault as RV
    d = RV.SeededDraws("k05c-seed")
    vals = [bounded(d._next48) for _ in range(15)]
    assert len(set(vals)) == 15  # three blocks, never the same block twice
    monkeypatch.setattr(RV, "_bern_exp_small", lambda *_a: True)
    with pytest.raises(RV.SamplerRangeError, match="laplace: no termination"):
        bounded(RV.discrete_laplace, RV.SeededDraws("k05c-lap"), 1, 1)


def test_ed25519_scalar_multiplication_terminates():
    from atlas_pca import ed25519 as E
    five = E._ID
    for _ in range(5):
        five = E._add(five, E._G)
    assert E._eq(bounded(E._mul, 5, E._G), five)
    assert E._eq(bounded(E._mul, 1, E._G), E._G)
    assert E._eq(bounded(E._mul, 0, E._G), E._ID)
    assert E._eq(bounded(E._mul, 8, E._G), bounded(E._mul, 2, bounded(E._mul, 4, E._G)))


# ---- first-ordered so a mutant that hands libcrypto a NULL handle is decided here, before any real-libcrypto test can crash the process

def test_openssl_key_hands_libcrypto_its_live_handles(monkeypatch):
    import ctypes
    from atlas_pca import pq_backends as PB
    from test_k05_kill_intent import _FakeLib, _key
    seen = {}

    def gen(ctx, ref):
        ref._obj.value = 4242
        return 1

    def rawpub(pkey, buf, ref):
        seen["pkey"] = pkey
        return 1

    def sign(ctx, buf, ref, msg, n):
        seen["ctx"], seen["buf"] = ctx, buf
        if buf is None:  # a NULL buffer would crash memmove: report a failure instead
            return 0
        ctypes.memmove(buf, b"SIG", 3)
        ref._obj.value = 3
        return 1

    lib = _FakeLib(EVP_PKEY_CTX_new_from_name=lambda *a: 99, EVP_PKEY_generate=gen, EVP_PKEY_get_raw_public_key=rawpub,
                   EVP_MD_CTX_new=lambda: 7, EVP_DigestSign=sign)
    k = _key(monkeypatch, lib)
    assert seen["pkey"] is not None and seen["pkey"].value == 4242
    assert k.sign(b"hello") == b"SIG"
    assert seen["ctx"] == 7 and seen["buf"] is not None
