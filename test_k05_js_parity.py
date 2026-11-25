"""Reference parity (BRIEF "pin the reference"): JS Number() / BigInt() of a string, String() of request members, UTF-16 slicing and
sorting, `v === 1`, replay key scope, ceiling `failed ?? []`, the guard's challenge error codes."""
import importlib
import math

import pytest

from atlas_pca import actions as A
from atlas_pca import actions_registry as R
from atlas_pca import agent as G
from atlas_pca import approval as AP
from atlas_pca import attest_common as C
Z = importlib.import_module("atlas_pca.authorize")  # the package attribute is the function
from atlas_pca import blueprint as B
from atlas_pca import escalation as E
from atlas_pca import intent_history as IH

NAN = ["+-Infinity", "-+Infinity", "+0x1", "-0x1", "0x+1", "0x-1", "0x1_0", "0x 1", "0x", "0b2", "0o8", "1_000", "١", "１", "infinity",
       "INFINITY", "nan", "NaN", "1e", ".", "+", "1f", "1d", "1L", "1\0", "\u0085", "\u180e", "0x1p3", "1\u0085", "\u180e1"]
PARSE = [("", 0.0), ("   ", 0.0), (" 12 ", 12.0), ("﻿12 ", 12.0), ("Infinity", math.inf), ("+Infinity", math.inf), ("-Infinity", -math.inf),
         ("0x10", 16.0), ("0X1f", 31.0), ("0o7", 7.0), ("0b1", 1.0), ("1.", 1.0), (".5", 0.5), ("1e3", 1000.0), ("+1.5", 1.5), ("-0", -0.0),
         ("0x" + "f" * 300, math.inf)]


@pytest.mark.parametrize("fn", [A._jnum, C.js_number])
@pytest.mark.parametrize("s", NAN)
def test_number_nan(fn, s):
    assert math.isnan(fn(s))


@pytest.mark.parametrize("fn", [A._jnum, C.js_number])
@pytest.mark.parametrize("s,want", PARSE)
def test_number_parses(fn, s, want):
    got = fn(s)
    assert got == want and math.copysign(1.0, got) == math.copysign(1.0, want)


@pytest.mark.parametrize("s", ["١", "１", "1١"])
def test_bigint_refuses_non_ascii_digits(s):
    with pytest.raises(C.JsError):
        C.big_int(s)


GRANT = {"id": "g"}


@pytest.mark.parametrize("build", [
    lambda p, r, **k: E.build_escalation_request(aud="a", grant=GRANT, pcactn=p, last_counter=0, reasons=r, now=5, **k),
    lambda p, r, **k: G.build_escalation_request("a", GRANT, p, 0, r, 5, **k),
])
def test_request_members_are_js_strings(build):
    r = build({"action": {"verb": True, "resource": None}}, [True, None, 1.5])
    assert (r["verb"], r["resource"], r["reasons"]) == ("true", "null", ["true", "null", "1.5"])
    assert (lambda x: (x["verb"], x["resource"]))(build({"action": {}}, [])) == ("undefined", "undefined")
    assert (lambda x: (x["verb"], x["resource"]))(build({}, [])) == ("undefined", "undefined")
    # slice(0, 512) counts UTF-16 code units: the cut inside a pair keeps the lone high surrogate
    assert build({}, ["a" * 511 + "\U0001f600"])["reasons"] == ["a" * 511 + "\ud83d"]
    assert build({}, [], ttl_ms=0)["expires_at"] == 5  # `ttlMs ?? default`: an explicit 0 stands


def test_sort_uniq_is_utf16_code_units():
    assert A._sort_uniq(["￿", "\U00010000", "a", "a"]) == ["a", "\U00010000", "￿"]


def test_is1_is_js_strict_equality_with_one():
    for v in (1, 1.0):
        assert R._is1(v) is True
    for v in (True, "1", 2, 1.5, None, [1]):
        assert R._is1(v) is False


def test_state_key_scope():
    assert Z.state_key("g", "h") == "g:h"
    assert Z.state_key("g", "h", "https://rs/a b") == "aud:https%3A%2F%2Frs%2Fa%20b:g:h"
    assert Z.state_key("g", "h", "-_.!~*'()") == "aud:-_.!~*'():g:h"
    assert Z.state_key("g", "h", "") == "aud::g:h"


def _mem_store(*bps):
    st = B.MemoryBlueprintStore()
    for b in bps:
        st.put(b)
    return st


def test_ceiling_failed_null_is_empty():
    bp = {"id": "bp1", "key": "K", "status": "active", "ceiling": [{"type": "max_spend", "usd": 1}], "epoch": 1, "operator": "op"}
    chain = [{"issuer": "root", "holder": "K"}, {"issuer": "K", "holder": "inst"}]
    r = B.check_blueprints(chain, B.BlueprintRegistry(["op"], _mem_store(bp)), 1, "any", None, lambda c, b: {"ok": False, "failed": None})
    assert r == {"decision": "deny", "code": "ceiling_violated", "blueprint": "bp1", "failed": []}


@pytest.mark.parametrize("q,want", [
    ("pending:", "missed"),  # Number("") is 0
    ("pending: \n", "missed"),
    ("pending:0", "missed"),
    ("pending:1", "missed"),
    ("pending: 3 ", "pending:2"),
    ("pending:0x3", "pending:2"),
    ("pending:2.5", "pending:1.5"),
    ("pending:Infinity", "pending:Infinity"),
    ("pending:abc", "pending:NaN"),
    ("pending:1_0", "pending:NaN"),
    ("pending:٣", "pending:NaN"),
    ("pending:1\0", "pending:NaN"),
    ("pending:᠎", "pending:NaN"),
    ("pending:0x1p3", "pending:NaN"),
    ("pending:nan", "pending:NaN"),
    ("pending:inf", "pending:NaN"),
])
def test_responds_within_pending_is_js_number(q, want):
    m = {"kind": "responds_within", "p": {"verb": "a"}, "q": {"verb": "b"}, "within": 4}
    e = {"status": "reserved", "verb": "x", "resource": "r", "params": {}}
    assert IH.monitor_step(m, q, e) == want
    assert IH.monitor_step(m, q, dict(e, verb="b")) == "idle"  # the response clears it, whatever the state held


def test_responds_within_pending_min_is_math_min():
    m = {"kind": "responds_within", "p": {"verb": "a"}, "q": {"verb": "b"}, "within": 4}
    e = {"status": "reserved", "verb": "a", "resource": "r", "params": {}}
    assert IH.monitor_step(m, "idle", e) == "pending:4"
    assert IH.monitor_step(m, "pending:3", e) == "pending:2"
    assert IH.monitor_step(m, "pending:9", e) == "pending:4"
    assert IH.monitor_step(m, "pending:Infinity", e) == "pending:4"
    assert IH.monitor_step(m, "pending:abc", e) == "pending:NaN"  # Math.min(NaN, W)


def test_jnum_is_the_one_helper():
    assert A._jnum("0x" + "f" * 300) == math.inf and math.isnan(A._jnum("1\0"))
    assert A._jnum(" 12 ") == 12.0 and A._jnum("") == 0.0
