"""k05 mutation-kill tests, group "intent": atomic_kv, plan_lifecycle, ledger, mesh, pq_backends, intent_history,
intent_v2 and arg_provenance. Expectations follow the TypeScript references in packages/pca/src (the module of the same
name). Deterministic, no network."""
import copy
import json
import sqlite3
import time

import pytest

from atlas_pca import plan_lifecycle as PLM
from atlas_pca.atomic_kv import MemoryAtomicKv, SqliteAtomicKv
from atlas_pca.plan_lifecycle import PlanRegistry, plan_root

# ================================================================================================================ atomic_kv


def test_memory_kv_copies_on_every_boundary():
    kv = MemoryAtomicKv()
    v = {"a": [1]}
    kv.set("k", v)
    v["a"].append(2)  # the caller's object is not the stored one
    assert kv.get("k") == {"a": [1]}
    kv.get("k")["a"].append(3)  # nor is a read's result
    assert kv.get("k") == {"a": [1]}
    seen = {}

    def peek(prev):
        prev["a"].append(9)  # fn gets a copy; returning None leaves the key unchanged
        seen["prev"] = prev
        return None
    out = kv.update("k", peek)
    assert out == {"a": [1]} and kv.get("k") == {"a": [1]}
    nxt = {"b": [1]}
    out = kv.update("k", lambda _p: nxt)
    assert out == {"b": [1]}
    nxt["b"].append(2)  # the stored value is a copy of what fn returned
    out["b"].append(3)  # and so is the returned one
    assert kv.get("k") == {"b": [1]}
    assert kv.update("fresh", lambda p: None) is None and kv.get("fresh") is None


def test_sqlite_kv_roundtrip_and_isolation(tmp_path):
    kv = SqliteAtomicKv(str(tmp_path / "kv.db"))
    kv.set("k", {"a": [1], "b": "x"})
    assert kv.get("k") == {"a": [1], "b": "x"}
    assert kv.get("nope") is None
    raw = sqlite3.connect(str(tmp_path / "kv.db")).execute("SELECT value FROM pca_kv WHERE key = ?", ("k",)).fetchone()[0]
    assert raw == '{"a":[1],"b":"x"}'  # compact separators
    assert kv.update("k", lambda p: {"c": 1}) == {"c": 1}  # a returned value is the new one
    assert kv.update("k", lambda p: None) == {"c": 1}  # None leaves it and returns the previous one

    def poke(prev):
        prev["c"] = 99
        return None
    assert kv.update("k", poke) == {"c": 1}

    def poke_nested(prev):
        prev["c"] = [1]
        return None
    kv.set("n", {"a": [1]})

    def append_nested(prev):
        prev["a"].append(2)
        return None
    assert kv.update("n", append_nested) == {"a": [1]}  # fn worked on a copy, not on the value returned
    assert kv.get("n") == {"a": [1]}


def test_sqlite_kv_refuses_nan_and_rolls_back(tmp_path):
    kv = SqliteAtomicKv(str(tmp_path / "kv.db"))
    kv.set("k", 1)
    with pytest.raises(ValueError):
        kv.update("k", lambda p: float("nan"))
    assert kv.get("k") == 1

    def boom(prev):
        raise KeyError("boom")
    with pytest.raises(KeyError):
        kv.update("k", boom)
    kv.set("k", 2)  # the failed update left no open transaction
    assert kv.get("k") == 2


def test_sqlite_kv_connection_settings(tmp_path):
    p = str(tmp_path / "kv.db")
    kv = SqliteAtomicKv(p, timeout=0.2)
    assert kv._conn().isolation_level is None
    assert kv._conn() is kv._conn()
    holder = sqlite3.connect(p, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    t0 = time.time()
    with pytest.raises(sqlite3.OperationalError):
        kv.update("k", lambda p_: 1)
    assert time.time() - t0 < 3.0  # the configured timeout, not sqlite's 5 s default
    holder.execute("ROLLBACK")


def test_sqlite_kv_memory_path_reuses_the_connection():
    kv = SqliteAtomicKv(":memory:")  # a fresh connection would be a fresh, empty database
    kv.set("k", 5)
    assert kv.get("k") == 5


# ============================================================================================================ plan_lifecycle

PNODES = [{"id": "a", "verb": "v", "resource": "r"}]


def _authorized(validator=None, nodes=PNODES, kv=None):
    clock = {"t": 10}
    reg = PlanRegistry(now=lambda: clock["t"], validator=validator, kv=kv)
    root = plan_root(nodes)
    assert reg.draft("g", nodes)["ok"]
    return reg, clock, root


def _to_authorized(reg, root, expires=None):
    assert reg.validate("g", root)["ok"] and reg.commit("g", root)["ok"]
    ap = {"by": "p"}
    if expires is not None:
        ap["expiresAt"] = expires
    assert reg.authorize("g", root, ap)["ok"]


def test_plan_default_clock_is_epoch_milliseconds(monkeypatch):
    monkeypatch.setattr(PLM.time, "time", lambda: 1234.5)
    reg = PlanRegistry()
    assert reg.draft("g", PNODES)["record"]["createdAt"] == 1234500


def test_plan_root_commits_to_post_conditions():
    base = plan_root(PNODES)
    assert plan_root([dict(PNODES[0], post={"x": 1})]) != base
    assert plan_root([dict(PNODES[0], post={"x": 1})]) != plan_root([dict(PNODES[0], post={"x": 2})])
    assert plan_root([dict(PNODES[0], pre={"x": 1})]) != base


def test_plan_key_encodes_like_encode_uri_component():
    reg = PlanRegistry()
    assert reg._key("a/b c!*'()~-_.é", "R") == "pca-plan:a%2Fb%20c!*'()~-_.%C3%A9:R"


def test_plan_get_refuses_non_records():
    reg = PlanRegistry()
    reg._kv.set(reg._key("g", "R"), {"root": 1})
    assert reg.get("g", "R") is None
    reg._kv.set(reg._key("g", "R"), "junk")
    assert reg.get("g", "R") is None
    rec = {"root": "R", "nodes": []}
    reg._kv.set(reg._key("g", "R"), rec)
    assert reg.get("g", "R") == rec


def test_plan_draft_returns_a_copy_of_the_nodes():
    nodes = copy.deepcopy(PNODES)
    out = PlanRegistry().draft("g", nodes)
    assert out["record"]["nodes"][0] is not nodes[0]


@pytest.mark.parametrize("upto", ["draft", "validated", "committed", "authorized"])
def test_plan_revoke_from_every_live_state(upto):
    reg, clock, root = _authorized()
    if upto != "draft":
        assert reg.validate("g", root)["ok"]
    if upto in ("committed", "authorized"):
        assert reg.commit("g", root)["ok"]
    if upto == "authorized":
        assert reg.authorize("g", root, {"by": "p"})["ok"]
    clock["t"] = 77
    out = reg.revoke("g", root, "why")
    assert out["ok"] is True and out["record"]["state"] == "revoked" and out["record"]["revokedAt"] == 77
    assert out["record"]["revokedReason"] == "why"


def test_plan_validate_losing_a_race_names_the_action():
    holder = {}

    def validator(rec):
        if not holder.get("inner"):
            holder["inner"] = True
            assert holder["reg"].validate("g", holder["root"])["ok"]  # somebody else validates first
        return {"ok": True}
    reg, _, root = _authorized(validator=validator)
    holder.update(reg=reg, root=root)
    assert reg.validate("g", root) == {"ok": False, "state": "validated", "reason": "plan %s is validated: cannot validate" % root}


class _RefKv:
    """A store that hands out its stored objects themselves (no copies)."""

    def __init__(self):
        self.m = {}

    def get(self, key):
        return self.m.get(key)

    def update(self, key, fn):
        nxt = fn(self.m.get(key))
        if nxt is not None:
            self.m[key] = nxt
        return self.m.get(key)


def test_plan_validator_gets_a_deep_copy():
    def validator(rec):
        rec["nodes"][0]["verb"] = "tampered"
        return {"ok": True}
    kv = _RefKv()
    reg, _, root = _authorized(validator=validator, kv=kv)
    assert reg.validate("g", root)["ok"] is True
    assert reg.get("g", root)["nodes"][0]["verb"] == "v"


def test_plan_status_unhashable_nodes_are_never_executable():
    reg, _, root = _authorized()
    _to_authorized(reg, root)
    k = reg._key("g", root)
    rec = reg._kv.get(k)
    rec["nodes"][0]["pre"] = object()
    reg._kv.set(k, rec)
    s = reg.status("g", root)
    assert s["executable"] is False and s["state"] == "authorized"
    assert s["reason"] == "plan %s: the stored nodes no longer hash to the root" % root
    assert s["record"]["root"] == root and set(s) == {"state", "executable", "reason", "record"}


def test_plan_check_unhashable_params_keep_the_status_fields():
    reg, _, root = _authorized()
    _to_authorized(reg, root)
    c = reg.check("g", root, operation={"verb": "v", "resource": "r", "params": {"p": float("nan")}}, now=50)
    assert c == dict(reg.status("g", root, 50), executable=False, reason="plan %s: the operation's params cannot be hashed" % root)
    assert c["state"] == "authorized" and "record" in c


def test_plan_check_and_context_use_the_given_time():
    reg, clock, root = _authorized()
    _to_authorized(reg, root, expires=100)
    assert reg.check("g", root, now=200)["executable"] is False
    assert reg.check("g", root, node_id="a", now=200)["reason"] == "plan %s: the principal's approval expired at 100" % root
    assert reg.context("g", root, 200)["planAuthorized"] is False
    assert reg.context("g", root, 50)["planAuthorized"] is True
    ctx = reg.context("g", root, 50)
    assert ctx["plan"] == PNODES and ctx["plan"] is not reg.status("g", root, 50)["record"]["nodes"]


def test_plan_context_plan_is_a_deep_copy():
    reg = PlanRegistry(kv=_RefKv())
    assert reg.draft("g", PNODES)["ok"]
    root = plan_root(PNODES)
    ctx = reg.context("g", root)
    ctx["plan"][0]["verb"] = "tampered"
    assert reg.get("g", root)["nodes"][0]["verb"] == "v"


def test_plan_check_not_executable_returns_the_status_as_is():
    reg, _, root = _authorized()  # still a draft: the status has a record but is not executable
    assert reg.check("g", root, node_id="zz") == reg.status("g", root)
    assert reg.check("g", root, operation={"verb": "x", "resource": "y"}) == reg.status("g", root)


# ===================================================================================================================== ledger

from atlas_pca import ledger as LG
from atlas_pca.agent import KeyPair
from atlas_pca.pca import _node_hash, b64u, canonical_bytes_strict, supported_suites

_G = KeyPair(bytes(range(32)))
_W1 = KeyPair(bytes(range(1, 33)))
_W2 = KeyPair(bytes(range(2, 34)))
_W3 = KeyPair(bytes(range(3, 35)))


def _h(n):
    return b64u(bytes([n]) * 32)


def _cosig(sth, w):
    msg = LG.STH_WITNESS_DOMAIN.encode() + canonical_bytes_strict(LG._witness_body(sth))
    return {"key": w.public, "sig": b64u(w.sign(msg))}


def _sth(size, root, prev_root, witnesses=()):
    body = {"instance_id": "i", "principal": "p", "size": size, "root": root, "prev_root": prev_root, "timestamp": 5}
    sth = dict(body, guardian=_G.public, sig=b64u(_G.sign(LG.STH_DOMAIN.encode() + canonical_bytes_strict(body))))
    sth["witnesses"] = [_cosig(sth, w) for w in witnesses]
    return sth


def _policy(threshold, *ws):
    return {"threshold": threshold, "witnessKeys": [w.public for w in ws]}


def _wh(root, w=_W1, principal="p", size=3):
    body = {"principal": principal, "size": size, "root": root}
    return dict(body, witness=w.public, sig=b64u(w.sign(LG.LEDGER_HEAD_DOMAIN.encode() + canonical_bytes_strict(body))))


def test_cosignature_needs_dict_matching_key_and_string_sig():
    sth = _sth(1, _h(1), _h(0))
    good = _cosig(sth, _W1)
    assert LG.verify_witness_cosignature(sth, good, _W1.public) is True
    assert LG.verify_witness_cosignature(sth, dict(good, key=_W2.public), _W1.public) is False  # a valid sig, named for another key
    assert LG.verify_witness_cosignature(sth, None, _W1.public) is False
    assert LG.verify_witness_cosignature(sth, dict(good, sig=5), _W1.public) is False
    assert LG.verify_witness_cosignature({}, good, _W1.public) is False  # malformed head: total, not an exception


def test_cosignatures_threshold_rules():
    sth = _sth(1, _h(1), _h(0), [_W1, _W2])
    pol = _policy(1.5, _W1, _W2)
    assert LG.verify_witness_cosignatures(sth, _policy(2, _W1, _W2)) is True
    assert LG.verify_witness_cosignatures(sth, pol) is False  # a non-integral threshold
    assert LG.verify_witness_cosignatures(sth, _policy(True, _W1, _W2)) is False
    assert LG.verify_witness_cosignatures(sth, _policy(-1, _W1, _W2)) is False
    assert LG.verify_witness_cosignatures(sth, _policy(0)) is True
    assert LG.verify_witness_cosignatures(sth, _policy(1, _W3)) is False  # nobody trusted signed
    assert LG.verify_witness_cosignatures(sth, _policy(1)) is False  # no trusted keys at all
    assert LG.verify_witness_cosignatures(sth, _policy(3, _W1, _W2, _W3)) is False
    two = dict(sth, witnesses=tuple(sth["witnesses"]))  # a JSON array only
    assert LG.verify_witness_cosignatures(two, _policy(1, _W1, _W2)) is False
    dup = dict(sth, witnesses=[sth["witnesses"][0], sth["witnesses"][0]])  # one witness counted once
    assert LG.verify_witness_cosignatures(dup, _policy(2, _W1, _W2)) is False


def test_cosignatures_skip_junk_entries_and_stop_at_threshold():
    sth = _sth(1, _h(1), _h(0), [_W1])
    good = sth["witnesses"][0]
    junk = {"key": ["unhashable"], "sig": "s"}
    assert LG.verify_witness_cosignatures(dict(sth, witnesses=[junk, good]), _policy(1, _W1)) is True  # skipped, not fatal
    assert LG.verify_witness_cosignatures(dict(sth, witnesses=[good, junk]), _policy(1, _W1)) is True  # never reached
    assert LG.verify_witness_cosignatures(dict(sth, witnesses=["x", {"key": "k", "sig": 1}, {"key": 1, "sig": "s"}, good]),
                                          _policy(1, _W1)) is True


def test_tree_head_malformed_is_false():
    sth = _sth(1, _h(1), _h(0))
    assert LG.verify_tree_head(sth, _G.public) is True
    broken = {k: v for k, v in sth.items() if k != "timestamp"}
    assert LG.verify_tree_head(broken, _G.public) is False
    assert LG.verify_tree_head(dict(sth, size=-1), _G.public) is False


def test_head_consistency_applies_the_witness_policy_to_both_heads():
    pol = _policy(1, _W1)
    older, newer = _sth(1, _h(1), _h(0), [_W1]), _sth(2, _h(2), _h(1), [_W1])
    proof = {"oldSize": 1, "newSize": 2, "path": [_h(9)]}
    proof["path"] = [_h(9)]
    newer = _sth(2, b64u(_node_hash(b"\x01" * 32, b"\x09" * 32)), _h(1), [_W1])
    assert LG.verify_head_consistency(older, newer, proof, _G.public, pol) is True
    bare_old, bare_new = _sth(1, _h(1), _h(0)), _sth(2, newer["root"], _h(1))
    assert LG.verify_head_consistency(bare_old, newer, proof, _G.public, pol) is False
    assert LG.verify_head_consistency(older, bare_new, proof, _G.public, pol) is False
    assert LG.verify_head_consistency(bare_old, bare_new, proof, _G.public) is True


def test_head_consistency_proof_sizes_must_match_both_heads():
    root1 = b64u(_node_hash(b"\x01" * 32, b"\x09" * 32))
    proof = {"oldSize": 1, "newSize": 2, "path": [_h(9)]}
    older, newer = _sth(1, _h(1), _h(0)), _sth(2, root1, _h(1))
    assert LG.verify_head_consistency(older, newer, proof, _G.public) is True
    assert LG.verify_head_consistency(_sth(5, _h(1), _h(0)), newer, proof, _G.public) is False  # old head claims another size
    assert LG.verify_head_consistency(older, _sth(7, root1, _h(1)), proof, _G.public) is False  # new head claims another size
    assert LG.verify_head_consistency(older, newer, dict(proof, oldSize=1.5), _G.public) is False
    assert LG.verify_head_consistency(older, newer, dict(proof, newSize=2.5), _G.public) is False


def test_checkpoint_chain_indexes_and_policy():
    root1 = b64u(_node_hash(b"\x01" * 32, b"\x09" * 32))
    pol = _policy(1, _W1)
    cp0 = {"sth": _sth(1, _h(1), _h(0), [_W1])}
    cp1 = {"sth": _sth(2, root1, _h(1), [_W1]), "proof": {"oldSize": 1, "newSize": 2, "path": [_h(9)]}}
    assert LG.verify_checkpoint_chain([cp0, cp1], _G.public, pol) == {"ok": True}
    assert LG.verify_checkpoint_chain([], _G.public) == {"ok": False, "at": 0}
    assert LG.verify_checkpoint_chain("x", _G.public) == {"ok": False, "at": 0}
    bare0 = {"sth": _sth(1, _h(1), _h(0))}  # the first head is not witnessed: it is refused where it stands
    assert LG.verify_checkpoint_chain([bare0, cp1], _G.public, pol) == {"ok": False, "at": 0}
    bare1 = {"sth": _sth(2, root1, _h(1)), "proof": cp1["proof"]}
    assert LG.verify_checkpoint_chain([cp0, bare1], _G.public, pol) == {"ok": False, "at": 1}
    assert LG.verify_checkpoint_chain([cp0, {"sth": cp1["sth"]}], _G.public, pol) == {"ok": False, "at": 1}
    assert LG.verify_checkpoint_chain([cp0, 5], _G.public, pol) == {"ok": False, "at": 1}


def test_checkpoint_chain_internal_failure_is_total(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr(LG, "verify_tree_head", boom)
    assert LG.verify_checkpoint_chain([{"sth": {}}, {"sth": {}}], _G.public) == {"ok": False, "at": 0}


def test_witnessed_head_and_equivocation():
    a, b = _wh(_h(1)), _wh(_h(2))
    assert LG.verify_witnessed_head(a, _W1.public) is True
    assert LG.verify_witnessed_head({k: v for k, v in a.items() if k != "root"}, _W1.public) is False  # malformed: total
    assert LG.verify_witnessed_head(a, _W2.public) is False
    assert LG.detect_equivocation(a, b, _W1.public) is True
    assert LG.detect_equivocation(a, a, _W1.public) is False
    assert LG.detect_equivocation(a, _wh(_h(2), principal="q"), _W1.public) is False
    assert LG.detect_equivocation(a, _wh(_h(2), size=4), _W1.public) is False


def _pq_witness_head(root, kp, w=_W1):
    body = {"principal": "p", "size": 3, "root": root}
    signed = dict(body, alg="ml-dsa-65", pq_pk=kp.public)
    sig = b64u(kp.sign(LG.LEDGER_HEAD_DOMAIN.encode() + canonical_bytes_strict(signed)))
    return dict(body, witness=w.public, alg="ml-dsa-65", pq_pk=kp.public, sig=sig)


def _pq():
    if "ml-dsa-65" not in supported_suites():
        pytest.skip("no ML-DSA-65 backend")
    from atlas_pca.agent import generate_pq_keypair
    return generate_pq_keypair("ML-DSA-65")


def test_equivocation_passes_pins_to_both_heads():
    kp = _pq()
    a, b = _pq_witness_head(_h(1), kp), _pq_witness_head(_h(2), kp)
    pins = {_W1.public: kp.public}
    assert LG.verify_witnessed_head(a, _W1.public, pins) is True
    assert LG.verify_witnessed_head(a, _W1.public) is False  # unpinned PQ: refused
    assert LG.detect_equivocation(a, b, _W1.public, pins) is True
    assert LG.detect_equivocation(a, b, _W1.public) is False


def test_signed_binds_suite_fields_and_needs_pq_pk():
    _pq()
    with pytest.raises(TypeError):
        LG._signed(LG.STH_DOMAIN, {"a": 1}, _W1.public, {"alg": "ml-dsa-65", "sig": "s"}, None)


def test_consistency_malformed_inputs():
    E = LG.EMPTY_TREE_ROOT
    assert LG.verify_ledger_consistency(E, None, {"oldSize": 0, "newSize": 5, "path": []}) is False
    assert LG.verify_ledger_consistency(None, E, {"oldSize": 0, "newSize": 5, "path": []}) is False
    assert LG.verify_ledger_consistency(E, E, {"oldSize": 0, "newSize": 5, "path": []}) is True
    assert LG.verify_ledger_consistency(E, _h(1), {"oldSize": 0, "newSize": 5, "path": ()}) is False  # a JSON array only
    assert LG.verify_ledger_consistency(_h(1), _h(2), {"oldSize": 3, "newSize": 5, "path": []}) is False  # no path at all


def test_consistency_path_bound_is_checked_before_any_decoding(monkeypatch):
    calls = []
    real = LG.decode_b64u_strict
    monkeypatch.setattr(LG, "decode_b64u_strict", lambda *a, **k: calls.append(1) or real(*a, **k))
    path = [_h(1)] * LG._MAX_CONSISTENCY_PATH
    assert LG.verify_ledger_consistency(_h(1), _h(2), {"oldSize": 3, "newSize": 5, "path": path}) is False
    assert len(calls) == LG._MAX_CONSISTENCY_PATH  # the longest allowed path is still examined
    del calls[:]
    assert LG.verify_ledger_consistency(_h(1), _h(2), {"oldSize": 3, "newSize": 5, "path": path + [_h(1)]}) is False
    assert calls == []


# ============================================================================================================== pq_backends

import ctypes

from atlas_pca import pq_backends as PB


class _Fn:
    def __init__(self, lib, name):
        self.lib, self.name, self.restype, self.argtypes = lib, name, "unset", "unset"

    def __call__(self, *a):
        self.lib.calls.append((self.name, a))
        return self.lib.impl.get(self.name, lambda *x: 1)(*a)


class _FakeLib:
    """A stand-in libcrypto: EVP_* attributes are call recorders whose behaviour a test sets in `impl`."""

    def __init__(self, **impl):
        self.calls, self.impl = [], impl

    def __getattr__(self, name):
        if name.startswith("EVP_"):
            f = _Fn(self, name)
            self.__dict__[name] = f
            return f
        raise AttributeError(name)

    def called(self, name):
        return [a for n, a in self.calls if n == name]


def test_bind_sign_declares_every_prototype_once():
    lib = _FakeLib()
    vp, sz, cp, ci = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_int
    assert PB._bind_sign(lib) is lib
    want = {
        "EVP_PKEY_CTX_new_from_name": (vp, [vp, cp, cp]), "EVP_PKEY_keygen_init": (ci, [vp]),
        "EVP_PKEY_generate": (ci, [vp, ctypes.POINTER(vp)]), "EVP_PKEY_CTX_free": (None, [vp]),
        "EVP_PKEY_get_raw_public_key": (ci, [vp, vp, ctypes.POINTER(sz)]),
        "EVP_DigestSignInit_ex": (ci, [vp, vp, cp, vp, cp, vp, vp]), "EVP_DigestSign": (ci, [vp, vp, ctypes.POINTER(sz), cp, sz]),
    }
    for name, (rt, at) in want.items():
        assert getattr(lib, name).restype == rt and getattr(lib, name).argtypes == at, name
    assert lib._atlas_sign_bound is True
    lib.EVP_PKEY_generate.restype = "sentinel"  # a second call does not bind again
    assert PB._bind_sign(lib) is lib
    assert lib.EVP_PKEY_generate.restype == "sentinel"


def _keygen_lib(**over):
    def gen(ctx, ref):
        ref._obj.value = 4242
        return 1

    def rawpub(pkey, buf, ref):
        ref._obj.value = ref._obj.value
        return 1
    impl = {"EVP_PKEY_CTX_new_from_name": lambda *a: 99, "EVP_PKEY_generate": gen, "EVP_PKEY_get_raw_public_key": rawpub}
    impl.update(over)
    return _FakeLib(**impl)


def _key(monkeypatch, lib, kt="ML-DSA-65"):
    monkeypatch.setattr(PB, "_libcrypto", lambda: lib)
    monkeypatch.setattr(PB, "_openssl_available", lambda t: True)
    return PB.OpensslKey(kt)


def test_openssl_key_generation(monkeypatch):
    lib = _keygen_lib()
    k = _key(monkeypatch, lib)
    assert len(k.public) == PB.KEY_TYPES["ML-DSA-65"][0]
    assert lib.called("EVP_PKEY_CTX_new_from_name") == [(None, b"ML-DSA-65", None)]
    assert lib.called("EVP_PKEY_CTX_free") == [(99,)]
    assert k._pkey.value == 4242
    k.__del__()
    assert lib.called("EVP_PKEY_free") == [(k._pkey,)]


def test_openssl_key_del_never_raises(monkeypatch):
    def boom(*a):
        raise RuntimeError("x")
    k = _key(monkeypatch, _keygen_lib(EVP_PKEY_free=boom))
    k.__del__()


@pytest.mark.parametrize("over,msg", [
    ({"EVP_PKEY_CTX_new_from_name": lambda *a: None}, "unsupported_suite: ML-DSA-65"),
    ({"EVP_PKEY_keygen_init": lambda *a: 0}, "unsupported_suite: ML-DSA-65 (key generation failed)"),
    ({"EVP_PKEY_generate": lambda *a: 0}, "unsupported_suite: ML-DSA-65 (key generation failed)"),
    ({"EVP_PKEY_generate": lambda ctx, ref: 1}, "unsupported_suite: ML-DSA-65 (key generation failed)"),  # a null key
    ({"EVP_PKEY_get_raw_public_key": lambda *a: 0}, "unsupported_suite: ML-DSA-65 (no raw public key)"),
])
def test_openssl_key_failures(monkeypatch, over, msg):
    lib = _keygen_lib(**over)
    with pytest.raises(RuntimeError) as e:
        _key(monkeypatch, lib)
    assert str(e.value) == msg
    if "EVP_PKEY_CTX_new_from_name" not in over:
        assert lib.called("EVP_PKEY_CTX_free") == [(99,)]  # the context is released on every path


def test_openssl_key_sign(monkeypatch):
    def sign(ctx, buf, ref, msg, n):
        assert ref._obj.value == PB.KEY_TYPES["ML-DSA-65"][1] and (msg, n) == (b"hello", 5)
        ctypes.memmove(buf, b"SIG", 3)
        ref._obj.value = 3
        return 1
    lib = _keygen_lib(EVP_MD_CTX_new=lambda: 7, EVP_DigestSign=sign)
    k = _key(monkeypatch, lib)
    assert k.sign(b"hello") == b"SIG"
    assert lib.called("EVP_DigestSignInit_ex") == [(7, None, None, None, None, k._pkey, None)]
    assert lib.called("EVP_MD_CTX_free") == [(7,)]


@pytest.mark.parametrize("which", ["EVP_DigestSignInit_ex", "EVP_DigestSign"])
def test_openssl_key_sign_failures(monkeypatch, which):
    lib = _keygen_lib(EVP_MD_CTX_new=lambda: 7, **{which: lambda *a: 0})
    k = _key(monkeypatch, lib)
    with pytest.raises(RuntimeError) as e:
        k.sign(b"m")
    assert str(e.value) == "signing failed"
    assert lib.called("EVP_MD_CTX_free") == [(7,)]


# ========================================================================================================== intent_history

from atlas_pca import intent_history as IH

_T = 1_000_000
_SUM = {"id": "s", "agg": "sum", "val": "action.params.total", "sel": {"verbs": ["pay"]}, "win": {"kind": "task"}, "key": None,
        "holder": {"kind": "site_local"}}


def _ev(total, id_="e1", t=_T, status="committed"):
    return {"id": id_, "verb": "pay", "resource": "r", "params": {"total": total}, "t": t, "status": status}


def _history_error(fn, *a):
    with pytest.raises(IH.HistoryError) as e:
        fn(*a)
    return str(e.value)


def test_history_times():
    assert [IH._is_time(x) for x in (0, 0.0, -0.0, 5.0, 1.5, True, "1", 2 ** 53, 2 ** 53 - 1, float("nan"))] == \
        [True, True, False, True, False, False, False, False, True, False]


def test_history_window_edges():
    assert IH.in_window({"kind": "weird"}, 5, 5) is False
    assert IH.in_window({}, 4, 5) is False
    assert IH.in_window({"kind": "weird"}, 6, 5) is True  # stamped after t: has not left any window
    assert IH.in_window({"kind": "task"}, 5, 5) is True
    assert IH.in_window({"kind": "sliding", "ms": 10}, 5, 5) is True


def test_history_empty_pre_states():
    assert [IH._empty_pre(a) for a in ("sum", "count", "max", "distinct")] == [{"sum": 0}, {"count": 0}, {"max": 0}, {"values": []}]


def test_history_pre_state_errors():
    keyed = dict(_SUM, key="action.params.k")
    assert _history_error(IH.acc_pre_state, keyed, [], {}, _T) == "the key parameter action.params.k is missing"
    assert _history_error(IH.acc_pre_state, _SUM, [], {}, 1.5) == "the candidate time is not a safe integer"
    assert _history_error(IH.acc_pre_state, _SUM, [_ev(1, "e9", t=1.5)], {}, _T) == "event e9: the time is not a safe integer"
    assert _history_error(IH.acc_pre_state, _SUM, [_ev(-1, "e8")], {}, _T) == \
        "event e8: action.params.total must be a non-negative safe integer"
    big = 2 ** 53 - 1
    assert _history_error(IH.acc_pre_state, _SUM, [_ev(big, "a"), _ev(big, "b")], {}, _T) == "sum exceeds 2^53-1"


def test_history_post_errors():
    big = 2 ** 53 - 1
    assert _history_error(IH.acc_post, _SUM, [_ev(big)], "pay", {"total": 1}, _T) == "overflow"
    assert _history_error(IH.acc_post, _SUM, [], "pay", {"total": -1}, _T) == "action.params.total must be a non-negative safe integer"


# ================================================================================================================ intent_v2

from atlas_pca import intent_v2 as V


def test_v2_declaration_checkers_default_to_the_v1_profile():
    d = {"type": "integer", "semantic": "s", "sensitivity": "free"}
    assert V._param_decl_error("action.params.a.b", d, {}) == "parameter path 'action.params.a.b' is not action.params.<name>"
    assert V._param_decl_error("action.params.a", dict(d, format="email"), {}) == "action.params.a: unknown member 'format'"
    v = {"verb": "x", "kind": "read", "params": {}}
    assert V._verb_decl_error(dict(v, traits=[]), {}) == "verb entry: unknown member 'traits'"


def _v2_doc(**kw):
    d = {"v": 2, "kind": V.ACTION_SCHEMA_KIND, "site": "s", "aud": "a", "version": "1",
         "verbs": [{"verb": "x", "kind": "read", "params": {}}]}
    d.update(kw)
    return d


def test_v2_schema_version_and_traits_digest():
    assert V.action_schema_shape_error(_v2_doc(v=3), signed=False) == "unsupported schema version"
    assert V.action_schema_shape_error(_v2_doc(v=None), signed=False) == "unsupported schema version"
    bad = "traits_digest must be a canonical base64url SHA-256 digest"
    assert V.action_schema_shape_error(_v2_doc(traits_digest=b64u(bytes(33))), signed=False) == bad
    assert V.action_schema_shape_error(_v2_doc(traits_digest=b64u(bytes(31))), signed=False) == bad
    assert V.action_schema_shape_error(_v2_doc(traits_digest=b64u(bytes(32))), signed=False) != bad
    assert V.action_schema_shape_error(_v2_doc(v=1, traits_digest=b64u(bytes(33))), signed=False) == "unknown member 'traits_digest'"


def _iban(cc, bban):
    n = int("".join(str(int(c, 36)) for c in bban + cc + "00"))
    return "%s%02d%s" % (cc, 98 - n % 97, bban)


def test_v2_iban_letters_a_to_z_are_numbered_10_to_35():
    for cc, bban in (("DE", "WEST12345A9876"), ("GB", "AAAAAAAAAAAAA"), ("FR", "A0000000000A0"), ("NL", "BANKA0123456789"), ("ES", "ZA1234567890")):
        assert V._iban_ok(_iban(cc, bban)) is True, bban
    assert V._iban_ok("GB82WEST12345698765432") is True
    assert V._iban_ok("GB83WEST12345698765432") is False


def test_v2_cidr_edges():
    assert V._cidr_ok("255.255.255.255/32") is True
    assert V._cidr_ok("0.0.0.0/0") is True
    assert V._cidr_ok("256.0.0.0/8") is False
    assert V._cidr_ok("10.0.0.0/33") is False
    assert V._cidr_ok("10.0.0.01/8") is False
    assert V._cidr_ok("::1/128") is True
    assert V._cidr_ok("::/0") is True
    assert V._cidr_ok("::1/129") is False
    assert V._cidr_ok("1:2/64") is False  # fewer than two colons
    assert V._cidr_ok(":::1/64") is False


def test_v2_email_format_is_capped_at_254():
    def mail(total):
        return "%s@%s.%s.%s" % ("a" * 64, "b" * 63, "c" * 63, "d" * (total - 193))
    chk = V.format_check("email")
    assert len(mail(254)) == 254 and chk(mail(254)) is True
    assert len(mail(255)) == 255 and chk(mail(255)) is False
    assert chk("a@b.co") is True and chk("a@b") is False
    assert V.format_check("nonsense") is None


def test_v2_revocation_age_unknown_message():
    assert V.check_revocation_age(None, 5, 10) == {"ok": False, "reason": "revocation state age is unknown (unverifiable revocation state)"}
    assert V.check_revocation_age("x", 5, 10, "epoch")["reason"] == "epoch age is unknown (unverifiable revocation state)"
    assert V.check_revocation_age(float("inf"), 5, 10)["reason"] == "revocation state age is unknown (unverifiable revocation state)"


def test_v2_schema_step_passes_reviewers_to_the_floor_check(monkeypatch):
    from atlas_pca import actions as ACT
    seen = []
    monkeypatch.setattr(ACT, "schema_floor_error", lambda doc, rv: seen.append((doc, rv)))
    monkeypatch.setattr(V, "_schema_ctx_error", lambda ctx: None)
    monkeypatch.setattr(V, "verify_action_schema", lambda doc, keys: {"ok": True})
    doc = {"v": 2, "aud": "A"}
    V._schema_step({"aud": "A"}, {"schema": {"docs": [doc], "keys": []}})
    V._schema_step({"aud": "A"}, {"schema": {"docs": [doc], "keys": []}, "reviewers": ["r"]})
    V._schema_step({"aud": "A"}, {"schema": {"docs": [dict(doc, v=1)], "keys": []}})
    assert seen == [(doc, None), (doc, ["r"])]


def test_v2_decide_hands_the_pieces_to_model_rules(monkeypatch):
    rec = []
    monkeypatch.setattr(V, "_model_rules", lambda *a: rec.append(a))
    p, grant, ctx = {"action": {"verb": "v", "resource": "r"}}, {"g": 1}, {"policy": {}}
    out = V.decide_intent_v2(p, grant, ctx, 5)
    (o, pp, gg, cc, run, action), = rec
    assert o is out and pp is p and gg is grant and cc is ctx and callable(run)
    assert action == {"verb": "v", "resource": "r", "params": {}}


def test_v2_decide_reports_the_single_source_list(monkeypatch):
    monkeypatch.setattr(V, "_model_rules", lambda *a: None)
    bad = {"ok": False, "reason": "x"}
    monkeypatch.setattr(V, "_schema_step", lambda p, ctx: bad)
    monkeypatch.setattr(V, "_session_step", lambda *a: bad)
    monkeypatch.setattr(V, "_acc_step", lambda *a: bad)
    src = ["a", "b"]
    monkeypatch.setattr(V, "decide_intent_wb", lambda inp: {"single_source": src, "checks": {}, "outcome": "deny"})
    p = {"intent_session": {"session": "s"}, "action": {"verb": "v", "resource": "r"}, "aud": "A"}
    out = V.decide_intent_v2(p, {}, {"policy": {}}, 5)
    assert out["single_source"] == ["a", "b"] and out["single_source"] is not src
    monkeypatch.setattr(V, "decide_intent_wb", lambda inp: {"single_source": [], "checks": {}, "outcome": "deny"})
    assert "single_source" not in V.decide_intent_v2(p, {}, {"policy": {}}, 5)


def test_v2_allow_side_predicates_read_all_three_ceilings():
    layers = {"org": {"predicates": ["o"]}, "site": {"predicates": ["s"]}, "std": {"predicates": ["t"]}, "other": {"predicates": ["x"]}}
    assert V._allow_side_predicates({"predicates": ["e"]}, {"layers": layers}) == [["e"], ["o"], ["s"], ["t"]]
    assert V._allow_side_predicates(None, {"layers": {"site": 5}}) == [None, None, None, None]
    assert V._allow_side_predicates(None, None) == [None]


def _rules(monkeypatch, env, out, ctx=None, grant=None):
    AZ = __import__("sys").modules["atlas_pca.authorize"]
    monkeypatch.setattr(AZ, "read_envelope", lambda g: env)
    ran = []
    V._model_rules(out, {}, grant if grant is not None else {"id": "G", "issuer": "I"}, ctx, lambda name, f: ran.append((name, f())) or {"ok": True},
                   {"verb": "x", "resource": "r", "params": {}})
    return ran


def test_v2_pin_reads_records_keys_and_reapprovals(monkeypatch):
    from atlas_pca import actions_registry as AR
    seen = []
    monkeypatch.setattr(AR, "decide_pin", lambda inp: seen.append(inp) or {"ok": True})
    env = {"actions": {"a": 1}, "caveats": [], "predicates": []}
    doc = {"v": 1}
    _rules(monkeypatch, env, {"schema": doc}, {"actions": {"records": [1], "keys": [2], "reapprovals": [3]}})
    _rules(monkeypatch, env, {"schema": doc}, {"actions": {"keys": None}})
    assert seen[0] == {"pin": {"a": 1}, "doc": doc, "verb": "x", "records": [1], "keys": [2], "reapprovals": [3],
                       "grant": {"id": "G", "issuer": "I"}}
    assert (seen[1]["records"], seen[1]["keys"], seen[1]["reapprovals"]) == ([], [], [])


def test_v2_traits_without_an_envelope_use_the_default_pin(monkeypatch):
    from atlas_pca import actions_registry as AR
    seen = []
    monkeypatch.setattr(AR, "rule22_decide", lambda doc, verb, grant, cc: seen.append((doc, verb, grant, cc)) or "allow")
    doc = {"v": 2}
    ran = _rules(monkeypatch, None, {"schema": doc})
    assert ("traits", {"ok": True}) in ran
    assert seen == [(doc, "x", {"caveats": [], "max_esc": AR.MAX_ESC_TIER, "preauth_esc": 0}, [])]


def test_v2_single_source_alone_triggers_the_tighten_rule(monkeypatch):
    seen = []
    monkeypatch.setattr(V, "decide_tighten", lambda inp: seen.append(inp) or {"legacy": False, "outcome": "ok"})
    env = {"predicates": [{"where": [{"field": "env.world.foo"}]}], "caveats": []}
    ran = _rules(monkeypatch, env, {"single_source": ["foo"]})
    assert [n for n, _ in ran] == ["tighten"] and seen[0]["single_source"] == ["foo"]
    assert _rules(monkeypatch, env, {"single_source": ["bar"]}) == []


# ============================================================================================================ arg_provenance

from atlas_pca import arg_provenance as AP


def test_prov_units_split_astral_characters():
    assert AP._units("\U00010000") == "\ud800\udc00"
    assert AP._units("a\U0001f600b") == "a\ud83d\ude00b"
    assert AP._units("abc￿") == "abc￿"


def test_prov_token_search_resumes_after_each_miss():
    assert AP.occurs_as_token("xab ab abx", "ab") is True
    assert AP.occurs_as_token("xab abx", "ab") is False
    assert AP.occurs_as_token("a ab", "ab") is True
    assert AP.occurs_as_token("", "a") is False and AP.occurs_as_token("a", "") is False


def test_prov_leaf_cap_allows_exactly_the_maximum():
    assert AP.prov_leaves(["x"] * AP.MAX_PROV_LEAVES + [[]]) == ["x"] * AP.MAX_PROV_LEAVES
    assert AP.prov_leaves(["x"] * (AP.MAX_PROV_LEAVES + 1)) is None


def _prov_input(**kw):
    i = {"mediators": [], "operation": {"verb": "v", "resource": "r", "params": {}}}
    i.update(kw)
    return i


def test_prov_observation_source_bound():
    ok = AP.decide_arg_provenance(_prov_input(observed=[{"origin": "tool", "source": "a" * 256}]))
    assert ok.get("code") != "malformed_config"
    bad = AP.decide_arg_provenance(_prov_input(observed=[{"origin": "tool", "source": "a" * 257}]))
    assert (bad["outcome"], bad["code"]) == ("deny", "malformed_config")
    assert bad["reason"] == "observations must be a list of {origin, source}"


def test_prov_clip_counts_utf16_units():
    assert AP._clip("\U00010000" + "b" * 261) == "\U00010000" + "b" * 129
    assert AP._clip("￿" + "b" * 255) == "￿" + "b" * 127
    assert AP._clip("￿" + "b" * 256) == "￿" + "b" * 127
    assert AP._clip("") == "-" and AP._clip("short") == "short"


def test_prov_recorder_construction():
    seed = bytes(range(32))
    assert AP.ProvenanceRecorder("m", "k", seed).pin["pk"] == KeyPair(seed).public
    a, b = AP.ProvenanceRecorder("m", "k"), AP.ProvenanceRecorder("m", "k")  # no key given: a fresh one each
    assert a.pin["pk"] != b.pin["pk"]
    assert "pq_pk" not in AP.ProvenanceRecorder("m", "k", alg="ed25519").pin
    with pytest.raises(ValueError) as e:
        AP.ProvenanceRecorder("m", "k", alg="ml-dsa-65")
    assert str(e.value) == "ProvenanceRecorder: suite 'ml-dsa-65' needs a PQ key pair"


def test_prov_recorder_clock(monkeypatch):
    monkeypatch.setattr(AP.time, "time", lambda: 1234.5)
    assert AP.ProvenanceRecorder("m", "k").principal("hi")["issued_at"] == 1234500
    r = AP.ProvenanceRecorder("m", "k", now=lambda: 0)
    assert r.principal("hi")["issued_at"] == 0
    r = AP.ProvenanceRecorder("m", "k", now=lambda: -5)
    assert r.principal("hi")["issued_at"] == 0


def test_prov_recorder_session_limit_and_receipts_copy():
    r = AP.ProvenanceRecorder("m", "k")
    r.principal("hi")
    got = r.receipts()
    assert got == r._chain and got is not r._chain
    r._chain = [r._chain[0]] * AP.MAX_PROV_RECEIPTS
    with pytest.raises(ValueError) as e:
        r.for_action({"verb": "v", "resource": "r", "params": {}})
    assert str(e.value) == ("provenance: the session holds %d receipts; start a new session with the principal's message"
                            % AP.MAX_PROV_RECEIPTS)
