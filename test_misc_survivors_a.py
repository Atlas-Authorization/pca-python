"""Exact pins for the atomic key/value conformance kit, the ed25519 point gate, the OID group caps, the compact-JWS size cap, the
NVIDIA firmware-policy key checks and the RSASSA-PSS parameter reader (each loop-bearing case runs under a hard deadline so a
non-terminating variant fails an assertion instead of timing out)."""
import base64
import copy
import inspect
import re
import threading

import pytest

from atlas_pca import attest_cert as AC
from atlas_pca import attest_common as C
from atlas_pca import attest_nvidia as N
from atlas_pca import atomic_kv as AK
from atlas_pca import ed25519 as E
from atlas_pca import run_atomic_kv_conformance
from atlas_pca.attest_amd import AttestConstructError
from atlas_pca.attest_der import _tlv_at
from test_attest_units import integer, octets, oid, seq, tlv
from test_k05c_deadline import bounded
from test_k05f_a_oid_caps import der_oid, sig_oid

# ------------------------------------------------------------------------------------------------ atomic kv kit doubles


class Backend:
    """An in-memory atomic key/value backend whose flaws are switched on by flags."""

    def __init__(self, **flags):
        self.m, self.flags, self.lock = {}, flags, threading.RLock()
        self.log, self.errors, self.events, self.handles, self.closed = [], [], [], [], []

    def open(self):
        h = Handle(self, len(self.handles))
        self.handles.append(h)
        return h


class Handle:
    def __init__(self, b, idx):
        self.b, self.idx = b, idx

    def close(self):
        self.b.closed.append(self.idx)

    def _slot(self, key):
        return "_" if self.b.flags.get("ignore_key") else key

    def get(self, key):
        b, f = self.b, self.b.flags
        with b.lock:
            b.log.append(("get", key))
            v = b.m.get(self._slot(key))
            if v is None:
                return f.get("missing")
            if f.get("stale_idx") == self.idx and isinstance(v, int):
                return v - 1
            return v if f.get("alias_get") else copy.deepcopy(v)

    def update(self, key, fn):
        b, f = self.b, self.b.flags
        with b.lock:
            b.log.append(("update", key))
            k = self._slot(key)
            cur = b.m.get(k)
            prev = cur if f.get("live_prev") else copy.deepcopy(cur)
            if prev is None and f.get("blind_prev"):
                prev = {}
            try:
                nxt = fn(prev)
                if f.get("retry_fn"):
                    nxt = fn(prev)
            except BaseException as e:  # noqa: BLE001
                b.errors.append(str(e))
                if f.get("dirty_on_error"):
                    b.m[k] = {"n": 0}
                if f.get("swallow"):
                    return copy.deepcopy(b.m.get(k))
                raise
            if nxt is not None:
                if f.get("cap") is not None and isinstance(nxt, int):
                    nxt = min(nxt, f["cap"])
                if f.get("no_store"):
                    return copy.deepcopy(nxt)
                if not (f.get("freeze") and k in b.m):
                    b.m[k] = nxt if f.get("alias_put") else copy.deepcopy(nxt)
            elif f.get("none_returns_none"):
                return None
            if f.get("ret_none"):
                return None
            return copy.deepcopy(b.m.get(k))


def kit(b, **kw):
    def restart():
        b.events.append(("restart", sorted(set(b.closed)), len(b.closed)))
        if b.flags.get("forget_on_restart"):
            b.m.clear()

    def teardown():
        b.events.append(("teardown", len(b.closed)))

    rep = run_atomic_kv_conformance(b.open, restart=restart, teardown=teardown, **kw)
    return rep, {r.test: r for r in rep.results}


def test_a_correct_store_passes_with_the_default_sizes_keys_and_lifecycle():
    b = Backend()
    rep, res = kit(b)
    assert [(r.test, r.status, r.note) for r in rep.results] == [
        ("semantics", "pass", ""), ("copies", "pass", ""), ("increments", "pass", "5 rounds x 16 threads"),
        ("cross-handle", "pass", "16 threads over 4 handles"), ("durability", "pass", "")]
    assert len(b.handles) == 9  # 3 single + 4 cross-handle + 1 durability write + 1 reopened after the restart
    keys = {k for _, k in b.log}
    run = next(k[4:] for k in keys if k.startswith("sem:"))
    assert re.fullmatch("[0-9a-f]{12}", run)
    assert keys == {p + run for p in ("sem:", "sem-other:", "copy:", "inc:", "xh:", "dur:")}
    kk, other, cp = "sem:" + run, "sem-other:" + run, "copy:" + run
    assert [e for e in b.log if e[1] in (kk, other)] == [
        ("get", kk), ("update", kk), ("get", kk), ("update", kk), ("update", kk), ("get", kk), ("get", other), ("update", kk),
        ("get", kk)]
    assert [e for e in b.log if e[1] == cp] == [("update", cp), ("get", cp), ("get", cp), ("update", cp), ("get", cp)]
    assert [e for e in b.log if e[1] == "dur:" + run] == [("update", "dur:" + run), ("get", "dur:" + run)]
    assert b.errors == ["boom"]
    assert b.events == [("restart", list(range(8)), 8), ("teardown", 17)]


def test_the_process_local_declarations_skip_exactly_what_they_name():
    b = Backend()
    rep, res = kit(b, durable=False, shared=False)
    assert (res["cross-handle"].status, res["cross-handle"].note) == ("skip", "the adapter declares shared=False (a process-local store)")
    assert (res["durability"].status, res["durability"].note) == ("skip", "the adapter declares durable=False (state dies with the process)")
    assert len(b.handles) == 3 and b.events == [("teardown", 3)]
    b2 = Backend()
    _, res2 = kit(b2, durable=False)
    assert res2["cross-handle"].status == "pass" and res2["durability"].status == "skip"
    b3 = Backend()
    _, res3 = kit(b3, shared=False)
    assert res3["cross-handle"].status == "skip" and res3["durability"].status == "pass"


FAILS = [
    ({"missing": 0}, "semantics", "a missing key must read None"),
    ({"blind_prev": True}, "semantics", "update must return the stored value"),
    ({"ret_none": True}, "semantics", "update must return the stored value"),
    ({"no_store": True}, "semantics", "the stored value is not readable"),
    ({"none_returns_none": True}, "semantics", "a None result must leave the key unchanged and return it"),
    ({"retry_fn": True}, "semantics", "fn must see the previous value"),
    ({"freeze": True}, "semantics", "fn must see the previous value"),
    ({"ignore_key": True}, "semantics", "another key must be independent"),
    ({"swallow": True}, "semantics", "an exception in fn must propagate"),
    ({"dirty_on_error": True}, "semantics", "an exception in fn must leave the key unchanged"),
    ({"alias_put": True}, "copies", "the store kept a reference to the caller's value"),
    ({"alias_get": True}, "copies", "a read returned a reference into the store"),
    ({"live_prev": True}, "copies", "fn mutated the stored value in place"),
    ({"forget_on_restart": True}, "durability", "the value did not survive closing every handle"),
]


@pytest.mark.parametrize("flags,test,note", FAILS)
def test_each_contract_breach_fails_with_its_exact_note(flags, test, note):
    b = Backend(**flags)
    rep, res = kit(b)
    assert (res[test].status, res[test].note) == ("fail", note)
    assert not rep.ok


def test_the_caller_value_and_stored_value_mutations_are_the_exact_ones():
    b = Backend(alias_put=True)
    kit(b)
    (ck,) = [k for k in b.m if k.startswith("copy:")]
    assert b.m[ck] == {"list": [1, 2]}
    b = Backend(alias_get=True)
    kit(b)
    (ck,) = [k for k in b.m if k.startswith("copy:")]
    assert b.m[ck] == {"list": [1, 3]}
    b = Backend(live_prev=True)
    kit(b)
    (ck,) = [k for k in b.m if k.startswith("copy:")]
    assert b.m[ck] == {"list": [1, 9]}


def test_lost_updates_are_reported_with_the_counts():
    b = Backend(cap=2)
    _, res = kit(b, threads=6, rounds=3, handles=3)
    assert (res["increments"].status, res["increments"].note) == ("fail", "lost updates: 2 of 18")
    assert (res["cross-handle"].status, res["cross-handle"].note) == ("fail", "lost updates over 3 handles: 2 of 6")


def test_the_first_cross_handle_is_the_one_read_back():
    b = Backend(stale_idx=3)  # semantics 0, copies 1, increments 2, then the cross handles 3..6
    _, res = kit(b)
    assert (res["cross-handle"].status, res["cross-handle"].note) == ("fail", "lost updates over 4 handles: 15 of 16")
    b = Backend(stale_idx=4)
    _, res = kit(b)
    assert res["cross-handle"].status == "pass"


class OnlyUpdate:
    def update(self, k, f):
        return None


class OnlyGet:
    def get(self, k):
        return None


class NonCallableGet:
    get = 5

    def update(self, k, f):
        return None


class NonCallableUpdate:
    update = None

    def get(self, k):
        return None


@pytest.mark.parametrize("cls", [object, OnlyUpdate, OnlyGet, NonCallableGet, NonCallableUpdate])
def test_a_handle_missing_either_method_is_refused_with_the_exact_message(cls):
    rep = run_atomic_kv_conformance(lambda: cls(), durable=False, shared=False)
    for name in ("semantics", "copies", "increments"):
        r = next(x for x in rep.results if x.test == name)
        assert (r.status, r.note) == ("fail", "the store has no get(key) and update(key, fn)")


# ------------------------------------------------------------------------------------------------ sqlite connection


def test_the_sqlite_store_connects_with_its_timeout_autocommit_and_cross_thread_use(tmp_path, monkeypatch):
    calls = []
    real = AK.sqlite3.connect

    def spy(*a, **k):
        calls.append((a, k))
        return real(*a, **k)

    monkeypatch.setattr(AK.sqlite3, "connect", spy)
    path = str(tmp_path / "kv.db")
    s = AK.SqliteAtomicKv(path, timeout=7.5)
    assert calls[0] == ((path,), {"timeout": 7.5, "isolation_level": None, "check_same_thread": False})
    s.close()
    calls.clear()
    AK.SqliteAtomicKv(path).close()
    assert calls[0][1]["timeout"] == 30.0


# ------------------------------------------------------------------------------------------------ ed25519 point gate


class _Reached(BaseException):
    pass


def test_an_undecodable_key_or_nonce_point_is_refused_before_any_group_arithmetic(monkeypatch):
    seed = bytes(range(32))
    pub, msg = E.public_key(seed), b"m"
    sig = E.sign(seed, msg)
    assert E.verify(pub, msg, sig) is True
    real = E._decode

    def boom(*a):
        raise _Reached()

    for bad in (pub, sig[:32]):
        monkeypatch.setattr(E, "_decode", lambda s, bad=bad: None if bytes(s) == bad else real(s))
        monkeypatch.setattr(E, "_mul", boom)
        assert E.verify(pub, msg, sig) is False
        monkeypatch.undo()


# ------------------------------------------------------------------------------------------------ OID group counter


def _dotted_first_arc(content):
    v = 0
    for b in content:
        v = (v << 7) | (b & 0x7F)
    return "2.%d" % (v - 80)


@pytest.mark.parametrize("fn", [der_oid, sig_oid])
def test_a_first_arc_of_exactly_64_groups_is_accepted(fn):
    content = [0x81] * 63 + [0x01]
    assert fn(content) == _dotted_first_arc(content)


# ------------------------------------------------------------------------------------------------ compact JWS size cap

LIMIT = 16 * 1024 * 1024


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def test_a_header_or_payload_of_exactly_the_limit_parses():
    head, pay = b'{"alg":"ES256"}', b"{}"
    sig = _b64u(b"sig")
    got = C.parse_jws("%s.%s.%s" % (_b64u(head.rjust(LIMIT)), _b64u(pay), sig), "f")
    assert got["header"] == {"alg": "ES256"} and got["payload"] == {}
    got = C.parse_jws("%s.%s.%s" % (_b64u(head), _b64u(pay.rjust(LIMIT)), sig), "f")
    assert got["header"] == {"alg": "ES256"} and got["payload"] == {}
    for h, p in ((head.rjust(LIMIT + 1), pay), (head, pay.rjust(LIMIT + 1))):
        with pytest.raises(TypeError) as e:
            C.parse_jws("%s.%s.%s" % (_b64u(h), _b64u(p), sig), "f")
        assert str(e.value) == "f: malformed JSON segment: input too large"


# ------------------------------------------------------------------------------------------------ NVIDIA policy and defaults


def test_the_chain_revocation_default_requires_a_crl_for_cdp_certificates():
    assert inspect.signature(N.check_nvidia_chain_revocation).parameters["require_for"].default == "cdp"


def _fw_error(fw):
    with pytest.raises(AttestConstructError) as e:
        N._compile_firmware_policy(fw)
    return str(e.value)


def test_a_non_string_minimum_is_named_in_key_order():
    assert _fw_error({"minDriverVersion": 5, "minVbiosVersion": 6}) == "nvidiaCollateralHook: malformed minDriverVersion '5'"
    assert _fw_error({"minDriverVersion": "abc", "minVbiosVersion": 7}) == "nvidiaCollateralHook: malformed minVbiosVersion '7'"
    assert _fw_error({"minDriverVersion": 5}) == "nvidiaCollateralHook: malformed minDriverVersion '5'"
    assert _fw_error({"minVbiosVersion": 8}) == "nvidiaCollateralHook: malformed minVbiosVersion '8'"
    assert _fw_error({"minDriverVersion": "abc"}) == "nvidiaCollateralHook: malformed minDriverVersion 'abc'"


# ------------------------------------------------------------------------------------------------ RSASSA-PSS parameters

SHA256 = seq(oid("2.16.840.1.101.3.4.2.1"), tlv(5))
SHA384 = seq(oid("2.16.840.1.101.3.4.2.2"), tlv(5))
MGF1 = "1.2.840.113549.1.1.8"
OID_PSS = "1.2.840.113549.1.1.10"


def _pss(*parts, trailer=b""):
    der = seq(*parts) + trailer
    return bounded(AC._pss_params, der, _tlv_at(der, 0))


def test_every_pss_parameter_is_read_and_the_walk_stops_at_the_sequence_end():
    assert _pss() == ("sha1", "sha1", 20)
    assert _pss(tlv(0xA0, SHA256), tlv(0xA1, seq(oid(MGF1), SHA384)), tlv(0xA2, tlv(2, b"\x01\x00")), tlv(0xA3, integer(1))) == ("sha256", "sha384", 256)
    assert _pss(tlv(0xA2, tlv(2, b"\x01\x00\x00")), tlv(0xA0, SHA384)) == ("sha384", "sha1", 65536)
    assert _pss(tlv(0xA2, tlv(2, b"\x00"))) == ("sha1", "sha1", 0)
    assert _pss(tlv(0xA1, seq(oid(MGF1), SHA256))) == ("sha1", "sha256", 20)
    assert _pss(tlv(0xA3, integer(1))) == ("sha1", "sha1", 20)
    # bytes after the parameters SEQUENCE are not part of it
    assert _pss(tlv(0xA0, SHA256), trailer=tlv(0xA2, integer(99))) == ("sha256", "sha1", 20)
    assert _pss(trailer=tlv(0xA4, integer(1))) == ("sha1", "sha1", 20)
    assert _pss(tlv(0xA1, seq(oid(MGF1), SHA384)), trailer=tlv(0xA0, SHA256)) == ("sha1", "sha384", 20)


def test_a_pss_trailer_field_other_than_one_is_refused():
    for part in (tlv(0xA3, integer(2)), tlv(0xA3, octets(b"\x01"))):
        with pytest.raises(AC.CertError) as e:
            _pss(part)
        assert str(e.value) == "trailer field is not 1"


# ------------------------------------------------------------------------------------------------ PSS issuer key shape


def test_an_issuer_key_whose_pss_parameters_are_not_a_sequence_never_verifies():
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    alg = seq(oid(OID_PSS), seq(tlv(0xA0, SHA256), tlv(0xA1, seq(oid(MGF1), SHA256)), tlv(0xA2, integer(32))))
    sig = priv.sign(b"m", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    assert AC._verify_signature(alg, b"m", sig, C._RsaPssPublicKey(priv.public_key(), seq(oid(OID_PSS)))) is True
    assert AC._verify_signature(alg, b"m", sig, C._RsaPssPublicKey(priv.public_key(), seq(oid(OID_PSS), tlv(5)))) is False
