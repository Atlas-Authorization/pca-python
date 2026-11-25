"""Fast mutation-kill tests that conftest.py orders before the slow tests: each decides, with an ordinary assertion, a mutant that a
later test only reaches after so much slow work that the per-mutant CPU limit expires first (a run error instead of a kill).
Small inputs, no subprocess, no network. The sigstore tests reuse the hand-built DER helpers of the stores group."""
import inspect
import types

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from atlas_pca import attest_common as AC  # noqa: E402
import importlib  # noqa: E402
from atlas_pca import intent_history as IH  # noqa: E402
from atlas_pca import operations as EO  # noqa: E402
from atlas_pca import sigstore_bundle as S  # noqa: E402
from atlas_pca.pca import EMPTY_PARAMS_DIGEST  # noqa: E402

Z = importlib.import_module("atlas_pca.authorize")  # the package attribute `authorize` is the function
from test_k05_kill_stores_sigstore import BC, INT, ISSUER, ROOTS, SCT_OID, _cert, _ext, _lst, _leaf, _sct, der  # noqa: E402
from test_k05c_deadline import bounded  # noqa: E402
import hashlib  # noqa: E402


def _msg(exp):
    with pytest.raises(TypeError) as e:
        AC.attestation_binding(exp)
    return str(e.value)


def test_binding_messages_are_exact():
    # holderPub required (the message text), and an empty / non-string grantRef is refused with its own message
    assert _msg({"grantRef": "g", "epoch": 1, "nonce": "n"}) == "binding: holderPub required"
    assert _msg({"holderPub": "h", "grantRef": "", "epoch": 1, "nonce": "n"}) == "binding: grantRef required"
    # `or` -> `and` would reach len(None) and raise a different message
    assert _msg({"holderPub": "h", "epoch": 1, "nonce": "n"}) == "binding: grantRef required"


def test_ecdsa_verify_raw_each_refusal_is_false_and_a_good_signature_true():
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key()
    assert AC.ecdsa_verify_raw(object(), b"\x01" * 64, b"d", "sha256") is False  # not an EC key
    assert AC.ecdsa_verify_raw(pub, b"\x01" * 63, b"d", "sha256") is False  # wrong length
    assert AC.ecdsa_verify_raw(pub, b"\x00" * 32 + b"\x01" * 32, b"d", "sha256") is False  # r == 0
    assert AC.ecdsa_verify_raw(pub, b"\x01" * 32 + b"\x00" * 32, b"d", "sha256") is False  # s == 0
    assert AC.ecdsa_verify_raw(pub, b"\x01" * 64, b"d", "sha256") is False  # well formed, wrong
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(key.sign(b"d", ec.ECDSA(hashes.SHA256())))
    assert AC.ecdsa_verify_raw(pub, r.to_bytes(32, "big") + s.to_bytes(32, "big"), b"d", "sha256") is True


@pytest.fixture
def accept(monkeypatch):
    monkeypatch.setattr(S, "_verify", lambda *a: True)


def test_sct_embedded_list_is_found_and_parsed(accept):
    # a valid leaf is accepted: `e = None` answers "no embedded SCT"; the tag test inverted answers "not an OCTET STRING"
    assert S._verify_sct(_leaf(_lst(_sct())), ISSUER, ROOTS) is None


def test_sct_list_that_is_not_an_octet_string_is_named(accept):
    # `_tlv(None, 0)` cannot parse the extension value, so the message below is never produced
    leaf = S._parse_cert(_cert(_ext(SCT_OID, der(0x30, _lst(_sct())))))
    assert S._verify_sct(leaf, ISSUER, ROOTS) == "SCT list is not an OCTET STRING"
    assert S._verify_sct(S._parse_cert(_cert(BC)), ISSUER, ROOTS) == "no embedded SCT"


def test_forbid_clause_source_receives_the_operation_and_the_grant():
    seen = []
    p = {"grant_ref": "r"}
    f = {"clauses": lambda op, g: seen.append((op, g)) or []}  # the decision itself is not under test: only what the source is called with
    Z._forbid_refusal(p, f, {"verb": "v"}, lambda ref: "GRANT", None)
    assert seen == [({"verb": "v"}, "GRANT")]


def test_execute_authorized_default_recheck_for_is_irreversible():
    assert inspect.signature(EO.execute_authorized).parameters["recheck_for"].default == "irreversible"
    # behavior: a reversible operation is not re-checked by default, only with recheck_for="always"
    calls = []
    az = types.SimpleNamespace(allow=True, pcactn={"action": {"reversibility_class": "reversible"}},
                               operation=Z.AuthorizedOperation(verb="v", resource="/r", params_digest=EMPTY_PARAMS_DIGEST, id="o1"))
    rc = lambda h: calls.append(1) or {"ok": True}  # noqa: E731
    EO.execute_authorized(az, lambda h: 1, store=EO.MemoryOperationStore(), recheck=rc, reversibility_class="reversible", now=lambda: 1)
    assert calls == []


def test_responds_within_pending_state_is_a_string():
    m = {"kind": "responds_within", "p": {"verb": "a"}, "q": {"verb": "b"}, "within": 4}
    e = {"status": "reserved", "verb": "a", "resource": "r", "params": {}}
    assert IH.monitor_step(m, "idle", e) == "pending:4"


@pytest.fixture
def sct_calls(monkeypatch):
    out = {"log": [], "result": False}

    def fake(hash_name, data, key, sig):
        out["log"].append((hash_name, data, key, sig))
        return out["result"]
    monkeypatch.setattr(S, "_verify", fake)
    return out


def _sct_verify(*scts, roots=ROOTS):
    return bounded(S._verify_sct, _leaf(_lst(*scts)), ISSUER, roots)


def test_attestation_binding_of_a_well_formed_expectation_is_a_sha512_digest():
    # a mutant that drops the byte order of the epoch raises TypeError here, a decided failure
    d = AC.attestation_binding({"holderPub": "h", "grantRef": "g", "epoch": 1, "nonce": "n"})
    assert isinstance(d, bytes) and len(d) == 64


def test_sct_walk_terminates_and_signs_the_rfc6962_structure(sct_calls):
    # decided by an ordinary assertion under a hard deadline: a mutant that no longer advances the cursor, slices one byte too far,
    # swaps the entry skip, or changes a field of the signed structure fails here instead of running into the per-mutant CPU limit
    sct_calls["result"] = True
    assert _sct_verify(_sct(ext=b"\xab\xcd")) is None
    tbs = der(0x30, INT + der(0xA3, der(0x30, BC)))  # the leaf TBS without the SCT list
    signed = (b"\x00\x00" + (150).to_bytes(8, "big") + b"\x00\x01" + hashlib.sha256(b"SPKI").digest() + len(tbs).to_bytes(3, "big") + tbs
              + b"\x00\x02" + b"\xab\xcd")
    assert sct_calls["log"] == [("sha256", signed, "KEY", b"SIG")]


def test_sct_two_entries_are_each_walked_to_their_own_end(sct_calls):
    sct_calls["result"] = False
    assert _sct_verify(_sct(), _sct(ts=160)) == "SCT signature invalid"
    assert len(sct_calls["log"]) == 2  # both entries were reached: the cursor moved past the first by exactly its length


def test_sct_entry_shape_refusals_are_exact(sct_calls):
    v = _sct_verify
    none = "no SCT from a pinned CT log"
    assert v(_sct(version=1)) == none and v(_sct(log_id=b"O" * 32)) == none  # skipped entries
    assert sct_calls["log"] == []
    s46 = _sct(sig=b"")[:-1]
    assert v(s46) == "SCT truncated"
    s = _sct()
    claim = (len(s) + 1).to_bytes(2, "big") + s
    assert bounded(S._verify_sct, _leaf(len(claim).to_bytes(2, "big") + claim), ISSUER, ROOTS) == "SCT truncated"
    assert v(_sct() + b"\x00") == "SCT malformed"
    assert v(_sct()[:-1]) == "SCT malformed"
    sct_calls["result"] = True
    assert v(_sct(sig=b"")) is None  # 47 bytes is the minimum
    assert sct_calls["log"][-1][3] == b""
