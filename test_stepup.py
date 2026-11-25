"""Step-up client for the principal's device: the device key (RFC 8032 vectors), the secret stores and the client against a
fake transport (no network)."""
import json
import os
import stat

import pytest

from atlas_pca import (ApiError, FileSecretStore, InvalidSecret, InvalidThresholdMessage, MemorySecretStore, NoDeviceKey,
                       PrincipalDeviceKey, PrincipalMismatch, StepUpClient, TransportError, ed25519)
from atlas_pca.pca import b64u, decode_b64u_strict

# RFC 8032 section 7.1 test 1 (empty message) and test 2 (one byte, 0x72)
RFC = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]
NOW = 1_799_999_999_000  # one second before 2027-01-15T08:00:00Z (= 1_800_000_000_000 ms)
MSG = b"threshold message bytes"


@pytest.mark.parametrize("seed, pub, msg, sig", RFC)
def test_rfc8032_vectors(seed, pub, msg, sig):
    sd, m = bytes.fromhex(seed), bytes.fromhex(msg)
    assert ed25519.public_key(sd).hex() == pub
    assert ed25519.sign(sd, m).hex() == sig
    assert ed25519.verify(bytes.fromhex(pub), m, bytes.fromhex(sig))


def test_seed_length_is_checked():
    for bad in (b"", b"x" * 31, b"x" * 33):
        with pytest.raises(ValueError):
            ed25519.sign(bad, b"m")
        with pytest.raises(ValueError):
            ed25519.public_key(bad)


def test_key_lifecycle():
    k = PrincipalDeviceKey(MemorySecretStore())
    assert k.exists is False
    with pytest.raises(NoDeviceKey):
        k.sign(b"m")
    with pytest.raises(NoDeviceKey):
        k.public_key()
    pub = k.generate()
    assert k.exists and k.public_key() == pub
    sig = decode_b64u_strict(k.sign(MSG), 64)
    assert ed25519.verify(decode_b64u_strict(pub, 32), MSG, sig)
    other = PrincipalDeviceKey(MemorySecretStore())
    assert other.import_secret(k.export_secret()) == pub
    k.delete()
    assert k.exists is False


@pytest.mark.parametrize("bad", ["", "AAAA", "not base64!", b64u(b"x" * 31), b64u(b"x" * 33), b64u(b"x" * 32) + "="])
def test_import_rejects_a_bad_secret(bad):
    with pytest.raises(InvalidSecret):
        PrincipalDeviceKey(MemorySecretStore()).import_secret(bad)


def test_file_store_is_private_and_roundtrips(tmp_path):
    path = str(tmp_path / "principal.key")
    k = PrincipalDeviceKey(FileSecretStore(path))
    pub = k.generate()
    if os.name != "nt":  # Windows has no POSIX permission bits (chmod only toggles read-only)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert PrincipalDeviceKey(FileSecretStore(path)).public_key() == pub
    k.delete()
    assert not os.path.exists(path) and k.exists is False


# ---- the client ----------------------------------------------------------------------------------------------------------

class Fake:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        a = self.answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a


def _client(fake, key=None):
    key = key or PrincipalDeviceKey(MemorySecretStore())
    if not key.exists:
        key.generate()
    return StepUpClient("https://dash.example/", "https://atlas.example", "acct 1", "ins_1", key, lambda: "tok",
                        transport=fake, now=lambda: NOW), key


def _list(*items):
    return 200, json.dumps({"stepups": list(items)})


def _item(i="su_1", exp="2027-01-15T08:00:00.500Z", msg=None, **kw):
    o = {"id": i, "grant_ref": "g1", "action": {"verb": "payments.send", "resource": "payments/acme"}, "required_t": 2,
         "threshold_message": b64u(MSG) if msg is None else msg, "expires_at": exp}
    o.update(kw)
    return o


def test_pending_lists_unexpired_step_ups_and_sends_the_token_to_the_dashboard_only():
    fake = Fake(_list(_item(), _item("su_old", exp="2020-01-01T00:00:00Z"), _item("su_2", exp="2027-01-15T08:00:00Z")))
    c, _ = _client(fake)
    out = c.pending()
    assert [p.id for p in out] == ["su_1", "su_2"]
    assert (out[0].action_verb, out[0].action_resource, out[0].required_t, out[0].expires_at) == \
        ("payments.send", "payments/acme", 2, 1_800_000_000_500)
    assert out[1].expires_at == 1_800_000_000_000
    m, url, headers, body = fake.calls[0]
    assert (m, body) == ("GET", None)
    assert url == "https://dash.example/v1/dashboard/accounts/acct%201/instances/ins_1/pca/stepups?status=pending"
    assert headers["Authorization"] == "Bearer tok"


def test_pending_parses_the_fraction_exactly():
    for text, ms in (("2027-01-15T08:00:00.5Z", 500), ("2027-01-15T08:00:00.123456Z", 123), ("2027-01-15T08:00:00Z", 0)):
        c, _ = _client(Fake(_list(_item(exp=text))))
        assert c.pending()[0].expires_at == 1_800_000_000_000 + ms


def test_pending_rejects_unreadable_answers():
    for answer in ((200, "not json"), (200, json.dumps({"stepups": "x"})), (200, json.dumps({})),
                   _list(_item(exp="yesterday")), _list(_item(required_t=True)), _list({"id": "x"})):
        c, _ = _client(Fake(answer))
        with pytest.raises(TransportError):
            c.pending()


def test_approve_signs_the_threshold_message_and_never_sends_the_dashboard_token():
    fake = Fake(_list(_item()), (200, json.dumps({"status": "anchored", "allow": True})))
    c, key = _client(fake)
    r = c.approve(c.pending()[0])
    assert (r.status, r.anchored, r.http_status) == ("anchored", True, 200)
    m, url, headers, body = fake.calls[1]
    assert (m, url) == ("POST", "https://atlas.example/v1/pca/stepups/su_1/cosign")
    assert "Authorization" not in headers
    payload = json.loads(body)
    assert payload["role"] == "principal" and payload["publicKey"] == key.public_key()
    assert ed25519.verify(decode_b64u_strict(payload["publicKey"], 32), MSG, decode_b64u_strict(payload["sig"], 64))


def test_approve_202_means_more_roles_are_required():
    c, _ = _client(Fake(_list(_item()), (202, json.dumps({"status": "pending", "allow": False}))))
    r = c.approve(c.pending()[0])
    assert (r.status, r.anchored, r.http_status) == ("pending", False, 202)


def test_approve_maps_errors():
    err = lambda m: json.dumps({"errors": [{"code": "x", "message": m}]})  # noqa: E731
    c, _ = _client(Fake(_list(_item()), (403, err("not the principal")), (500, err("boom")), (502, "<html>")))
    s = c.pending()[0]
    with pytest.raises(PrincipalMismatch, match="not the principal"):
        c.approve(s)
    with pytest.raises(ApiError) as e:
        c.approve(s)
    assert (e.value.status, str(e.value)) == (500, "boom")
    with pytest.raises(ApiError) as e:
        c.approve(s)
    assert (e.value.status, str(e.value)) == (502, "The request failed.")


def test_approve_refuses_a_non_canonical_threshold_message_before_signing():
    fake = Fake(_list(_item(msg="AAAA=")))
    c, _ = _client(fake)
    with pytest.raises(InvalidThresholdMessage):
        c.approve(c.pending()[0])
    assert len(fake.calls) == 1  # nothing was posted


def test_network_failure_is_a_transport_error():
    c, _ = _client(Fake(TransportError("down")))
    with pytest.raises(TransportError):
        c.pending()


def test_deny_posts_the_reason_to_the_dashboard():
    fake = Fake(_list(_item()), (200, "{}"), (200, "{}"))
    c, _ = _client(fake)
    s = c.pending()[0]
    c.deny(s, "not me")
    c.deny(s)
    m, url, headers, body = fake.calls[1]
    assert (m, url, json.loads(body)) == ("POST", "https://dash.example/v1/dashboard/accounts/acct%201/instances/ins_1/pca/stepups/su_1/deny", {"reason": "not me"})
    assert headers["Authorization"] == "Bearer tok" and json.loads(fake.calls[2][3]) == {}


def test_urls_must_be_http():
    for bad in ("ftp://x", "file:///etc/passwd", "dash.example", ""):
        with pytest.raises(ValueError):
            StepUpClient(bad, "https://a.example", "a", "i", PrincipalDeviceKey(MemorySecretStore()), lambda: "t")
