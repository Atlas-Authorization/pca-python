"""A three-party FROST DKG over real loopback mutual-TLS 1.3 links with pinned peer certificates (generated here, self-signed, one per party), plus the
refusals the node promises: a client whose certificate is not pinned never gets a link, and a plain TCP client is dropped before any DKG byte. Needs
libsodium (the ``ristretto`` extra) and the ``cryptography`` package."""
import datetime
import os
import socket
import threading

import pytest

pytest.importorskip("pysodium")
x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from atlas_pca.frost_dkg_channel import DkgChannelError, run_dkg_over_channel  # noqa: E402
from atlas_pca.frost_dkg_tls import start_tls_dkg_node  # noqa: E402


def _identity(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            cert.public_bytes(serialization.Encoding.PEM).decode())


def _nodes(ids, sid):
    ident = {i: _identity("p%d" % i) for i in ids}
    return ident, {i: start_tls_dkg_node(i, sid, ident[i][0], ident[i][1], [{"id": j, "certPem": ident[j][1]} for j in ids if j != i]) for i in ids}


def test_three_parties_complete_a_dkg_over_loopback_tls():
    ids, sid = [1, 2, 3], os.urandom(32)
    ident, nodes = _nodes(ids, sid)
    out, errs = {}, []

    def party(i):
        try:
            ch = nodes[i].connect([{"id": j, "host": "127.0.0.1", "port": nodes[j].port} for j in ids if j < i], 15000)
            out[i] = run_dkg_over_channel(ch, 2, ids, sid, 15000)
        except Exception as e:  # noqa: BLE001
            errs.append((i, e))
    ts = [threading.Thread(target=party, args=(i,)) for i in ids]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    for n in nodes.values():
        n.close()
    assert not errs, errs
    assert {i: r["qualified"] for i, r in out.items()} == {1: ids, 2: ids, 3: ids}
    assert len({r["keyPackage"]["groupPublicKey"] for r in out.values()}) == 1


def test_a_client_without_a_pinned_certificate_and_a_plain_client_get_no_link():
    ids, sid = [1, 2], os.urandom(32)
    ident, nodes = _nodes(ids, sid)
    stranger = start_tls_dkg_node(2, sid, *_identity("evil"), [{"id": 1, "certPem": ident[1][1]}])  # presents a certificate node 1 never pinned
    plain = socket.create_connection(("127.0.0.1", nodes[1].port))
    plain.sendall(b"\x00\x00\x00\x05hello")
    with pytest.raises(DkgChannelError) as e:
        stranger.connect([{"id": 1, "host": "127.0.0.1", "port": nodes[1].port}], 600)
    assert e.value.code == "timeout"
    with pytest.raises(DkgChannelError) as e2:
        nodes[1].connect([], 400)  # nobody linked: the plain and the stranger connections never became links
    assert e2.value.code == "timeout"
    plain.close()
    for n in (*nodes.values(), stranger):
        n.close()
