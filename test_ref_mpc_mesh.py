"""The mutual-TLS mesh (atlas_pca.mpc_mesh) over loopback: an honest 3-node exchange, and the refusals (wrong pin, wrong hello id,
oversize, replay, skipped sequence, wrong round, early close, silent peer, unpinned client). Identities come from the `cryptography`
package with fixed seed labels, so every run uses the same keys."""
import asyncio
import socket
import ssl

import pytest

pytest.importorskip("cryptography")

from atlas_pca.mpc_certs import generate_identity  # noqa: E402
from atlas_pca.mpc_mesh import Mesh, MeshConfig, NodeAddr  # noqa: E402
from atlas_pca.mpc_net import NetWire  # noqa: E402

SID = "mesh-test-session"


_HANDED_OUT = set()


def free_port():
    """A port nobody listens on, never handed out twice in this process (a closed ephemeral port can be returned again by the OS, and two
    nodes of one mesh then fought over it)."""
    while True:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port not in _HANDED_OUT:
            _HANDED_OUT.add(port)
            return port


def cfg(self_id, nodes, ident, connect_ms, recv_ms, **kw):
    return MeshConfig(self_id, nodes, ident.key_pem, ident.cert_pem, SID, listen_host="127.0.0.1",
                      connect_timeout_ms=connect_ms, recv_timeout_ms=recv_ms, **kw)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 60))


def test_honest_three_node_exchange():
    async def go():
        n = 3
        ids = [generate_identity("node%d" % i, seed="honest-%d" % i) for i in range(n)]
        nodes = [NodeAddr(i, "127.0.0.1", free_port(), ids[i].cert_pem) for i in range(n)]
        meshes = [Mesh(cfg(i, nodes, ids[i], 20_000, 10_000)) for i in range(n)]
        await asyncio.gather(*[m.connect() for m in meshes])

        async def party(me):
            meshes[me].broadcast("r1", {"x": me})
            return await meshes[me].collect("r1")

        got = await asyncio.gather(*[party(i) for i in range(n)])
        for i in range(n):
            assert len(got[i]) == n - 1
            for k, v in got[i].items():
                assert k != i and v == {"x": k}
        # signatures are verifiable against the pinned certificate only
        data = b"statement"
        sig = meshes[0].sign(data)
        assert meshes[1].verify(0, data, sig)
        assert not meshes[1].verify(2, data, sig)
        assert not meshes[1].verify(0, b"other", sig)
        assert not meshes[0].verify(0, data, sig)
        for m in meshes:
            await m.finish()

    run(go())


def test_pinned_cert_mismatch_refuses_the_link():
    async def go():
        real0 = generate_identity("real0", seed="pin-real0")
        imposter = generate_identity("imposter", seed="pin-imposter")
        id1 = generate_identity("node1", seed="pin-node1")
        p0, p1 = free_port(), free_port()
        # node 1 pins an imposter certificate for node 0, so the real node 0 must be refused
        view0 = [NodeAddr(0, "127.0.0.1", p0, real0.cert_pem), NodeAddr(1, "127.0.0.1", p1, id1.cert_pem)]
        view1 = [NodeAddr(0, "127.0.0.1", p0, imposter.cert_pem), NodeAddr(1, "127.0.0.1", p1, id1.cert_pem)]
        m0 = Mesh(cfg(0, view0, real0, 2_500, 2_000))
        m1 = Mesh(cfg(1, view1, id1, 2_500, 2_000))
        r = await asyncio.gather(m0.connect(), m1.connect(), return_exceptions=True)
        assert isinstance(r[1], NetWire.NetAbort) and r[1].kind in ("timeout", "identity")
        assert isinstance(r[0], Exception)

    run(go())


def test_tamper_hook_needs_explicit_opt_in_and_own_cert_must_match():
    id0 = generate_identity("n0", seed="hook-n0")
    id1 = generate_identity("n1", seed="hook-n1")
    nodes = [NodeAddr(0, "127.0.0.1", 1, id0.cert_pem), NodeAddr(1, "127.0.0.1", 2, id1.cert_pem)]
    with pytest.raises(ValueError):
        Mesh(cfg(0, nodes, id0, 1000, 1000, tamper=lambda ev: [ev["raw"]]))
    Mesh(cfg(0, nodes, id0, 1000, 1000, tamper=lambda ev: [ev["raw"]], unsafe_test_hooks=True))
    with pytest.raises(ValueError):  # a node whose own certificate differs from the one listed for it is refused
        Mesh(cfg(0, nodes, id1, 1000, 1000))


# ---- refusals from a hand-driven peer (node 1 dials node 0) ----

class RawPeer:
    """A raw TLS client speaking the frame format, standing in for node 1."""

    def __init__(self, me, server_cert_pem, port):
        self.me, self.server_cert_pem, self.port = me, server_cert_pem, port
        self.writer = None

    async def open(self):
        import os
        import tempfile
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=self.server_cert_pem)
        with tempfile.TemporaryDirectory() as d:
            kp, cp = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
            open(kp, "w").write(self.me.key_pem)
            open(cp, "w").write(self.me.cert_pem)
            ctx.load_cert_chain(cp, kp)
        last = None
        for _ in range(100):
            try:
                _, self.writer = await asyncio.open_connection("127.0.0.1", self.port, ssl=ctx)
                return self
            except (OSError, ssl.SSLError) as e:
                last = e
                await asyncio.sleep(0.1)
        raise last

    async def frame(self, ty, rd, seq, d):
        self.writer.write(NetWire.encode_frame({"v": NetWire.WIRE_VERSION, "ty": ty, "sid": SID, "seq": seq, "rd": rd, "d": d}))
        await self.writer.drain()

    async def hello(self, claimed):
        await self.frame("hello", "hello", 0, {"id": claimed})

    def close(self):
        if self.writer is not None:
            self.writer.close()


async def _rig(connect_ms, recv_ms):
    id0 = generate_identity("n0", seed="rig-n0")
    id1 = generate_identity("n1", seed="rig-n1")
    p0 = free_port()
    nodes = [NodeAddr(0, "127.0.0.1", p0, id0.cert_pem), NodeAddr(1, "127.0.0.1", 1, id1.cert_pem)]
    m0 = Mesh(cfg(0, nodes, id0, connect_ms, recv_ms))
    return id0, id1, m0, asyncio.ensure_future(m0.connect()), p0


def test_hello_with_wrong_party_id_is_refused():
    async def go():
        id0, id1, m0, conn, port = await _rig(10_000, 5_000)
        p = await RawPeer(id1, id0.cert_pem, port).open()
        try:
            await p.hello(5)
            with pytest.raises(NetWire.NetAbort) as ei:
                await conn
            assert ei.value.kind == "identity" and ei.value.blamed == 1
        finally:
            p.close()

    run(go())


async def _linked(connect_ms=10_000, recv_ms=5_000):
    id0, id1, m0, conn, port = await _rig(connect_ms, recv_ms)
    p = await RawPeer(id1, id0.cert_pem, port).open()
    await p.hello(1)
    await conn
    return m0, p


def _refused(kind, send):
    async def go():
        m0, p = await _linked()
        try:
            await send(p)
            with pytest.raises(NetWire.NetAbort) as ei:
                await m0.recv(1, "x", 5_000)
            assert ei.value.kind == kind and ei.value.blamed == 1
        finally:
            p.close()

    run(go())


def test_oversize_length_prefix_is_refused():
    async def send(p):
        p.writer.write((NetWire.MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
        await p.writer.drain()

    _refused("oversize", send)


def test_replayed_sequence_number_is_refused():
    async def send(p):
        await p.frame("msg", "x", 1, "a")
        await p.frame("msg", "x", 1, "b")

    _refused("duplicate", send)


def test_skipped_sequence_number_is_refused():
    async def send(p):
        await p.frame("msg", "x", 5, "a")

    _refused("out-of-order", send)


def test_wrong_round_is_refused():
    async def send(p):
        await p.frame("msg", "other", 1, "a")

    _refused("wrong-round", send)


def test_early_close_is_a_disconnect():
    async def send(p):
        p.close()

    _refused("disconnect", send)


def test_silent_peer_is_blamed_after_the_deadline():
    async def go():
        m0, p = await _linked()
        try:
            with pytest.raises(NetWire.NetAbort) as ei:
                await m0.recv(1, "x", 300)
            assert ei.value.kind == "timeout" and ei.value.blamed == 1 and ei.value.deadline_ms == 300
        finally:
            p.close()

    run(go())


def test_client_with_an_unpinned_certificate_never_links():
    async def go():
        id0, _id1, _m0, conn, port = await _rig(2_000, 1_000)
        stranger = generate_identity("stranger", seed="rig-stranger")
        p = RawPeer(stranger, id0.cert_pem, port)
        try:
            await p.open()
            await p.hello(1)  # the server may refuse the unpinned client before or after our handshake completes
        except (OSError, ssl.SSLError):
            pass
        finally:
            p.close()
        with pytest.raises(NetWire.NetAbort) as ei:
            await conn
        assert ei.value.kind == "timeout"

    run(go())
