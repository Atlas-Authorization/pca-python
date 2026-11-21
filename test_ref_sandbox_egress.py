"""The egress proxy server: loopback-only (127.0.0.1, ephemeral ports), no external network. The policy logic itself is
replayed against the shared corpus in the sandbox replay test; this covers the I/O layer."""
import asyncio

from atlas_pca.authorize import AuthorizeResult, AuthorizedOperation
from atlas_pca.pca import params_digest
from atlas_pca.sandbox import EgressPolicy, ReceiptLog, verify_receipt_chain
from atlas_pca.sandbox_egress import EgressProxy

OP = {"verb": "http.get", "resource": "api", "params": {"x": 1}}


def _result():
    b = AuthorizedOperation(OP["verb"], OP["resource"], params_digest(OP["params"]), "op1")
    return AuthorizeResult(allow=True, status=200, operation=b, decision="allow")


def _policy(port, **t):
    p = EgressPolicy()
    tmpl = {"method": "GET", "scheme": "http", "host": "127.0.0.1", "port": port, "path": "/ok"}
    tmpl.update(t)
    p.admit(_result(), OP, lambda op: tmpl, {"uses": 1})
    return p


async def _upstream(seen):
    async def h(r, w):
        head = await r.readuntil(b"\r\n\r\n")
        seen.append(head)
        w.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nx-up: 1\r\nconnection: close\r\n\r\nhi")
        await w.drain()
        w.close()
    s = await asyncio.start_server(h, "127.0.0.1", 0)
    return s, s.sockets[0].getsockname()[1]


async def _send(port, raw):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(raw)
    await w.drain()
    data = await r.read()
    w.close()
    return data


async def _flow():
    seen = []
    up, uport = await _upstream(seen)
    log = ReceiptLog()
    proxy = await EgressProxy(_policy(uport), log, allow_private=True).start()
    url = "http://127.0.0.1:%d/ok" % uport
    req = ("GET %s HTTP/1.1\r\nhost: x\r\nx-keep: 1\r\nproxy-authorization: secret\r\n\r\n" % url).encode()
    ok = await _send(proxy.port, req)
    assert ok.startswith(b"HTTP/1.1 200") and ok.endswith(b"hi") and b"x-up: 1" in ok
    assert b"x-keep: 1" in seen[0] and b"proxy-authorization" not in seen[0].lower()
    # the single use is spent: the same request is refused and never reaches the upstream
    again = await _send(proxy.port, req)
    assert again.startswith(b"HTTP/1.1 403") and b"spent" in again and len(seen) == 1
    # a different path, a body the template does not allow, chunked framing, an origin-form request: all refused
    for raw in (("GET http://127.0.0.1:%d/other HTTP/1.1\r\n\r\n" % uport).encode(),
                ("POST %s HTTP/1.1\r\ncontent-length: 1\r\n\r\nx" % url).encode(),
                ("GET %s HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n" % url).encode(),
                b"GET /ok HTTP/1.1\r\n\r\n",
                ("GET %s HTTP/1.1\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\nxx" % url).encode()):
        got = await _send(proxy.port, raw)
        assert got.startswith((b"HTTP/1.1 403", b"HTTP/1.1 400")), got
    assert len(seen) == 1
    assert [e["outcome"] for e in log.entries][:2] == ["ok", "refused"]
    assert verify_receipt_chain(log.entries)["ok"]
    await proxy.close()
    up.close()


async def _private_guard():
    seen = []
    up, uport = await _upstream(seen)
    log = ReceiptLog()
    proxy = await EgressProxy(_policy(uport), log).start()  # allow_private defaults to False: loopback upstream is refused
    got = await _send(proxy.port, ("GET http://127.0.0.1:%d/ok HTTP/1.1\r\n\r\n" % uport).encode())
    assert got.startswith(b"HTTP/1.1 502") and not seen
    assert log.entries[-1]["reason"] == "upstream:EACCES"
    await proxy.close()
    up.close()


async def _connect():
    async def echo(r, w):
        w.write(await r.read(4))
        await w.drain()
        w.close()
    up = await asyncio.start_server(echo, "127.0.0.1", 0)
    uport = up.sockets[0].getsockname()[1]
    p = EgressPolicy()
    p.admit(_result(), OP, lambda op: {"method": "GET", "scheme": "https", "host": "127.0.0.1", "port": uport, "path": "/", "tunnel": True})
    proxy = await EgressProxy(p, ReceiptLog(), allow_private=True).start()
    r, w = await asyncio.open_connection("127.0.0.1", proxy.port)
    w.write(("CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n" % uport).encode())
    assert (await r.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
    w.write(b"ping")
    assert await r.read(4) == b"ping"
    w.close()
    # not admitted any more (one use): refused
    assert (await _send(proxy.port, ("CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n" % uport).encode())).startswith(b"HTTP/1.1 403")
    await proxy.close()
    up.close()


def test_proxy_flow():
    asyncio.run(_flow())


def test_proxy_private_guard():
    asyncio.run(_private_guard())


def test_proxy_connect():
    asyncio.run(_connect())
