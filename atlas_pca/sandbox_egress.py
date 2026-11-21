"""The egress forward proxy of the PCA sandbox (stdlib asyncio): the server side of :class:`atlas_pca.sandbox.EgressPolicy`.

Set it as a non-WASM tool's only route out. Every request is claimed against the admissions; a refusal answers 403 and is
receipted. The upstream address is resolved here and checked with ``is_private_address`` (the canonical, stricter rule of
``atlas_pca.sandbox``) BEFORE connecting, and the connection goes to the checked address, so an admitted hostname cannot be
re-pointed at an internal service (no DNS rebinding window). Fail closed: anything the parser does not fully understand is refused.

Differences from the TypeScript server, all stricter: a request body must carry ``Content-Length`` (``Transfer-Encoding`` on a
request is refused with 400, so there is no chunked-framing ambiguity), the connection is closed after every response, and an
upstream address that is not an IP literal after resolution counts as private. Response framing headers are relayed with the raw
body unchanged.
"""
from __future__ import annotations

import asyncio
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .sandbox import EgressPolicy, ReceiptLog, is_private_address

_HOP = frozenset(("connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer",
                  "transfer-encoding", "upgrade", "host"))
_MAX_HEAD = 65536


class _Refused(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status, self.reason = status, reason


async def _read_head(reader: asyncio.StreamReader) -> Tuple[str, List[Tuple[str, str]]]:
    raw = await reader.readuntil(b"\r\n\r\n")
    if len(raw) > _MAX_HEAD:
        raise _Refused(431, "head_too_large")
    try:
        lines = raw[:-4].decode("latin-1").split("\r\n")
    except UnicodeDecodeError:  # pragma: no cover (latin-1 decodes every byte)
        raise _Refused(400, "bad_request")
    headers: List[Tuple[str, str]] = []
    for ln in lines[1:]:
        k, sep, v = ln.partition(":")
        if not sep or not k or k != k.strip() or any(c in k for c in " \t"):
            raise _Refused(400, "bad_header")
        headers.append((k.lower(), v.strip()))
    return lines[0], headers


def _unique(headers: List[Tuple[str, str]], name: str) -> Optional[str]:
    vals = {v for k, v in headers if k == name}
    if len(vals) > 1:
        raise _Refused(400, "duplicate_" + name.replace("-", "_"))
    return next(iter(vals), None)


class EgressProxy:
    """``await EgressProxy(policy, log).start()`` listens on 127.0.0.1 (ephemeral port unless given); ``.port``, ``await .close()``."""

    def __init__(self, policy: EgressPolicy, log: ReceiptLog, runtime_class: str = "egress_default_deny", allow_private: bool = False,
                 max_body_bytes: int = 1 << 20, upstream_timeout_ms: int = 10_000, host: str = "127.0.0.1", port: int = 0,
                 ssl_context: Optional[ssl.SSLContext] = None) -> None:
        self.policy, self.log, self.cls = policy, log, runtime_class
        self.allow_private, self.max_body = allow_private, max_body_bytes
        self.timeout = upstream_timeout_ms / 1000
        self._host, self._port, self._ssl = host, port, ssl_context  # ssl_context: how to verify https upstreams (default: system trust)
        self._server: Optional[asyncio.AbstractServer] = None
        self.port = 0

    async def start(self) -> "EgressProxy":
        self._server = await asyncio.start_server(self._handle, self._host, self._port, limit=_MAX_HEAD + 1024)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    # ---- helpers ------------------------------------------------------------------------------------------------
    def _receipt(self, method: str, url: str, d: Dict[str, Any], outcome: str, reason: str) -> None:
        a = d.get("admission") or {}
        allow = d["allow"]
        self.log.append(self.cls, {"kind": "egress", "subject": {
            "op_id": d["op_id"] if allow else "", "verb": a.get("verb", "") if allow else "",
            "resource": a.get("resource", "") if allow else (method + " " + url)[:256],
            "params_digest": a.get("params_digest", "") if allow else ""}, "outcome": outcome, "reason": reason})

    async def _resolve(self, host: str, port: int) -> str:
        """The first resolved address, after every resolved address passed the private-address rule (a literal is checked as is)."""
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=1)
        addrs = [i[4][0] for i in infos]
        if not addrs or (not self.allow_private and any(is_private_address(a) for a in addrs)):
            raise PermissionError("EACCES")
        return addrs[0]

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: int, body: bytes = b"") -> None:
        head = "HTTP/1.1 %d %s\r\nconnection: close\r\ncontent-length: %d\r\n%s\r\n" % (
            status, {200: "OK", 400: "Bad Request", 403: "Forbidden", 413: "Payload Too Large", 431: "Header Fields Too Large",
                     502: "Bad Gateway"}.get(status, "Error"), len(body), "content-type: application/json\r\n" if body else "")
        writer.write(head.encode("latin-1") + body)
        try:
            await writer.drain()
        except ConnectionError:
            pass

    async def _deny(self, writer: asyncio.StreamWriter, method: str, url: str, reason: str, status: int = 403) -> None:
        self._receipt(method, url, {"allow": False, "reason": reason}, "refused", reason)
        await self._reply(writer, status, ('{"error":"egress_denied","reason":"%s"}' % reason).encode())

    # ---- connection handler -------------------------------------------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._serve(reader, writer)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, asyncio.CancelledError):
            pass
        except Exception:  # noqa: BLE001  (never leak an internal error shape to the tool)
            try:
                await self._reply(writer, 502)
            except Exception:  # noqa: BLE001
                pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line, headers = await _read_head(reader)
            parts = line.split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                raise _Refused(400, "bad_request_line")
            method, url = parts[0], parts[1]
            if any(k == "transfer-encoding" for k, _ in headers):
                raise _Refused(400, "transfer_encoding")
            cl = _unique(headers, "content-length")
            if cl is not None and (not cl.isascii() or not cl.isdigit()):
                raise _Refused(400, "bad_content_length")
            n = int(cl) if cl else 0
        except _Refused as e:
            return await self._deny(writer, "", "", e.reason, e.status)
        if method.upper() == "CONNECT":
            return await self._connect(reader, writer, url)
        if n > self.max_body:
            return await self._deny(writer, method, url, "body_too_large", 413)
        body = await reader.readexactly(n) if n else b""
        d = self.policy.claim({"method": method, "url": url, "body": body})
        if not d["allow"]:
            return await self._deny(writer, method, url, d["reason"])
        u = urlsplit(url)
        host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
        try:
            addr = await self._resolve(host, port)
            ur, uw = await asyncio.wait_for(asyncio.open_connection(
                addr, port, ssl=(self._ssl or ssl.create_default_context()) if u.scheme == "https" else None,
                server_hostname=host if u.scheme == "https" else None), self.timeout)
        except Exception as e:  # noqa: BLE001
            self._receipt(method, url, d, "error", ("upstream:" + ("EACCES" if isinstance(e, PermissionError) else type(e).__name__))[:64])
            return await self._reply(writer, 502)
        sent = False
        try:
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            out = ["%s %s HTTP/1.1" % (method, path), "host: %s" % (u.netloc.rpartition("@")[2]), "connection: close"]
            out += ["%s: %s" % (k, v) for k, v in headers if k not in _HOP]
            uw.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
            await uw.drain()
            sline, uh = await asyncio.wait_for(_read_head(ur), self.timeout)
            sent = True
            status = sline.split(" ")[1] if len(sline.split(" ")) > 1 else "502"
            keep = ["%s: %s" % (k, v) for k, v in uh if k not in _HOP or k == "transfer-encoding"]
            writer.write((sline + "\r\n" + "\r\n".join(keep + ["connection: close"]) + "\r\n\r\n").encode("latin-1"))
            while True:
                chunk = await asyncio.wait_for(ur.read(65536), self.timeout)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
            self._receipt(method, url, d, "ok", "status:" + status)
        except Exception as e:  # noqa: BLE001
            self._receipt(method, url, d, "error", ("upstream:" + type(e).__name__)[:64])
            if not sent:
                await self._reply(writer, 502)
        finally:
            uw.close()

    async def _connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str) -> None:
        d = self.policy.claim({"method": "CONNECT", "url": target})
        if not d["allow"]:
            return await self._deny(writer, "CONNECT", target, d["reason"])
        host, _, port_text = target.rpartition(":")
        host = host.strip("[]")
        try:
            addr = await self._resolve(host, int(port_text))
            ur, uw = await asyncio.wait_for(asyncio.open_connection(addr, int(port_text)), self.timeout)
        except Exception as e:  # noqa: BLE001
            self._receipt("CONNECT", target, d, "error", ("upstream:" + ("EACCES" if isinstance(e, PermissionError) else "error"))[:64])
            return await self._reply(writer, 502)
        self._receipt("CONNECT", target, d, "ok", "tunnel")
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    c = await src.read(65536)
                    if not c:
                        break
                    dst.write(c)
                    await dst.drain()
            except ConnectionError:
                pass
            finally:
                dst.close()

        await asyncio.gather(pump(reader, uw), pump(ur, writer))
