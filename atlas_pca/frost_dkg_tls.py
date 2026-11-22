"""Length-prefixed framing for a DKG link (the TLS transport's wire format): a 4-byte big-endian payload length followed by the payload. A decoder refuses a
frame whose declared length exceeds the message cap BEFORE buffering it, so a hostile peer cannot make the node allocate a gigabyte. A port of the framing
loop of the reference TLS node; :func:`start_tls_dkg_node` is the transport: one mutual-TLS 1.3 connection per pair of participants, pinned by certificate."""
from __future__ import annotations

import hashlib
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

from .frost_dkg_channel import DKG_MAX_MESSAGE_BYTES, DkgChannelError, DkgInbox, encode_dkg_message
from .private_fs import mkdtemp_private, open_private
from .pca import b64u  # noqa: F401  (kept for parity with the channel module's imports)

__all__ = ["frame_encode", "FrameDecoder", "start_tls_dkg_node", "TlsDkgNode"]


def frame_encode(payload: bytes) -> bytes:
    """``len(payload)`` as 4 big-endian bytes, then the payload."""
    return len(payload).to_bytes(4, "big") + bytes(payload)


class FrameDecoder:
    """Incremental frame reader: ``feed(chunk)`` appends bytes and returns the complete payloads now available. After a frame over the cap ``error`` is
    ``"oversize"`` and every later chunk is ignored; ``buffered`` is the number of bytes held for an unfinished frame."""

    def __init__(self, max_frame: int = DKG_MAX_MESSAGE_BYTES) -> None:
        self._max = max_frame
        self._buf = b""
        self.error: Optional[str] = None

    @property
    def buffered(self) -> int:
        return len(self._buf)

    def feed(self, chunk: bytes) -> List[bytes]:
        out: List[bytes] = []
        if self.error:
            return out
        self._buf += bytes(chunk)
        while len(self._buf) >= 4:
            n = int.from_bytes(self._buf[:4], "big")
            if n > self._max:
                self.error = "oversize"
                break
            if len(self._buf) < 4 + n:
                break
            out.append(self._buf[4:4 + n])
            self._buf = self._buf[4 + n:]
        return out


def _fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _contexts(key_pem: str, cert_pem: str, trusted_pems: List[str], server: bool) -> ssl.SSLContext:
    """A TLS 1.3 context presenting our certificate and trusting exactly the given peer certificates; the key and certificate go through a private
    temporary directory because the ssl module reads them from files only."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # pinned by certificate, not by host name
    d = mkdtemp_private("pca-tls-")
    try:
        kp, cp = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
        for p, txt in ((kp, key_pem), (cp, cert_pem)):
            with os.fdopen(open_private(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL), "w") as f:
                f.write(txt)
        ctx.load_cert_chain(cp, kp)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    ctx.load_verify_locations(cadata="\n".join(trusted_pems))
    return ctx


class TlsDkgNode:
    """One participant's listener and links. ``port`` is the listening port; ``connect(addresses)`` dials the LOWER-numbered peers (the higher id dials),
    waits until every peer is linked and returns the channel for :func:`atlas_pca.frost_dkg_channel.run_dkg_over_channel`; ``close()`` ends everything."""

    def __init__(self, self_id: int, session_id: bytes, key_pem: str, cert_pem: str, peer_certs: List[Dict[str, Any]], listen_port: int, listen_host: str) -> None:
        self.self_id, self._sid, self._key, self._cert = self_id, session_id, key_pem, cert_pem
        self._peer_pem = {p["id"]: p["certPem"] for p in peer_certs}
        self._pinned: Dict[str, int] = {}
        for p in peer_certs:
            fp = _fingerprint(ssl.PEM_cert_to_DER_cert(p["certPem"]))
            self._pinned[fp] = p["id"]
        if len(self._pinned) != len(peer_certs) or any(p["id"] == self_id for p in peer_certs):
            raise ValueError("startTlsDkgNode: peer certificates must be distinct and none may be this node")
        self.peers = sorted(p["id"] for p in peer_certs)
        self._inbox = DkgInbox(session_id, self.peers)
        self._links: Dict[int, ssl.SSLSocket] = {}
        self._socks: set = set()
        self._cv = threading.Condition()
        self._closed = False
        self._server_ctx = _contexts(key_pem, cert_pem, list(self._peer_pem.values()), True)
        self._lsock = socket.create_server((listen_host, listen_port))
        self.port = self._lsock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    # -- links
    def _attach(self, pid: int, sock: ssl.SSLSocket, first: bytes = b"") -> None:
        with self._cv:
            self._links[pid] = sock
            self._cv.notify_all()
        threading.Thread(target=self._read_loop, args=(pid, sock, first), daemon=True).start()

    def _read_loop(self, pid: int, sock: ssl.SSLSocket, first: bytes = b"") -> None:
        dec = FrameDecoder()
        try:
            chunk = first
            while True:
                if not chunk:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                for payload in dec.feed(chunk):
                    self._inbox.accept(pid, payload)
                chunk = b""
                if dec.error:
                    self._inbox.fail(pid, DkgChannelError("oversize", pid, "frame exceeds the cap"))
                    break
        except OSError:
            pass
        finally:
            with self._cv:
                if self._links.get(pid) is sock:
                    del self._links[pid]
                self._socks.discard(sock)
            try:
                sock.close()
            except OSError:
                pass
            self._inbox.peer_gone(pid)

    def _accept_loop(self) -> None:
        while not self._closed:
            try:
                raw, _ = self._lsock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw: socket.socket) -> None:
        sock = None
        try:
            raw.settimeout(10)
            sock = self._server_ctx.wrap_socket(raw, server_side=True)
            der = sock.getpeercert(binary_form=True)
            pid = self._pinned.get(_fingerprint(der)) if der else None
            with self._cv:
                refuse = pid is None or pid < self.self_id or pid in self._links or self._closed  # a lower id is dialled, never accepted
                if not refuse:
                    self._socks.add(sock)
            if refuse:
                sock.close()
                return
            sock.settimeout(None)
            self._attach(pid, sock)
        except (OSError, ssl.SSLError):
            try:
                (sock or raw).close()
            except OSError:
                pass

    def _dial(self, pid: int, host: str, port: int, stop: threading.Event) -> None:
        ctx = _contexts(self._key, self._cert, [self._peer_pem[pid]], False)
        while not stop.is_set() and not self._closed:
            raw = None
            try:
                raw = socket.create_connection((host, port), timeout=5)
                sock = ctx.wrap_socket(raw)
                der = sock.getpeercert(binary_form=True)
                if not der or self._pinned.get(_fingerprint(der)) != pid:
                    sock.close()
                else:
                    # TLS 1.3 completes the client side before the server has judged our certificate: a short read tells a refusal (alert or EOF)
                    # from silence; bytes a pinned peer already sent are kept and fed to the reader.
                    sock.settimeout(0.15)
                    try:
                        first = sock.recv(65536)
                    except socket.timeout:
                        first = None
                    if first == b"":
                        raise OSError("peer closed the link")
                    sock.settimeout(None)
                    with self._cv:
                        self._socks.add(sock)
                    self._attach(pid, sock, first or b"")
                    return
            except (OSError, ssl.SSLError):
                if raw is not None:
                    try:
                        raw.close()
                    except OSError:
                        pass
            time.sleep(0.05)

    def connect(self, addresses: List[Dict[str, Any]], connect_timeout_ms: float = 15000) -> Any:
        stop = threading.Event()
        for a in addresses:
            if a["id"] not in self.peers:
                raise DkgChannelError("identity", a["id"], "address for a participant that is not a pinned peer")
            if a["id"] < self.self_id:
                threading.Thread(target=self._dial, args=(a["id"], a["host"], a["port"], stop), daemon=True).start()
        deadline = time.monotonic() + connect_timeout_ms / 1000.0
        with self._cv:
            while len(self._links) < len(self.peers):
                left = deadline - time.monotonic()
                if left <= 0:
                    stop.set()
                    missing = [p for p in self.peers if p not in self._links]
                    self._cv.release()
                    try:
                        self.close()
                    finally:
                        self._cv.acquire()
                    raise DkgChannelError("timeout", missing[0], "no authenticated link to %s" % ",".join(str(m) for m in missing))
                self._cv.wait(left)
        stop.set()
        return _TlsChannel(self)

    def write(self, to: int, kind: str, body: Any) -> None:
        sock = self._links.get(to)
        if sock is None:
            raise DkgChannelError("closed", to, "no authenticated link")
        frame = frame_encode(encode_dkg_message(self._sid, kind, body))
        try:
            sock.sendall(frame)
        except OSError:
            raise DkgChannelError("closed", to, "write failed")

    def close(self) -> None:
        self._closed = True
        self._inbox.close()
        try:
            self._lsock.close()
        except OSError:
            pass
        with self._cv:
            socks = list(self._socks) + list(self._links.values())
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


class _TlsChannel:
    def __init__(self, node: TlsDkgNode) -> None:
        self._n = node
        self.self = node.self_id
        self.peers = node.peers

    def broadcast(self, kind: str, body: Any) -> None:
        for p in self.peers:
            self._n.write(p, kind, body)

    def send(self, to: int, kind: str, body: Any) -> None:
        if to not in self.peers:
            raise DkgChannelError("identity", to, "not a connected peer")
        self._n.write(to, kind, body)

    def collect(self, kind: str, from_ids: List[int], timeout_ms: Any) -> Dict[Any, Any]:
        return self._n._inbox.collect(kind, from_ids, timeout_ms)

    def close(self) -> None:
        self._n.close()


def start_tls_dkg_node(self_id: int, session_id: bytes, key_pem: str, cert_pem: str, peer_certs: List[Dict[str, Any]], listen_port: int = 0,
                       listen_host: str = "127.0.0.1") -> TlsDkgNode:
    """Start one participant: ``peer_certs`` is ``[{"id", "certPem"}]`` for every OTHER participant (each trusted exactly, and its SHA-256 fingerprint maps
    to its id, so the sender the driver sees comes from the handshake and never from message content). A peer without a pinned certificate, a plaintext
    or TLS 1.2 client, a second connection for a linked identity and a connection from a party that should have been dialled are refused before any DKG
    byte is read."""
    return TlsDkgNode(self_id, session_id, key_pem, cert_pem, peer_certs, listen_port, listen_host)
