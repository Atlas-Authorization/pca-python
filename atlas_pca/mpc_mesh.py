"""Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3 on asyncio + ssl (research prototype; port of the
reference's packages/pca-mpc/src/net/mesh.ts).

 - MUTUAL TLS with PINNED self-signed certificates (see mpc_certs). A peer is identified by the SHA-256 fingerprint of its
   certificate, never by anything it claims; the claimed id in the hello frame must agree with the pinned fingerprint.
 - Strict framing + per-link sequence numbers. A malformed frame, a duplicate / replayed frame, a skipped (out-of-order) frame, a
   frame for the wrong round or session, or an oversize length prefix aborts the whole run with an ATTRIBUTABLE NetAbort.
 - Timeouts on every receive (no hangs); a silent peer is blamed after recv_timeout_ms.
 - ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort sends an `abort` frame to every
   peer, then closes the sockets. Once failed, nothing further is sent as protocol data (fail closed).
"""
from __future__ import annotations

import asyncio
import re
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .mpc_certs import fingerprint_of, fingerprint_of_der
from .mpc_net import NetWire

NetAbort = NetWire.NetAbort
MAX_MESH_EVENTS = 64  # further non-fatal observations are only counted


class NodeAddr:
    """id, host, port and the node's PUBLIC certificate (PEM): pinned trust anchor + identity."""

    def __init__(self, id: int, host: str, port: int, cert_pem: str):
        self.id, self.host, self.port, self.cert_pem = id, host, port, cert_pem


class MeshClock:
    """Time source for every DECISION the mesh makes by time (receive deadlines, connect deadline, dial retry). The default is the
    wall clock; tests inject a virtual clock so an outcome never depends on machine load."""

    def now(self) -> float:  # milliseconds
        return time.time() * 1000.0

    def set_timer(self, fn: Callable[[], None], ms: float) -> Any:
        return asyncio.get_running_loop().call_later(max(ms, 0) / 1000.0, fn)

    def clear_timer(self, handle: Any) -> None:
        handle.cancel()


WALL_CLOCK = MeshClock()


class MeshConfig:
    def __init__(self, self_id: int, nodes: Sequence[NodeAddr], key_pem: str, cert_pem: str, session_id: str, *,
                 link_to: Optional[Sequence[int]] = None, listen_host: str = "0.0.0.0", connect_timeout_ms: float = 30_000,
                 recv_timeout_ms: float = 20_000, clock: Optional[MeshClock] = None,
                 tamper: Optional[Callable[[Dict[str, Any]], List[bytes]]] = None, unsafe_test_hooks: bool = False,
                 max_inbox_frames: int = 1024, max_inbox_bytes: int = 32 * 1024 * 1024):
        self.self_id, self.nodes, self.key_pem, self.cert_pem, self.session_id = self_id, list(nodes), key_pem, cert_pem, session_id
        self.link_to, self.listen_host = link_to, listen_host
        self.connect_timeout_ms, self.recv_timeout_ms, self.clock = connect_timeout_ms, recv_timeout_ms, clock
        self.tamper, self.unsafe_test_hooks = tamper, unsafe_test_hooks
        self.max_inbox_frames, self.max_inbox_bytes = max_inbox_frames, max_inbox_bytes


class _Link:
    def __init__(self, id: int):
        self.id = id
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.splitter = NetWire.FrameSplitter()
        self.inbox: List[Dict[str, Any]] = []  # {"f", "size", "abort"?}
        self.inbox_bytes = 0
        self.paused = False
        self._resume: Optional[asyncio.Event] = None
        self.send_seq = 0
        self.recv_seq = 0
        self.closed = False
        self.hello_seen = False
        self.bytes_in = self.bytes_out = self.frames_in = self.frames_out = 0
        self.task: Optional[asyncio.Task] = None

    @property
    def resume(self) -> asyncio.Event:
        """Created on first use inside the running loop: before Python 3.10 an Event binds the loop current at construction (a Mesh is built
        outside any loop). Starts set: reading is not paused."""
        if self._resume is None:
            self._resume = asyncio.Event()
            self._resume.set()
        return self._resume


def _sanitize(x: str, mx: int) -> str:
    """Printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging)."""
    return re.sub(r"[^\x20-\x7e]", "?", x)[:mx]


def _server_ctx(cfg: MeshConfig, others: Sequence[NodeAddr], key_path_pair) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    key_path_pair(ctx)
    ctx.load_verify_locations(cadata="".join(n.cert_pem for n in others))
    return ctx


class Mesh:
    def __init__(self, cfg: MeshConfig):
        if cfg.tamper is not None and cfg.unsafe_test_hooks is not True:
            raise ValueError("mesh: the tamper test hook requires unsafe_test_hooks=True (test-only)")
        self.cfg = cfg
        self.self_id = cfg.self_id
        self.clock = cfg.clock or WALL_CLOCK
        self.recv_timeout_ms = cfg.recv_timeout_ms
        self.connect_timeout_ms = cfg.connect_timeout_ms
        self._links: Dict[int, _Link] = {}
        self._pinned: Dict[str, int] = {}  # fingerprint -> node id
        self._server: Optional[asyncio.AbstractServer] = None
        self._failure: Optional[Exception] = None
        self._finished = False
        self._defer_aborts = False
        self._waiters: List[asyncio.Future] = []
        self._tasks: List[asyncio.Task] = []
        self.events: List[str] = []  # non-fatal observations (e.g. a TLS client rejected at the door)
        self.events_dropped = 0
        self._key = serialization.load_pem_private_key(cfg.key_pem.encode("ascii"), None)
        mine = next((n for n in cfg.nodes if n.id == cfg.self_id), None)
        if mine is None or fingerprint_of(mine.cert_pem) != fingerprint_of(cfg.cert_pem):
            raise ValueError("mesh: this node's certificate is not the one listed for it")
        want = cfg.link_to if cfg.link_to is not None else [n.id for n in cfg.nodes if n.id != cfg.self_id]
        for n in cfg.nodes:
            if n.id != cfg.self_id:
                self._pinned[fingerprint_of(n.cert_pem)] = n.id
        for i in want:
            if not any(n.id == i for n in cfg.nodes):
                raise ValueError("mesh: unknown link target %s" % i)
            self._links[i] = _Link(i)

    # ---- small helpers ----

    def _note(self, msg: str) -> None:
        if len(self.events) < MAX_MESH_EVENTS:
            self.events.append(msg)
        else:
            self.events_dropped += 1

    def _wake(self) -> None:
        ws, self._waiters = self._waiters, []
        for w in ws:
            if not w.done():
                w.set_result(None)

    @property
    def session_id(self) -> str:
        return self.cfg.session_id

    @property
    def peers(self) -> List[int]:
        return sorted(self._links)

    @property
    def failed(self) -> Optional[Exception]:
        return self._failure

    def _load_chain(self, ctx: ssl.SSLContext) -> None:
        # ssl wants files; load the PEM pair through a private temp dir (0700) that exists only for the call
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            kp, cp = os.path.join(d, "key.pem"), os.path.join(d, "cert.pem")
            for p, txt in ((kp, self.cfg.key_pem), (cp, self.cfg.cert_pem)):
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(txt)
            ctx.load_cert_chain(cp, kp)

    # ---- connect ----

    async def connect(self) -> None:
        """Listen, dial every lower-numbered link target, and wait until all links are authenticated."""
        selfn = next((n for n in self.cfg.nodes if n.id == self.self_id), None)
        if selfn is None:
            raise ValueError("mesh: self not in nodes")
        others = [n for n in self.cfg.nodes if n.id != self.self_id]
        sctx = _server_ctx(self.cfg, others, self._load_chain)
        self._server = await asyncio.start_server(self._on_incoming, self.cfg.listen_host, selfn.port, ssl=sctx,
                                                  ssl_handshake_timeout=10)
        deadline = self.clock.now() + self.connect_timeout_ms
        for i in self.peers:
            if i < self.self_id:
                self._tasks.append(asyncio.ensure_future(self._dial(i, deadline)))
        # wait for all links to complete the authenticated hello exchange (poll; bounded by the deadline)
        while True:
            if self._failure:
                raise self._failure
            missing = [i for i in self.peers if not self._links[i].hello_seen]
            if not missing:
                return
            if self.clock.now() > deadline:
                e = NetAbort("timeout", missing[0], self.self_id, "connect: no authenticated link from %s" % ",".join(map(str, missing)))
                self.fail(e)
                raise e
            await asyncio.sleep(0.02)  # a poll interval, not a decision: real time

    async def _dial(self, id: int, deadline: float) -> None:
        node = next(n for n in self.cfg.nodes if n.id == id)
        while not self._failure and self.clock.now() < deadline:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.check_hostname = False  # we pin by certificate (ca = exactly that cert + fingerprint check below), not by hostname
            ctx.verify_mode = ssl.CERT_REQUIRED
            self._load_chain(ctx)
            ctx.load_verify_locations(cadata=node.cert_pem)
            try:
                reader, writer = await asyncio.open_connection(node.host, node.port, ssl=ctx, ssl_handshake_timeout=10)
            except (OSError, ssl.SSLError, asyncio.TimeoutError):
                await asyncio.sleep(0.15)  # retry pacing, not a decision: real time
                continue
            der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            fp = fingerprint_of_der(der) if der else None
            if self._pinned.get(fp) != id:
                writer.close()
                self.fail(NetAbort("identity", id, self.self_id, "dial: peer certificate is not the pinned identity of node %d" % id))
                return
            self._attach(id, reader, writer)
            return

    async def _on_incoming(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        fp = fingerprint_of_der(der) if der else None
        i = self._pinned.get(fp) if fp else None
        if i is None or i not in self._links or i < self.self_id:
            self._note("rejected incoming connection (fp=%s)" % (fp or "none"))
            writer.close()
            return
        if self._links[i].writer is not None:
            self._note("duplicate connection from node %d" % i)  # a second connection claiming an already-linked identity
            writer.close()
            return
        self._attach(i, reader, writer)

    def _attach(self, id: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        l = self._links[id]
        if l.writer is not None:
            writer.close()
            return
        l.reader, l.writer = reader, writer
        l.task = asyncio.ensure_future(self._read_loop(l))
        self._tasks.append(l.task)
        # hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin.
        self._send_frame(l, "hello", "hello", {"id": self.self_id})

    # ---- receive path ----

    async def _read_loop(self, l: _Link) -> None:
        why = "peer ended"
        try:
            while True:
                await l.resume.wait()  # back-pressure: stop reading while the inbox is half full
                chunk = await l.reader.read(65536)
                if not chunk:
                    break
                self._on_data(l, chunk)
        except (OSError, ssl.SSLError, asyncio.IncompleteReadError) as e:
            why = "socket error: %s" % e
        self._on_closed(l, why)

    def _on_data(self, l: _Link, chunk: bytes) -> None:
        if self._failure:
            return
        l.bytes_in += len(chunk)
        try:
            bodies = l.splitter.push(chunk)
        except Exception:  # noqa: BLE001 - the splitter raises on an oversize length prefix
            return self.fail(NetAbort("oversize", l.id, self.self_id, "length prefix above MAX_FRAME_BYTES"))
        for b in bodies:
            f = NetWire.parse_frame(b)
            if f is None:
                pv = NetWire.version_mismatch(b)
                if pv is not None:
                    return self.fail(NetAbort("version", l.id, self.self_id, "peer %d speaks wire version %s, this node speaks %d; upgrade both peers" % (l.id, pv, NetWire.WIRE_VERSION)))
                return self.fail(NetAbort("malformed", l.id, self.self_id, "undecodable or ill-shaped frame"))
            if f["sid"] != self.cfg.session_id:
                return self.fail(NetAbort("wrong-session", l.id, self.self_id, "frame from another session"))
            if f["ty"] == "abort":
                # An abort frame is only a CLAIM by the peer that sent it. We blame that peer (the authenticated sender), never
                # the party it names: otherwise any peer could frame an honest one.
                d = f["d"] if isinstance(f["d"], dict) else None
                relayed = bool(d is not None and d.get("relayed") is True)
                ck = d.get("kind") if d else None
                claimed_kind = ck if isinstance(ck, str) and ck in NetWire.ABORT_KINDS else None
                max_id = max(x.id for x in self.cfg.nodes)
                bl = d.get("blamed") if d else None
                claimed_blame = bl if (isinstance(bl, (int, float)) and not isinstance(bl, bool) and float(bl).is_integer()
                                       and not (isinstance(bl, float) and str(bl).startswith("-")) and 0 <= bl <= max_id) else None
                dt = d.get("detail") if d else None
                detail = _sanitize(dt, 120) if isinstance(dt, str) else ""
                claim = NetAbort(
                    "peer-abort", None if relayed else l.id, self.self_id,
                    "peer %d %s an abort (%s, accuses %s, unverified) %s" % (
                        l.id, "relayed" if relayed else "reported", claimed_kind or "unspecified",
                        "no one" if claimed_blame is None else int(claimed_blame), detail),
                    claimed_kind, None if claimed_blame is None else int(claimed_blame),
                    "relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence" if relayed else None)
                if self._defer_aborts:
                    # Order-preserving: the claim takes effect when it is READ, i.e. only after every frame this peer sent
                    # before it (an honest peer always sends its round data before it aborts, on this same in-order link).
                    l.inbox.append({"f": f, "size": len(b), "abort": claim})
                    continue
                return self.fail(claim, l.id)
            if f["seq"] != l.recv_seq:
                kind = "duplicate" if f["seq"] < l.recv_seq else "out-of-order"
                return self.fail(NetAbort(kind, l.id, self.self_id, "expected seq %d, got %s (round %s)" % (l.recv_seq, f["seq"], f["rd"])))
            l.recv_seq += 1
            l.frames_in += 1
            if f["ty"] == "hello":
                d = f["d"] if isinstance(f["d"], dict) else None
                hid = d.get("id") if d else None
                if l.hello_seen or isinstance(hid, bool) or hid != l.id:
                    return self.fail(NetAbort("identity", l.id, self.self_id, "hello claims id %s on the link pinned to %d" % (hid, l.id)))
                l.hello_seen = True
            else:
                if not l.hello_seen:
                    return self.fail(NetAbort("malformed", l.id, self.self_id, "data before hello"))
                l.inbox.append({"f": f, "size": len(b)})
                l.inbox_bytes += len(b)
                if len(l.inbox) > self.cfg.max_inbox_frames or l.inbox_bytes > self.cfg.max_inbox_bytes:
                    return self.fail(NetAbort("flood", l.id, self.self_id, "peer %d queued more than the inbox cap allows" % l.id))
                if not l.paused and (len(l.inbox) > self.cfg.max_inbox_frames / 2 or l.inbox_bytes > self.cfg.max_inbox_bytes / 2):
                    l.paused = True
                    l.resume.clear()
        self._wake()

    def _on_closed(self, l: _Link, why: str) -> None:
        if l.closed:
            return
        l.closed = True
        if not self._finished and not self._failure and not l.hello_seen:
            self._note("link %d closed before hello: %s" % (l.id, why))
        self._wake()

    # ---- send path ----

    def _send_frame(self, l: _Link, ty: str, rd: str, d: Any) -> None:
        frame = {"v": NetWire.WIRE_VERSION, "ty": ty, "sid": self.cfg.session_id, "seq": l.send_seq, "rd": rd, "d": d}
        l.send_seq += 1
        raw = NetWire.encode_frame(frame)
        outs = self.cfg.tamper({"to": l.id, "frame": frame, "raw": raw}) if (self.cfg.tamper and ty != "hello") else [raw]
        for b in outs:
            if l.writer is not None and not l.writer.is_closing():
                l.writer.write(b)
                l.bytes_out += len(b)
        l.frames_out += 1

    def send(self, to: int, round: str, payload: Any) -> None:
        """Send a protocol message to one peer. Raises the mesh failure if already aborted (fail closed)."""
        if self._failure:
            raise self._failure
        l = self._links.get(to)
        if l is None:
            raise ValueError("mesh: no link to %s" % to)
        self._send_frame(l, "msg", round, payload)

    def broadcast(self, round: str, payload: Any, to: Optional[Sequence[int]] = None) -> None:
        for p in (self.peers if to is None else to):
            self.send(p, round, payload)

    def sign(self, data: bytes) -> bytes:
        """ECDSA-P256/SHA-256 (DER) signature over `data` with this node's TLS identity key (transferable: verifiable against
        the pinned certificate)."""
        return self._key.sign(bytes(data), ec.ECDSA(hashes.SHA256()))

    def verify(self, peer: int, data: bytes, sig: bytes) -> bool:
        """Verify `sig` over `data` against the PINNED certificate of node `peer`. False on any failure (never raises)."""
        n = next((x for x in self.cfg.nodes if x.id == peer), None)
        if n is None or peer == self.self_id:
            return False
        try:
            cert = x509.load_pem_x509_certificate(n.cert_pem.encode("ascii"))
            cert.public_key().verify(bytes(sig), bytes(data), ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:  # noqa: BLE001
            return False

    async def recv(self, frm: int, round: str, timeout_ms: Optional[float] = None) -> Any:
        """Receive the next message from `frm`, which must belong to `round`. Times out; never hangs."""
        l = self._links.get(frm)
        if l is None:
            raise ValueError("mesh: no link to %s" % frm)
        timeout_ms = self.recv_timeout_ms if timeout_ms is None else timeout_ms
        deadline = self.clock.now() + timeout_ms
        while True:
            if self._failure:
                raise self._failure
            it = l.inbox.pop(0) if l.inbox else None
            if it is not None and it.get("abort") is not None:
                self.fail(it["abort"], frm)
                raise it["abort"]
            if it is not None:
                f = it["f"]
                l.inbox_bytes -= it["size"]
                if l.paused and len(l.inbox) <= self.cfg.max_inbox_frames / 2 and l.inbox_bytes <= self.cfg.max_inbox_bytes / 2:
                    l.paused = False
                    l.resume.set()
                if f["rd"] != round:
                    e = NetAbort("wrong-round", frm, self.self_id, "expected round '%s', got '%s'" % (round, f["rd"]))
                    self.fail(e)
                    raise e
                return f["d"]
            if l.closed:
                e = NetAbort("disconnect", frm, self.self_id, "link to %d closed while awaiting '%s'" % (frm, round))
                self.fail(e)
                raise e
            left = deadline - self.clock.now()
            if left <= 0:
                e = NetAbort("timeout", frm, self.self_id,
                             "no '%s' message from %d within %sms (deadline %sms; a silent peer is blamed on this local observation only)" % (round, frm, timeout_ms, timeout_ms),
                             None, None, None, None, timeout_ms)
                self.fail(e)
                raise e
            fut = asyncio.get_running_loop().create_future()
            self._waiters.append(fut)
            t = self.clock.set_timer(lambda fu=fut: fu.done() or fu.set_result(None), left)
            try:
                await fut
            finally:
                self.clock.clear_timer(t)

    def set_defer_aborts(self, on: bool) -> None:
        """While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and
        only takes effect when a receive from that peer reaches it (the blame round)."""
        self._defer_aborts = bool(on)

    async def collect(self, round: str, frm: Optional[Sequence[int]] = None, timeout_ms: Optional[float] = None) -> Dict[int, Any]:
        """Receive `round` from every peer in `frm` concurrently. A failure on any link raises."""
        ps = list(self.peers if frm is None else frm)
        got = await asyncio.gather(*[self.recv(p, round, timeout_ms) for p in ps])
        return dict(zip(ps, got))

    # ---- failure / shutdown ----

    def fail(self, err: Exception, skip_peer: Optional[int] = None) -> None:
        """Poison the mesh: record the first failure, tell EVERY peer except `skip_peer` (the one that just told us; forwarding the
        original accusation so an innocent bystander is never blamed for merely closing), close all."""
        if self._failure:
            return
        self._failure = err
        for l in self._links.values():
            if l.id == skip_peer:
                continue
            if l.writer is not None and not l.writer.is_closing() and not l.closed:
                try:
                    relay = err.kind == "peer-abort"
                    kind = (err.claimed_kind or "peer-abort") if relay else err.kind
                    blamed = err.claimed_blame if relay else err.blamed
                    d = {"kind": kind, "blamed": blamed, "detail": _sanitize(str(err), 200)}
                    if relay:
                        d["relayed"] = True
                    self._send_abort(l, d)
                except Exception:  # noqa: BLE001 - best effort
                    pass
        self._wake()
        try:
            asyncio.get_running_loop().call_later(0.05, self._close_all)
        except RuntimeError:
            self._close_all()

    def _send_abort(self, l: _Link, d: Any) -> None:
        frame = {"v": NetWire.WIRE_VERSION, "ty": "abort", "sid": self.cfg.session_id, "seq": l.send_seq, "rd": "abort", "d": d}
        l.send_seq += 1
        l.writer.write(NetWire.encode_frame(frame))

    async def finish(self) -> None:
        """Normal completion: flush and close. Peers that are still reading will see EOF only after our data."""
        self._finished = True
        await asyncio.sleep(0.1)
        self._close_all()

    def _close_all(self) -> None:
        for l in self._links.values():
            if l.writer is not None:
                try:
                    l.writer.close()
                except Exception:  # noqa: BLE001
                    pass
        if self._server is not None:
            self._server.close()
        for t in self._tasks:
            if not t.done() and t is not asyncio.current_task():
                t.cancel()

    def stats(self) -> List[Dict[str, Any]]:
        return [{"peer": p, "appBytesOut": self._links[p].bytes_out, "appBytesIn": self._links[p].bytes_in,
                 "framesOut": self._links[p].frames_out, "framesIn": self._links[p].frames_in} for p in self.peers]
