"""TEST-ONLY fault injection for the networked MPC (reference: net/faults.ts).

Two layers, deliberately separate:
 - tamper_for(spec): a MALICIOUS SENDER rewriting its own outgoing frames at the application layer. The bytes still travel inside
   valid TLS, so the receiver's framing checks decide. Plug the result into MeshConfig(tamper=..., unsafe_test_hooks=True).
 - FaultProxy: a NETWORK adversary on the wire (TCP middlebox): drop / delay / truncate / bit-flip / duplicate / reorder at the byte
   level. TLS 1.3 record authentication rejects tampering, so the expected outcome is an attributable-to-the-link disconnect,
   never a silently corrupted value."""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from .mpc_net import NetWire

FRAME_FAULT_KINDS = ("duplicate", "reorder", "skip-seq", "garbage", "truncate", "bitflip", "wrong-round", "wrong-session", "oversize",
                     "drop", "silent-from", "extra-field", "false-accuse")


@dataclass
class FrameFault:
    kind: str
    round: str  # protocol round to attack (e.g. 'mul0')
    to: Optional[int] = None  # restrict to one recipient; default all
    accuse: Optional[int] = None  # false-accuse: the honest party named in the forged abort frame


def tamper_for(spec: FrameFault) -> Callable[[Dict[str, Any]], List[bytes]]:
    if spec.kind not in FRAME_FAULT_KINDS:
        raise ValueError("tamper_for: unknown fault kind %r" % (spec.kind,))
    stash: Dict[int, bytes] = {}
    silent = [False]

    def tamper(ev: Dict[str, Any]) -> List[bytes]:
        if silent[0]:
            return []
        raw, frame, to = ev["raw"], ev["frame"], ev["to"]
        hit = frame["rd"] == spec.round and (spec.to is None or spec.to == to)
        k = spec.kind
        if k == "reorder":
            held = stash.pop(to, None)
            if held is not None:
                return [raw, held]  # later frame first, then the held-back one
            if hit:
                stash[to] = raw
                return []
            return [raw]
        if not hit:
            return [raw]
        if k == "duplicate":
            return [raw, raw]
        if k == "skip-seq":
            return [NetWire.encode_frame({**frame, "seq": frame["seq"] + 1})]
        if k == "garbage":
            return [struct.pack(">I", len(raw) - 4) + b"\x5a" * (len(raw) - 4)]
        if k == "truncate":
            return [raw[:max(5, len(raw) // 2)]]
        if k == "bitflip":
            b = bytearray(raw)
            i = int(len(b) * 0.6)
            b[i] ^= 0x04
            return [bytes(b)]
        if k == "wrong-round":
            return [NetWire.encode_frame({**frame, "rd": "zzz-" + frame["rd"]})]
        if k == "wrong-session":
            return [NetWire.encode_frame({**frame, "sid": "not-this-session"})]
        if k == "oversize":
            return [struct.pack(">I", 0x7FFFFFFF)]
        if k == "drop":
            return []
        if k == "silent-from":
            silent[0] = True
            return []
        if k == "false-accuse":
            return [NetWire.encode_frame({**frame, "ty": "abort", "rd": "abort",
                                          "d": {"kind": "timeout", "blamed": spec.accuse if spec.accuse is not None else 0, "detail": "forged accusation"}})]
        return [NetWire.encode_frame({**frame, "x": 1})]  # extra-field

    return tamper


# ----------------------------------------------------------------------------- TCP fault proxy

WIRE_FAULT_KINDS = ("none", "drop", "delay", "truncate", "bitflip", "duplicate", "reorder")


@dataclass
class WireFault:
    kind: str  # one of WIRE_FAULT_KINDS
    dir: str  # 'c2s' (client->server) or 's2c'
    after_bytes: int  # the fault starts after this many bytes passed in that direction (skips the TLS handshake)
    ms: Optional[float] = None  # delay milliseconds (kind=delay), default 1000


class _Pipe:
    """One direction. A closed side tears down the other only after that direction's delayed bytes are delivered: a real network delays
    data, it does not drop what the sender wrote before it closed."""

    def __init__(self, f: WireFault, direction: str, to: asyncio.StreamWriter, log: List[str]):
        self.f, self.dir, self.to, self.log = f, direction, to, log
        self.active = f.kind != "none" and f.dir == direction
        self.seen = 0
        self.fired = self.done = self.ended = self.closed = False
        self.held: Optional[bytes] = None
        self.pending = 0  # delayed writes in flight: a half-close must not overtake them

    def _write(self, b: bytes) -> None:
        if not self.to.is_closing():
            self.to.write(b)

    def _end(self) -> None:
        try:
            if not self.to.is_closing() and self.to.can_write_eof():
                self.to.write_eof()
        except Exception:  # noqa: BLE001
            self.to.close()

    def data(self, chunk: bytes) -> None:
        f = self.f
        before = self.seen
        self.seen += len(chunk)
        if not self.active or self.done or before + len(chunk) <= f.after_bytes:
            if self.active and f.kind == "drop" and self.fired:
                return  # black hole stays black
            self._write(chunk)
            return
        if not self.fired:
            self.fired = True
            self.log.append("fault %s %s after %dB" % (f.kind, self.dir, f.after_bytes))
        k = f.kind
        if k == "drop":
            return
        if k == "delay":
            self.pending += 1
            asyncio.get_running_loop().call_later((f.ms if f.ms is not None else 1000) / 1000.0, self._delivered, chunk)
        elif k == "truncate":
            self.done = True
            self._write(chunk[:len(chunk) // 2])
            self._end()
        elif k == "bitflip":
            self.done = True
            b = bytearray(chunk)
            b[len(b) // 2] ^= 0x01
            self._write(bytes(b))
        elif k == "duplicate":
            self.done = True
            self._write(chunk)
            self._write(chunk)
        elif k == "reorder":
            if self.held is None:
                self.held = chunk
            else:
                self.done = True
                self._write(chunk)
                self._write(self.held)
                self.held = None
        else:
            self._write(chunk)

    def _delivered(self, chunk: bytes) -> None:
        self._write(chunk)
        self.pending -= 1
        if self.pending == 0 and self.closed:
            self._end()
            self.to.close()
        elif self.pending == 0 and self.ended:
            self._end()

    def end(self) -> None:
        if self.held is not None:
            self._write(self.held)
            self.held = None
        self.ended = True
        if self.pending == 0:
            self._end()

    def close(self) -> None:
        self.closed = True
        if self.pending == 0:
            self.to.close()


class FaultProxy:
    """A transparent TCP proxy (loopback only) that misbehaves once, after after_bytes bytes, in one direction."""

    def __init__(self, listen_port: int, target: Tuple[str, int], fault: WireFault, listen_sock: Any = None):
        if fault.kind not in WIRE_FAULT_KINDS or fault.dir not in ("c2s", "s2c"):
            raise ValueError("FaultProxy: bad fault spec")
        self.listen_port, self.target, self.fault = listen_port, target, fault
        self.listen_sock = listen_sock  # an already-bound socket (no probe-then-close gap)
        self.log: List[str] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._conns: List[asyncio.StreamWriter] = []
        self._tasks: List[asyncio.Task] = []

    async def listen(self) -> None:
        if self.listen_sock is not None:
            self._server = await asyncio.start_server(self._on_client, sock=self.listen_sock)
        else:
            self._server = await asyncio.start_server(self._on_client, "127.0.0.1", self.listen_port)

    @property
    def port(self) -> int:
        return self._server.sockets[0].getsockname()[1] if self._server else -1

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
        for w in self._conns:
            w.close()
        for t in self._tasks:
            t.cancel()

    async def _on_client(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        self._conns.append(cw)
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(self.target[0], self.target[1]), 5)
        except Exception:  # noqa: BLE001
            cw.close()
            return
        self._conns.append(uw)
        c2s, s2c = _Pipe(self.fault, "c2s", uw, self.log), _Pipe(self.fault, "s2c", cw, self.log)
        for coro in (self._pump(cr, c2s, cw, uw), self._pump(ur, s2c, uw, cw)):
            self._tasks.append(asyncio.ensure_future(coro))

    @staticmethod
    async def _pump(src: asyncio.StreamReader, pipe: _Pipe, a: asyncio.StreamWriter, b: asyncio.StreamWriter) -> None:
        """Read until the source ends, feeding the pipe; an I/O error destroys both sides at once."""
        try:
            while True:
                chunk = await src.read(16 * 1024)
                if not chunk:
                    break
                pipe.data(chunk)
            pipe.end()
            pipe.close()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            a.close()
            b.close()
