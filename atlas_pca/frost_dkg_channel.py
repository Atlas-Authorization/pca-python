"""The wire, the inbox and the driver of a networked FROST DKG: a versioned JSON envelope per message (``{"v", "sid", "kind", "body"}``, strict JSON, capped at
256 KiB, bound to the session), strict decoders for each body kind, a per-link INBOX (first message per peer and kind wins, a second identical one is a
``duplicate`` and a different one an ``equivocation``, either poisons that peer for every later collect), an in-memory network for tests, and
:func:`run_dkg_over_channel`, one party's whole ceremony over any channel. A port of the reference ``frost-dkg-channel`` module; the channel is synchronous
(``collect`` blocks up to its timeout). TLS framing is in :mod:`atlas_pca.frost_dkg_tls`."""
from __future__ import annotations

import math
import os
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from . import frost_dkg as D
from .analyzer_js import js_json
from .pca import b64u, decode_b64u_strict, strict_parse

__all__ = ["DKG_WIRE_VERSION", "DKG_MAX_MESSAGE_BYTES", "DKG_MAX_PARTICIPANTS", "DKG_MESSAGE_KINDS", "DkgChannelError", "encode_dkg_message", "decode_dkg_message",
           "decode_dkg_round1_package", "decode_dkg_share_message", "decode_dkg_complaints", "decode_dkg_rebuttals", "decode_dkg_echo", "DkgInbox",
           "create_memory_dkg_network", "run_dkg_over_channel"]

DKG_WIRE_VERSION = 1
DKG_MAX_MESSAGE_BYTES = 256 * 1024
DKG_MAX_PARTICIPANTS = 256
DKG_MESSAGE_KINDS = ("round1", "share", "complaints", "rebuttals", "echo")
_PREFIX = re.compile(r"^dkg channel \([^)]*\): ")


class DkgChannelError(Exception):
    """A ceremony failure: ``code`` is one of timeout, identity, wrong-session, duplicate, equivocation, malformed, oversize, closed, protocol, disqualified;
    ``peer`` the participant to blame (None when none)."""

    def __init__(self, code: str, peer: Optional[Any], message: str) -> None:
        super().__init__("dkg channel (%s%s): %s" % (code, "" if peer is None else ", peer %s" % D._js_string(peer), message))
        self.code = code
        self.peer = peer
        self.detail = message


def _rebind(e: DkgChannelError, peer: Any) -> DkgChannelError:
    return DkgChannelError(e.code, peer, _PREFIX.sub("", str(e), count=1))


# ---- envelope ----------------------------------------------------------------------------------------------------------

def encode_dkg_message(session_id: bytes, kind: Any, body: Any) -> bytes:
    """The wire bytes of a message: JSON of ``{"v", "sid", "kind", "body"}`` (member order as written, body members in the order given)."""
    data = js_json({"v": DKG_WIRE_VERSION, "sid": b64u(session_id), "kind": kind, "body": body}).encode("utf-8")
    if len(data) > DKG_MAX_MESSAGE_BYTES:
        raise DkgChannelError("oversize", None, "message of %d bytes exceeds the cap" % len(data))
    return data


def _as_record(x: Any, keys: tuple, what: str) -> dict:
    if x is None or not isinstance(x, dict):
        raise DkgChannelError("malformed", None, "%s is not an object" % what)
    if len(x) != len(keys) or not all(k in x for k in keys):
        raise DkgChannelError("malformed", None, "%s has unexpected or missing members" % what)
    return x


def decode_dkg_message(data: Any, session_id: bytes) -> Dict[str, Any]:
    """Parse and check one envelope: strict JSON, exactly the four members, wire version 1, a known kind, this session. Returns ``{"kind", "body"}``."""
    if not isinstance(data, (bytes, bytearray)):
        raise DkgChannelError("malformed", None, "message is not bytes")
    if len(data) > DKG_MAX_MESSAGE_BYTES:
        raise DkgChannelError("oversize", None, "message of %d bytes exceeds the cap" % len(data))
    try:
        msg = strict_parse(bytes(data))
    except Exception:  # noqa: BLE001
        raise DkgChannelError("malformed", None, "message is not strict JSON")
    o = _as_record(msg, ("v", "sid", "kind", "body"), "envelope")
    v = o["v"]
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != DKG_WIRE_VERSION:
        raise DkgChannelError("malformed", None, "unsupported wire version")
    if not isinstance(o["kind"], str) or o["kind"] not in DKG_MESSAGE_KINDS:
        raise DkgChannelError("malformed", None, "unknown message kind")
    if o["sid"] != b64u(session_id):
        raise DkgChannelError("wrong-session", None, "message names another session")
    return {"kind": o["kind"], "body": o["body"]}


def _pos_int(x: Any, what: str) -> Any:
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not D._safe_pos(x):
        raise DkgChannelError("malformed", None, "%s is not a positive integer" % what)
    return x


def _b64_field(x: Any, what: str, length: Optional[int] = None) -> str:
    if decode_b64u_strict(x, length) is None:
        raise DkgChannelError("malformed", None, "%s is not canonical base64url" % what)
    return x


def decode_dkg_round1_package(x: Any, t: Any) -> Dict[str, Any]:
    """A round-1 package from the wire: exact members, t commitments of 32 canonical bytes each, a 32-byte proof pair. Not validated as points."""
    o = _as_record(x, ("identifier", "sessionId", "coefficientCommitments", "proofOfKnowledge"), "round-1 package")
    pok = _as_record(o["proofOfKnowledge"], ("R", "mu"), "proof of knowledge")
    cc = o["coefficientCommitments"]
    if not isinstance(cc, list) or isinstance(t, bool) or not isinstance(t, (int, float)) or len(cc) != t:
        raise DkgChannelError("malformed", None, "round-1 package must commit to exactly t=%s coefficients" % D._js_string(t))
    return {"identifier": _pos_int(o["identifier"], "identifier"), "sessionId": _b64_field(o["sessionId"], "sessionId"),
            "coefficientCommitments": [_b64_field(c, "coefficient commitment", 32) for c in cc],
            "proofOfKnowledge": {"R": _b64_field(pok["R"], "PoP R", 32), "mu": _b64_field(pok["mu"], "PoP mu", 32)}}


def decode_dkg_share_message(x: Any) -> Dict[str, Any]:
    o = _as_record(x, ("from", "to", "sessionId", "share", "sig"), "share message")
    return {"from": _pos_int(o["from"], "from"), "to": _pos_int(o["to"], "to"), "sessionId": _b64_field(o["sessionId"], "sessionId"),
            "share": decode_b64u_strict(_b64_field(o["share"], "share", 32)), "sig": _b64_field(o["sig"], "share signature", 64)}


def _complaint_of(x: Any) -> Dict[str, Any]:
    o = _as_record(x, ("accused", "accuser", "sessionId", "revealedShare", "shareSig"), "complaint")
    return {"accused": _pos_int(o["accused"], "accused"), "accuser": _pos_int(o["accuser"], "accuser"), "sessionId": _b64_field(o["sessionId"], "sessionId"),
            "revealedShare": _b64_field(o["revealedShare"], "revealed share", 32), "shareSig": _b64_field(o["shareSig"], "share signature", 64)}


def _rebuttal_of(x: Any) -> Dict[str, Any]:
    o = _as_record(x, ("accused", "accuser", "sessionId", "presentedShare", "shareSig"), "rebuttal")
    return {"accused": _pos_int(o["accused"], "accused"), "accuser": _pos_int(o["accuser"], "accuser"), "sessionId": _b64_field(o["sessionId"], "sessionId"),
            "presentedShare": _b64_field(o["presentedShare"], "presented share", 32), "shareSig": _b64_field(o["shareSig"], "share signature", 64)}


def _list_of(x: Any, key: str, one: Callable[[Any], Any]) -> List[Any]:
    o = _as_record(x, (key,), key)
    lst = o[key]
    if not isinstance(lst, list) or len(lst) > DKG_MAX_PARTICIPANTS:
        raise DkgChannelError("malformed", None, "%s is not a bounded list" % key)
    return [one(v) for v in lst]


def decode_dkg_complaints(x: Any) -> List[Dict[str, Any]]:
    return _list_of(x, "complaints", _complaint_of)


def decode_dkg_rebuttals(x: Any) -> List[Dict[str, Any]]:
    return _list_of(x, "rebuttals", _rebuttal_of)


def decode_dkg_echo(x: Any) -> Dict[str, Any]:
    o = _as_record(x, ("identifier", "sessionId", "transcriptDigest"), "echo")
    return {"identifier": _pos_int(o["identifier"], "identifier"), "sessionId": _b64_field(o["sessionId"], "sessionId"),
            "transcriptDigest": _b64_field(o["transcriptDigest"], "transcript digest", 32)}


# ---- inbox -------------------------------------------------------------------------------------------------------------

class DkgInbox:
    """Messages received from the authenticated links of one participant. ``accept(sender, bytes)`` files a message under (kind, sender); the first error
    per peer is sticky and is what every later ``collect`` that names that peer raises."""

    def __init__(self, session_id: bytes, peers: List[Any]) -> None:
        self.session_id = session_id
        self.peers = peers
        self._seen: Dict[tuple, tuple] = {}
        self._errors: Dict[Any, DkgChannelError] = {}
        self._gone: set = set()
        self._closed = False
        self._cv = threading.Condition()

    def fail(self, peer: Any, err: DkgChannelError) -> None:
        with self._cv:
            if peer not in self._errors:
                self._errors[peer] = DkgChannelError(err.code, peer, _PREFIX.sub("", str(err), count=1))
            self._cv.notify_all()

    def accept(self, sender: Any, data: Any) -> None:
        if not any(D._seq(sender, p) for p in self.peers):
            return
        try:
            m = decode_dkg_message(data, self.session_id)
            key = (m["kind"], sender)
            digest = b64u(bytes(data))
            with self._cv:
                prev = self._seen.get(key)
                if prev is not None:
                    raise DkgChannelError("duplicate" if prev[0] == digest else "equivocation", sender, "second %s message" % m["kind"])
                self._seen[key] = (digest, m["body"])
                self._cv.notify_all()
        except Exception as e:  # noqa: BLE001
            self.fail(sender, e if isinstance(e, DkgChannelError) else DkgChannelError("malformed", sender, "undecodable message"))

    def peer_gone(self, peer: Any) -> None:
        with self._cv:
            self._gone.add(peer)
            self._cv.notify_all()

    def close(self) -> None:
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    def collect(self, kind: str, from_ids: List[Any], timeout_ms: Any) -> Dict[Any, Any]:
        """The bodies of ``kind`` from every id in ``from_ids`` (ascending), waiting up to ``timeout_ms`` for the rest. Raises the first sticky error of a
        wanted peer (lowest id first), ``closed`` when the channel closed or a wanted peer's link ended first, ``timeout`` naming the lowest missing id."""
        want = sorted(from_ids)
        deadline = time.monotonic() + timeout_ms / 1000.0
        with self._cv:
            while True:
                for i in want:
                    e = self._errors.get(i)
                    if e is not None:
                        raise e
                out = {}
                for i in want:
                    m = self._seen.get((kind, i))
                    if m is not None:
                        out[i] = m[1]
                if len(out) == len(want):
                    return out
                if self._closed:
                    raise DkgChannelError("closed", None, "channel closed before all messages arrived")
                gone = next((i for i in want if i not in out and i in self._gone), None)
                if gone is not None:
                    raise DkgChannelError("closed", gone, "link ended before its %s message arrived" % kind)
                left = deadline - time.monotonic()
                if left <= 0:
                    missing = [i for i in want if i not in out]
                    raise DkgChannelError("timeout", missing[0], "no %s message from %s" % (kind, ",".join(D._js_string(m) for m in missing)))
                self._cv.wait(left)


# ---- in-memory network -------------------------------------------------------------------------------------------------

class _MemoryChannel:
    def __init__(self, self_id: Any, peers: List[Any], route: Callable[[Any, str, Any], None], inbox: DkgInbox) -> None:
        self.self = self_id
        self.peers = peers
        self._route = route
        self._inbox = inbox

    def broadcast(self, kind: str, body: Any) -> None:
        for p in self.peers:
            self._route(p, kind, body)

    def send(self, to: Any, kind: str, body: Any) -> None:
        if not any(D._seq(to, p) for p in self.peers):
            raise DkgChannelError("identity", to, "not a connected peer")
        self._route(to, kind, body)

    def collect(self, kind: str, from_ids: List[Any], timeout_ms: Any) -> Dict[Any, Any]:
        return self._inbox.collect(kind, from_ids, timeout_ms)

    def close(self) -> None:
        self._inbox.close()


def create_memory_dkg_network(ids: List[Any], session_id: bytes, intercept: Optional[Callable[[dict], Optional[bytes]]] = None) -> Dict[str, Any]:
    """Channels for every id wired through in-process inboxes; ``intercept({"from", "to", "kind", "bytes"})`` may drop (None) or replace the bytes of a
    delivery. Returns ``{"channels": {id: channel}, "deliver": fn(from, to, bytes)}`` (``deliver`` injects a message as if ``from`` sent it)."""
    ordered = sorted(ids)
    inboxes = {i: DkgInbox(session_id, [p for p in ordered if p != i]) for i in ordered}

    def deliver(frm: Any, to: Any, data: bytes) -> None:
        ib = inboxes.get(to)
        if ib is not None:
            ib.accept(frm, data)
    channels: Dict[Any, _MemoryChannel] = {}
    for self_id in ordered:
        def route(to: Any, kind: str, body: Any, self_id: Any = self_id) -> None:
            data = encode_dkg_message(session_id, kind, body)
            out = intercept({"from": self_id, "to": to, "kind": kind, "bytes": data}) if intercept is not None else data
            if out is not None:
                deliver(self_id, to, out)
        channels[self_id] = _MemoryChannel(self_id, [p for p in ordered if p != self_id], route, inboxes[self_id])
    return {"channels": channels, "deliver": deliver}


# ---- driver ------------------------------------------------------------------------------------------------------------

def _bind(peer: Any, f: Callable[[], Any]) -> Any:
    try:
        return f()
    except DkgChannelError as e:
        raise _rebind(e, peer)


def run_dkg_over_channel(ch: Any, t: Any, participants: List[Any], session_id: bytes, timeout_ms: Any = None, coefficients: Optional[List[bytes]] = None,
                         random_bytes: Callable[[int], bytes] = os.urandom) -> Dict[str, Any]:
    """One party's whole DKG over ``ch`` (``self``, ``peers``, ``broadcast``, ``send``, ``collect``, ``close``): round 1 and the proofs of knowledge, the
    signed shares, the blame round (a bad share must be provable, else the ceremony aborts), the rebuttals, the qualified set, the echo agreement and the
    verified finalize. Returns ``{"keyPackage", "qualified", "complaints"}``; raises :class:`DkgChannelError` naming the peer to blame."""
    me = ch.self
    ids = sorted(participants)
    if len(ids) > DKG_MAX_PARTICIPANTS or any(not D._safe_pos(i) or (k > 0 and D._seq(ids[k - 1], i)) for k, i in enumerate(ids)):
        raise DkgChannelError("protocol", None, "participants must be distinct positive integers within the cap")
    if not any(D._seq(me, i) for i in ids):
        raise DkgChannelError("protocol", None, "this participant is not in the participant list")
    if not D._safe_pos(t) or t > len(ids):
        raise DkgChannelError("protocol", None, "need 1 <= t <= n")
    others = [i for i in ids if not D._seq(i, me)]
    if len(ch.peers) != len(others) or not all(D._seq(ch.peers[k], o) for k, o in enumerate(others)):
        raise DkgChannelError("protocol", None, "the channel peers are not exactly the other participants")
    sid = session_id
    sid_b64 = b64u(sid)
    tmo = timeout_ms if timeout_ms is not None else 30000
    n = len(ids)

    r1 = D.dkg_round1(me, t, n, sid, {"coefficients": coefficients}, random_bytes)
    ch.broadcast("round1", r1["package"])
    pkgs = [r1["package"]]
    for frm, body in ch.collect("round1", others, tmo).items():
        p = _bind(frm, lambda body=body: decode_dkg_round1_package(body, t))
        if p["identifier"] != frm:
            raise DkgChannelError("identity", frm, "package claims identifier %s" % D._js_string(p["identifier"]))
        if p["sessionId"] != sid_b64:
            raise DkgChannelError("wrong-session", frm, "package names another session")
        pkgs.append(p)
    by_id = {p["identifier"]: p for p in pkgs}
    pok = [p for p in pkgs if D.dkg_verify_round1(p["identifier"], p, sid)]
    ok_peers = [o for o in others if any(p["identifier"] == o for p in pok)]

    for s in D.dkg_round2(r1["state"], pok):
        ch.send(s["to"], "share", {"from": s["from"], "to": s["to"], "sessionId": s["sessionId"], "share": b64u(s["share"]), "sig": s["sig"]})
    inbox: List[dict] = []
    mine: List[dict] = []
    for frm, body in ch.collect("share", ok_peers, tmo).items():
        m = _bind(frm, lambda body=body: decode_dkg_share_message(body))
        if m["from"] != frm:
            raise DkgChannelError("identity", frm, "share claims sender %s" % D._js_string(m["from"]))
        if m["to"] != me:
            raise DkgChannelError("identity", frm, "share is addressed to %s" % D._js_string(m["to"]))
        if m["sessionId"] != sid_b64:
            raise DkgChannelError("wrong-session", frm, "share names another session")
        received = {"from": frm, "sessionId": m["sessionId"], "share": m["share"], "sig": m["sig"]}
        sender = by_id[frm]
        if D.dkg_verify_share(received, sender, me, sid):
            inbox.append(received)
            continue
        c = D.dkg_file_complaint({"accused": frm, "accuser": me, "receivedShare": m["share"], "shareSig": m["sig"],
                                  "senderCommitments": sender["coefficientCommitments"], "sessionId": sid})
        if not D.dkg_verify_complaint(c, pkgs)["justified"]:
            raise DkgChannelError("protocol", frm, "share failed verification and is not admissible blame")
        mine.append(c)

    ch.broadcast("complaints", {"complaints": mine})
    complaints: List[dict] = list(mine)
    for frm, body in ch.collect("complaints", others, tmo).items():
        lst = _bind(frm, lambda body=body: decode_dkg_complaints(body))
        pairs = set()
        for c in lst:
            if c["accuser"] != frm:
                raise DkgChannelError("identity", frm, "complaint filed as %s" % D._js_string(c["accuser"]))
            if c["sessionId"] != sid_b64:
                raise DkgChannelError("wrong-session", frm, "complaint names another session")
            if c["accused"] == frm or c["accused"] not in ids:
                raise DkgChannelError("protocol", frm, "complaint names an invalid accused")
            if str(c["accused"]) in pairs:
                raise DkgChannelError("duplicate", frm, "two complaints against one accused")
            pairs.add(str(c["accused"]))
            complaints.append(c)
    rebuttals = [D.dkg_rebut(me, c, r1["state"]) for c in complaints if c["accused"] == me]
    ch.broadcast("rebuttals", {"rebuttals": rebuttals})
    all_rebuttals: List[dict] = list(rebuttals)
    for frm, body in ch.collect("rebuttals", others, tmo).items():
        for r in _bind(frm, lambda body=body: decode_dkg_rebuttals(body)):
            if r["accused"] != frm:
                raise DkgChannelError("identity", frm, "rebuttal made as %s" % D._js_string(r["accused"]))
            if r["sessionId"] != sid_b64:
                raise DkgChannelError("wrong-session", frm, "rebuttal names another session")
            all_rebuttals.append(r)

    qualified = D.dkg_qualified_set(ids, complaints, pkgs, all_rebuttals)
    if me not in qualified:
        raise DkgChannelError("disqualified", me, "this participant was disqualified by the blame round")
    if len(qualified) < t:
        raise DkgChannelError("protocol", None, "fewer than t participants remain qualified")

    echo = D.dkg_echo({"identifier": me, "round1Packages": pkgs, "complaints": complaints, "qualified": qualified, "sessionId": sid})
    ch.broadcast("echo", echo)
    echoes: List[dict] = [echo]
    for frm, body in ch.collect("echo", [q for q in qualified if q != me], tmo).items():
        e = _bind(frm, lambda body=body: decode_dkg_echo(body))
        if e["identifier"] != frm:
            raise DkgChannelError("identity", frm, "echo claims identifier %s" % D._js_string(e["identifier"]))
        echoes.append(e)
    agreement = D.dkg_check_echoes(qualified, echoes, sid)
    if not agreement["agreed"]:
        raise DkgChannelError("equivocation", None, agreement["reason"])

    key_package = D.dkg_finalize(me, r1["state"], inbox, pkgs, qualified, {"echoes": echoes, "complaints": complaints})
    return {"keyPackage": key_package, "qualified": qualified, "complaints": complaints}
