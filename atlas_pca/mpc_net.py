"""The pure parts of the networked MPC runner: the length-prefixed JSON frame codec with strict envelope validation, the canonical hex
field-element encoding, and the structured abort (NetAbort) that blames a party only when the evidence names one (``NetWire``); pairwise-
authenticated shares (``NetPa``); forensic disclosures of a failed offline triple (``NetForensics``); and the canonical encodings and gadget-seed
agreement helpers (``NetCodec``). Sockets, TLS and the distributed protocol driver are not part of this module."""

from __future__ import annotations

from ._fin import fin
import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .mpc import Field
from .mpc_ec import Ec, Point
from .sdjwt_jws import _js_str, js_num

_MAX_SAFE = 9007199254740991


# ---- JavaScript JSON ---------------------------------------------------------------------------------------------------------------------

def _is_index(k: str) -> bool:
    return k.isascii() and k.isdigit() and (k == "0" or k[0] != "0") and int(k) < 4294967295


def _js_keys(d: dict) -> list:
    """Own-property order of a JS object: array-index keys (< 2^32 - 1) ascending, then the rest in insertion order."""
    keys = [str(k) for k in d]
    idx = sorted((k for k in keys if _is_index(k)), key=int)
    return idx + [k for k in keys if not _is_index(k)]


def js_json(v: Any) -> str:
    """JSON.stringify (compact, the JS number form and property order; a lone surrogate is escaped)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _js_str(v)
    if isinstance(v, (int, float)):
        return js_num(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(js_json(x) for x in v) + "]"
    if isinstance(v, dict):
        by_str = {str(k): x for k, x in v.items()}
        return "{" + ",".join(_js_str(k) + ":" + js_json(by_str[k]) for k in _js_keys(by_str)) + "}"
    raise TypeError("js_json: unsupported type %s" % type(v).__name__)


def js_utf8(text: str) -> bytes:
    """TextEncoder#encode: UTF-8 bytes, every lone surrogate replaced by U+FFFD."""
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def _parse_int(t: str) -> Any:
    if t == "-0":
        return -0.0
    if len(t) > 400:
        return float(t)
    v = int(t)
    return v if -_MAX_SAFE <= v <= _MAX_SAFE else float(t)


def _no_constant(name: str) -> Any:
    raise ValueError("invalid JSON constant " + name)


def js_parse(text: str) -> Any:
    """JSON.parse with JS numbers: -0 stays -0.0, an integer beyond 2^53 is a float; NaN / Infinity literals are refused."""
    return json.loads(text, parse_int=_parse_int, parse_constant=_no_constant)


def _num(o: Any) -> Optional[float]:
    if isinstance(o, bool) or not isinstance(o, (int, float)):
        return None
    try:
        return float(o)
    except OverflowError:
        return math.inf if o > 0 else -math.inf


def _safe_int(d: Optional[float]) -> bool:
    return d is not None and fin(d) and d == math.floor(d) and abs(d) <= 9007199254740991.0


def _neg_zero(d: float) -> bool:
    return d == 0 and math.copysign(1.0, d) < 0


# ---- the wire ----------------------------------------------------------------------------------------------------------------------------

WIRE_VERSION = 2  # a peer on another version is rejected as a version mismatch
MAX_FRAME_BYTES = 4 * 1024 * 1024
ABORT_KINDS = ["timeout", "disconnect", "version", "malformed", "oversize", "duplicate", "out-of-order", "wrong-round", "wrong-session", "identity",
               "commitment", "ot-check", "mac-check", "dealer", "equivocation", "flood", "peer-abort", "local"]
FRAME_TYPES = ["hello", "msg", "abort"]
_HEX61 = re.compile(r"(?:0|[1-9a-f][0-9a-f]{0,15})")


class NetAbort(Exception):
    """A protocol abort; blamed is None when the evidence names no culprit (then reason explains why)."""

    def __init__(self, kind, blamed, reporter, detail, claimed_kind=None, claimed_blame=None, reason=None, evidence=None, deadline_ms=None):
        super().__init__("[%s] blamed=%s reporter=%s: %s" % (kind, "none" if blamed is None else blamed, reporter, detail))
        self.kind = kind
        self.blamed = blamed
        self.reporter = reporter
        self.claimed_kind = claimed_kind
        self.claimed_blame = claimed_blame
        if blamed is None:
            self.reason = reason if reason else "unattributable: the evidence available to this party does not identify a culprit"
        else:
            self.reason = None
        self.evidence = evidence
        self.deadline_ms = deadline_ms


@dataclass
class Frame:
    """A frame: {v, ty, sid, seq, rd, d}."""

    v: Any
    ty: Any
    sid: Any
    seq: Any
    rd: Any
    d: Any


class FrameSplitter:
    """Reassembles length-prefixed frames from arbitrary chunking; an oversize length prefix raises."""

    def __init__(self):
        self._data = b""

    def push(self, chunk: bytes) -> List[bytes]:
        self._data += bytes(chunk)
        out = []
        off = 0
        while True:
            if len(self._data) - off < 4:
                break
            n = int.from_bytes(self._data[off:off + 4], "big")
            if n > MAX_FRAME_BYTES:
                raise RuntimeError("oversize")
            if len(self._data) - off < 4 + n:
                break
            out.append(self._data[off + 4:off + 4 + n])
            off += 4 + n
        if off > 0:
            self._data = self._data[off:]
        return out


class NetWire:
    WIRE_VERSION = WIRE_VERSION
    MAX_FRAME_BYTES = MAX_FRAME_BYTES
    ABORT_KINDS = ABORT_KINDS
    FRAME_TYPES = FRAME_TYPES
    NetAbort = NetAbort
    Frame = Frame
    FrameSplitter = FrameSplitter

    @staticmethod
    def encode_frame(f) -> bytes:
        """Length-prefixed (4-byte big-endian) JSON frame; raises when the body exceeds MAX_FRAME_BYTES."""
        if isinstance(f, dict):
            f = Frame(*[f.get(k) for k in ("v", "ty", "sid", "seq", "rd", "d")])
        body = js_utf8(js_json({"v": f.v, "ty": f.ty, "sid": f.sid, "seq": f.seq, "rd": f.rd, "d": f.d}))
        if len(body) > MAX_FRAME_BYTES:
            raise ValueError("frame too large")
        return len(body).to_bytes(4, "big") + body

    @staticmethod
    def num(o) -> Optional[float]:
        """The JavaScript number value of a parsed JSON number (None for anything else)."""
        return _num(o)

    @staticmethod
    def safe_int(d) -> bool:
        return _safe_int(d)

    @staticmethod
    def neg_zero(d) -> bool:
        return _neg_zero(d)

    @staticmethod
    def parse_object(body: bytes) -> Optional[dict]:
        try:
            text = bytes(body).decode("utf-8", "replace")
            j = js_parse(text)
            return j if isinstance(j, dict) else None
        except Exception:  # noqa: BLE001 - any parse failure is "not an object"
            return None

    @staticmethod
    def peek_version(body: bytes) -> Optional[int]:
        """The envelope version of a body, or None when it is not a JSON object with a safe-integer v."""
        o = NetWire.parse_object(body)
        if o is None:
            return None
        v = _num(o.get("v"))
        return int(v) if _safe_int(v) and not _neg_zero(v) else None

    @staticmethod
    def envelope_shape_ok(o: dict) -> bool:
        if len(o) != 6 or "v" not in o:
            return False
        if not (isinstance(o.get("ty"), str) and o["ty"] in FRAME_TYPES):
            return False
        if not (isinstance(o.get("sid"), str) and isinstance(o.get("rd"), str)):
            return False
        seq = _num(o.get("seq"))
        if not _safe_int(seq) or seq < 0 or _neg_zero(seq):
            return False
        return "d" in o

    @staticmethod
    def parse_frame(body: bytes) -> Optional[dict]:
        """The frame as a dict when it is a well-formed envelope of the current version, else None."""
        o = NetWire.parse_object(body)
        if o is None:
            return None
        v = _num(o.get("v"))
        if v is None or v != WIRE_VERSION or not NetWire.envelope_shape_ok(o):
            return None
        return o

    @staticmethod
    def version_mismatch(body: bytes) -> Optional[int]:
        """The peer's version when the body is a well-formed envelope of a DIFFERENT version, else None."""
        o = NetWire.parse_object(body)
        if o is None:
            return None
        v = _num(o.get("v"))
        if v is None or not _safe_int(v) or _neg_zero(v) or v == WIRE_VERSION:
            return None
        return int(v) if NetWire.envelope_shape_ok(o) else None

    @staticmethod
    def hx(x: int) -> str:
        return format(x, "x")

    @staticmethod
    def unhx(s) -> Optional[int]:
        """Canonical lowercase hex without leading zeros of an element below the field prime; None otherwise."""
        if not isinstance(s, str) or _HEX61.fullmatch(s) is None:
            return None
        v = int(s, 16)
        return v if v < Field.PRIME else None

    @staticmethod
    def unhx_array(a, n: int) -> Optional[List[int]]:
        if not isinstance(a, list) or len(a) != n:
            return None
        out = [NetWire.unhx(x) for x in a]
        return None if any(x is None for x in out) else out


# ---- pairwise-authenticated shares -------------------------------------------------------------------------------------------------------

@dataclass
class PA:
    """x with tag[j] (my tag for verifier j) and key[j] (my key for verifying j's share)."""

    x: int
    tag: List[int]
    key: List[int]


@dataclass
class AW:
    """An authenticated value: a value share plus one MAC share per global key, each pairwise-authenticated."""

    v: PA
    m: List[PA]


@dataclass
class PaEnv:
    id: int
    n: int
    delta: int
    tagged: bool


def _zip(a, b, op):
    return [op(a[i], b[i]) for i in range(len(a))]


class NetPa:
    """Pairwise-authenticated field shares for the identifiable-abort mode of the networked runner: each share carries one tag per verifier and
    one key per peer, so a bad opening is attributable to the party that sent it. The operations are linear and local."""

    PA = PA
    AW = AW
    PaEnv = PaEnv

    @staticmethod
    def pa_add(a: PA, b: PA) -> PA:
        return PA(Field.fadd(a.x, b.x), _zip(a.tag, b.tag, Field.fadd), _zip(a.key, b.key, Field.fadd))

    @staticmethod
    def pa_sub(a: PA, b: PA) -> PA:
        return PA(Field.fsub(a.x, b.x), _zip(a.tag, b.tag, Field.fsub), _zip(a.key, b.key, Field.fsub))

    @staticmethod
    def pa_neg(a: PA) -> PA:
        return PA(Field.fneg(a.x), [Field.fneg(t) for t in a.tag], [Field.fneg(k) for k in a.key])

    @staticmethod
    def pa_scale(a: PA, c: int) -> PA:
        return PA(Field.fmul(a.x, c), [Field.fmul(t, c) for t in a.tag], [Field.fmul(k, c) for k in a.key])

    @staticmethod
    def pa_add_public0(env: PaEnv, a: PA, c: int) -> PA:
        """Adds a PUBLIC constant to party 0's share (every party applies the same call)."""
        if env.id == 0:
            return PA(Field.fadd(a.x, c), a.tag, a.key)
        if not env.tagged:
            return a
        key = list(a.key)
        key[0] = Field.fsub(key[0], Field.fmul(env.delta, c))
        return PA(a.x, a.tag, key)

    @staticmethod
    def w_add(a: AW, b: AW) -> AW:
        return AW(NetPa.pa_add(a.v, b.v), [NetPa.pa_add(a.m[l], b.m[l]) for l in range(len(a.m))])

    @staticmethod
    def w_sub(a: AW, b: AW) -> AW:
        return AW(NetPa.pa_sub(a.v, b.v), [NetPa.pa_sub(a.m[l], b.m[l]) for l in range(len(a.m))])

    @staticmethod
    def w_neg(a: AW) -> AW:
        return AW(NetPa.pa_neg(a.v), [NetPa.pa_neg(p) for p in a.m])

    @staticmethod
    def w_scale(a: AW, c: int) -> AW:
        return AW(NetPa.pa_scale(a.v, c), [NetPa.pa_scale(p, c) for p in a.m])

    @staticmethod
    def w_add_public(env: PaEnv, a: AW, c: int, alpha: List[PA]) -> AW:
        """x + c for a PUBLIC c: party 0's value share moves by c and every MAC share moves by alpha_i * c."""
        return AW(NetPa.pa_add_public0(env, a.v, c), [NetPa.pa_add(a.m[l], NetPa.pa_scale(alpha[l], c)) for l in range(len(a.m))])

    @staticmethod
    def pa_verify(env: PaEnv, a: PA, frm: int, x: int, tag: int) -> bool:
        """Verifies peer frm's opened share x with tag against my key for that peer."""
        return Field.fadd(a.key[frm], Field.fmul(env.delta, x)) == tag

    # ---- wire codec ----

    @staticmethod
    def pa_width(n: int, tagged: bool) -> int:
        return 1 + (2 * (n - 1)) if tagged else 1

    @staticmethod
    def pa_flat(a: PA, id: int, n: int, tagged: bool) -> List[int]:
        out = [a.x]
        if tagged:
            out.extend(a.tag[j] for j in range(n) if j != id)
            out.extend(a.key[j] for j in range(n) if j != id)
        return out

    @staticmethod
    def pa_parse(nums, off: int, id: int, n: int, tagged: bool) -> PA:
        x = nums[off]
        if not tagged:
            return PA(x, [], [])
        tag = [0] * n
        key = [0] * n
        o = off + 1
        for j in range(n):
            if j == id:
                continue
            tag[j] = nums[o]
            o += 1
        for j in range(n):
            if j == id:
                continue
            key[j] = nums[o]
            o += 1
        return PA(x, tag, key)

    @staticmethod
    def aw_width(n: int, keys: int, tagged: bool) -> int:
        return (1 + keys) * NetPa.pa_width(n, tagged)

    @staticmethod
    def aw_flat(a: AW, id: int, n: int, tagged: bool) -> List[int]:
        out = NetPa.pa_flat(a.v, id, n, tagged)
        for p in a.m:
            out += NetPa.pa_flat(p, id, n, tagged)
        return out

    @staticmethod
    def aw_parse(nums, off: int, id: int, n: int, keys: int, tagged: bool) -> AW:
        w = NetPa.pa_width(n, tagged)
        return AW(NetPa.pa_parse(nums, off, id, n, tagged), [NetPa.pa_parse(nums, off + ((1 + l) * w), id, n, tagged) for l in range(keys)])


# ---- forensics ---------------------------------------------------------------------------------------------------------------------------

@dataclass
class SlotDisclosure:
    """One product item's disclosure; recv and rho are dicts keyed by peer index (insertion ordered) of lists of field elements."""

    bits: List[int]
    y: int
    z: int
    recv: Dict[int, List[int]]
    rho: Dict[int, List[int]]


@dataclass
class AuditResult:
    """self_bad: parties whose own disclosure is inconsistent; pair_bad: ordered [receiver, sender] pairs whose OT transcripts disagree."""

    self_bad: List[int]
    pair_bad: List[List[int]]


DEFAULT_FORENSIC_DEADLINE_MS = 30000


def _js_int(o: Any) -> Optional[int]:
    if isinstance(o, bool) or not isinstance(o, (int, float)):
        return None
    d = _num(o)
    return int(d) if fin(d) and d == math.floor(d) and abs(d) < 1e9 else None


class NetForensics:
    """Forensic disclosures of a failed offline triple: each party discloses its OT choice bits, operands, claimed product share and the per-peer
    OT messages; the cross-check names the party whose own data are inconsistent or whose counterpart's transcript disagrees. This namespace holds
    the pure parts (strict parsing, audit, blame, the commit-first binding)."""

    SlotDisclosure = SlotDisclosure
    AuditResult = AuditResult
    DEFAULT_FORENSIC_DEADLINE_MS = DEFAULT_FORENSIC_DEADLINE_MS

    @staticmethod
    def slots_for(partners: int) -> int:
        return 1 + partners

    @staticmethod
    def side(x: dict) -> list:
        return [[peer, [NetWire.hx(v) for v in vals]] for peer, vals in x.items()]

    @staticmethod
    def wire_disclosure(d: List[SlotDisclosure]) -> list:
        """The wire (JSON) form of a disclosure."""
        return [{"bits": "".join(str(b) for b in s.bits), "y": NetWire.hx(s.y), "z": NetWire.hx(s.z), "recv": NetForensics.side(s.recv),
                 "rho": NetForensics.side(s.rho)} for s in d]

    @staticmethod
    def field(s) -> int:
        v = NetWire.unhx(s)
        if v is None:
            raise ValueError("bad field element")
        return v

    @staticmethod
    def parse_disclosure(raw, slots: int, rows: int, peers) -> List[SlotDisclosure]:
        """Strict parse of a peer's disclosure; raises on any deviation from the expected shape."""
        if not isinstance(raw, list) or len(raw) != slots:
            raise ValueError("bad forensic disclosure")
        out = []
        for r in raw:
            if not (isinstance(r, dict) and isinstance(r.get("bits"), str) and len(r["bits"]) == rows and re.fullmatch(r"[01]*", r["bits"])):
                raise ValueError("bad choice bits")
            bits = [1 if c == "1" else 0 for c in r["bits"]]
            out.append(SlotDisclosure(bits, NetForensics.field(r.get("y")), NetForensics.field(r.get("z")),
                                      NetForensics.side_parse(r.get("recv"), rows, peers), NetForensics.side_parse(r.get("rho"), rows, peers)))
        return out

    @staticmethod
    def side_parse(x, rows: int, peers) -> Dict[int, List[int]]:
        if not isinstance(x, list) or len(x) != len(peers):
            raise ValueError("bad peer table")
        m: Dict[int, List[int]] = {}
        for e in x:
            if not (isinstance(e, list) and len(e) == 2 and not isinstance(e[0], bool) and isinstance(e[0], (int, float))):
                raise ValueError("bad peer entry")
            p = _js_int(e[0])
            if p is None or p not in peers or p in m:
                raise ValueError("bad peer entry")
            vals = e[1]
            if not isinstance(vals, list) or len(vals) != rows:
                raise ValueError("bad row table")
            m[p] = [NetForensics.field(v) for v in vals]
        return m

    @staticmethod
    def audit_disclosures(all_: Dict[int, List[SlotDisclosure]], gadget: List[int]) -> AuditResult:
        """Cross-checks every party's disclosure of one failed triple against the public gadget."""
        self_bad: List[int] = []
        pair_bad: List[List[int]] = []
        parties = sorted(all_.keys())
        for i in parties:
            for s, sd in enumerate(all_[i]):
                value = 0
                for k in range(len(gadget)):
                    if k < len(sd.bits) and sd.bits[k] == 1:
                        value += gadget[k]
                implied = Field.fmul(Field.mod(value), sd.y)
                for p in parties:
                    if p == i:
                        continue
                    for v in sd.recv[p]:
                        implied = Field.fadd(implied, Field.mod(v))
                    for v in sd.rho[p]:
                        implied = Field.fsub(implied, v)
                if implied != sd.z:
                    self_bad.append(i)
                for p in parties:
                    if p == i:
                        continue
                    sp = all_[p][s]
                    rho = sp.rho[i]
                    got = sd.recv[p]
                    y = Field.mod(sp.y)
                    bad = False
                    for k in range(len(gadget)):
                        want = Field.fadd(rho[k], Field.fmul(gadget[k], y) if k < len(sd.bits) and sd.bits[k] == 1 else 0)
                        if Field.mod(got[k]) != want:
                            bad = True
                            break
                    if bad:
                        pair_bad.append([i, p])
        return AuditResult(list(dict.fromkeys(self_bad)), pair_bad)

    @staticmethod
    def blame_from(me: int, r: AuditResult) -> Optional[int]:
        """The party the verifier me blames, or None when the evidence cannot name one."""
        own = min((p for p in r.self_bad if p != me), default=None)
        if own is not None:
            return own
        for pr in r.pair_bad:
            if pr[0] == me:
                return pr[1]
            if pr[1] == me:
                return pr[0]
        return None

    @staticmethod
    def disclosure_commit(session_id: str, party: int, triple_index: int, deadline_ms: int, nonce: str, wire) -> str:
        """Binding commitment to a disclosure: session, party, triple index, deadline, a 256-bit nonce and the canonical wire form."""
        text = js_utf8(js_json([session_id, party, triple_index, deadline_ms, nonce, wire]))
        return hashlib.sha256(b"atlas-pca-mpc/forensic-commit/v1\x00" + text).hexdigest()


# ---- codecs ------------------------------------------------------------------------------------------------------------------------------

_B64RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_HEX255 = re.compile(r"(?:0|[1-9a-f][0-9a-f]{0,63})")


def _bytes_of(s) -> bytes:
    return bytes(s) if isinstance(s, (bytes, bytearray)) else str(s).encode("utf-8")


class NetCodec:
    """Canonical encodings of the OT-over-network messages (one accepted string per value) and the gadget-seed agreement helpers: strict base64,
    minimal lowercase hex field elements, subgroup-validated points, and the commitment / signed statement of the gadget seed exchange."""

    @staticmethod
    def b64(u: bytes) -> str:
        return base64.b64encode(bytes(u)).decode("ascii")

    @staticmethod
    def unb64(s, length: Optional[int] = None) -> bytes:
        """Strict base64: re-encoding must reproduce the input (no trailing-bit or padding aliases); length < 0 (or None) means any length."""
        if not isinstance(s, str) or _B64RE.fullmatch(s) is None:
            raise ValueError("bad base64")
        try:
            b = base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("bad base64") from None
        if NetCodec.b64(b) != s:
            raise ValueError("non-canonical base64")
        if length is not None and length >= 0 and len(b) != length:
            raise ValueError("bad length")
        return b

    @staticmethod
    def pt_j(p: Point) -> dict:
        x, y = Ec.to_affine(p)
        return {"x": NetWire.hx(x), "y": NetWire.hx(y)}

    @staticmethod
    def hex_big(s) -> int:
        """Canonical lowercase hex without leading zeros of an element below the curve field prime."""
        if not isinstance(s, str) or _HEX255.fullmatch(s) is None:
            raise ValueError("bad field element")
        v = int(s, 16)
        if v >= Ec.Q:
            raise ValueError("non-canonical field element")
        return v

    @staticmethod
    def j_pt(v) -> Point:
        """A point from {x, y} canonical hex, validated to be a non-identity prime-order-subgroup point."""
        if not isinstance(v, dict):
            raise ValueError("bad point")
        x = NetCodec.hex_big(v.get("x"))
        y = NetCodec.hex_big(v.get("y"))
        p = Point(x, y, 1, (x * y) % Ec.Q)
        Ec.assert_in_subgroup(p, "received point")
        return p

    @staticmethod
    def sharings_per_triple(partners: int) -> int:
        return 3 + (2 * partners)

    @staticmethod
    def gadget_commit(session_id, party: int, seed) -> str:
        """Commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex."""
        return hashlib.sha256(b"atlas-pca-mpc/gadget-commit" + _bytes_of(session_id) + str(party).encode("ascii") + _bytes_of(seed)).hexdigest()

    @staticmethod
    def gadget_statement(session_id: str, rnd: str, signer: int, value) -> bytes:
        """The exact bytes a party signs in the gadget seed exchange (round is "gd-c" or "gd-o")."""
        return js_utf8(js_json(["atlas-pca-mpc/gadget-sig/v1", session_id, rnd, signer, value]))
