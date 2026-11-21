"""Pairwise base oblivious transfer OVER THE NETWORK (research prototype), port of the reference's net/ot-net.ts.

  - 'ec'  : the malicious-secure Chou-Orlandi-style base OT on Ed25519 with a Schnorr proof of knowledge and subgroup validation of every
            received point.
  - 'lwe' : the post-quantum endemic OT over Module-LWE (mpc_lwe_ot).

A FUNCTIONAL-CORRECTNESS demonstration: afterwards the receiver reveals its choice bits and a hash of each received pad (a demo-only step, NOT
part of the OT) so the sender can check the pads over a real network."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Callable, List, TypeVar

from . import mpc_lwe_ot as lwe
from .mpc_ec import SchnorrProof
from .mpc_mesh import Mesh
from .mpc_net import NetAbort, NetCodec, NetWire, js_utf8
from .mpc_ot import BaseOtAbort, BaseOtBinding, Ot

T = TypeVar("T")

# Codec helpers the offline phase imports from here (same names as the reference, snake_case).
b64 = NetCodec.b64
unb64 = NetCodec.unb64
pt_j = NetCodec.pt_j
j_pt = NetCodec.j_pt
hex_big = NetCodec.hex_big
hx = NetWire.hx


def J(v: Any) -> bool:
    """A JSON object (not an array, not null)."""
    return isinstance(v, dict)


def _sha(*parts: bytes) -> str:
    h = hashlib.sha256()
    for x in parts:
        h.update(x)
    return h.hexdigest()


@dataclass
class OtNetResult:
    kind: str
    role: str
    count: int
    ms: float
    wasm_curve_active: bool
    matched: bool
    pad_digest: str  # digest over all pads this party holds (sender: both pads; receiver: chosen pads): evidence, not secrets


def net_binding(mesh: Mesh, sender_index: int, receiver_index: int, rnd: str) -> BaseOtBinding:
    """Binding of a base OT on this mesh: session (hashed to a fixed length), who sends, who receives, which round."""
    sid = hashlib.sha256(b"atlas-pca-mpc/net-session/v2" + js_utf8(mesh.session_id)).digest()
    return BaseOtBinding(sid, sender_index, receiver_index, rnd)


def _parsing(mesh: Mesh, peer: int, rd: str, f: Callable[[], T]) -> T:
    """Wrap peer-supplied data parsing so any failure aborts naming the peer."""
    try:
        return f()
    except Exception as e:  # noqa: BLE001
        ne = NetAbort("malformed", peer, mesh.self_id, "round '%s': %s" % (rd, e))
        mesh.fail(ne)
        raise ne from None


def _pairs(raw: Any, count: int, what: str) -> List[tuple]:
    if not isinstance(raw, list) or len(raw) != count:
        raise ValueError("bad %s array" % what)
    out = []
    for pp in raw:
        if not isinstance(pp, list) or len(pp) != 2:
            raise ValueError("bad %s pair" % what)
        out.append((unb64(pp[0]), unb64(pp[1])))
    return out


def _is_bit(c: Any) -> bool:
    return isinstance(c, (int, float)) and not isinstance(c, bool) and (c == 0 or c == 1)


async def run_ot_sender(mesh: Mesh, peer: int, kind: str, count: int) -> OtNetResult:
    t0 = time.perf_counter()
    rng = Ot.secure_ot_random()
    if kind == "ec":
        binding = net_binding(mesh, mesh.self_id, peer, "ot-ec")
        setup = Ot.mal_base_ot_sender_setup(rng, binding)
        mesh.send(peer, "ot-S", {"S": pt_j(setup.s), "U": pt_j(setup.proof.u), "z": hx(setup.proof.z)})
        r_raw = await mesh.recv(peer, "ot-R")

        def parse_r():
            if not isinstance(r_raw, list) or len(r_raw) != count:
                raise ValueError("bad R array")
            return [j_pt(x) for x in r_raw]

        R = _parsing(mesh, peer, "ot-R", parse_r)
        try:
            sender_pads = Ot.mal_base_ot_sender_derive(setup.y, setup.t, R, setup.s, binding)
        except Exception as e:  # noqa: BLE001
            ne = NetAbort("malformed", peer, mesh.self_id, str(e))
            mesh.fail(ne)
            raise ne from None
    else:
        m = await mesh.recv(peer, "ot-recv")

        def parse_recv():
            if not J(m) or not isinstance(m.get("points"), list) or not isinstance(m.get("rhos"), list) or len(m["points"]) != count or len(m["rhos"]) != count:
                raise ValueError("bad receiver message")
            pts = []
            for pp in m["points"]:
                if not isinstance(pp, list) or len(pp) != 2:
                    raise ValueError("bad point pair")
                pts.append((unb64(pp[0]), unb64(pp[1])))
            return lwe.ReceiverMessage(unb64(m.get("rn"), 32), pts, [unb64(r, 32) for r in m["rhos"]])

        msg = _parsing(mesh, peer, "ot-recv", parse_recv)
        try:
            sm = lwe.send_random(msg)
        except Exception as e:  # noqa: BLE001
            ne = NetAbort("malformed", peer, mesh.self_id, "lwe sender: %s" % e)
            mesh.fail(ne)
            raise ne from None
        sender_pads = sm.sender_pads
        mesh.send(peer, "ot-ct", [[b64(a), b64(b)] for a, b in sm.ciphertexts])
    # demo-only verification: the receiver reveals choices + pad hashes
    v = await mesh.recv(peer, "ot-verify")

    def parse_verify():
        if not J(v) or not isinstance(v.get("choices"), list) or not isinstance(v.get("padHashes"), list) or len(v["choices"]) != count or len(v["padHashes"]) != count:
            raise ValueError("bad verify message")
        return all(_is_bit(c) and _sha(sender_pads[i][int(c)]) == v["padHashes"][i] for i, c in enumerate(v["choices"]))

    ok = _parsing(mesh, peer, "ot-verify", parse_verify)
    mesh.send(peer, "ot-done", {"matched": ok})
    await mesh.finish()
    return OtNetResult(kind, "sender", count, (time.perf_counter() - t0) * 1000.0, False, ok,
                       _sha(*[x for a, b in sender_pads for x in (a, b)]))


async def run_ot_receiver(mesh: Mesh, peer: int, kind: str, count: int) -> OtNetResult:
    t0 = time.perf_counter()
    rng = Ot.secure_ot_random()
    choices = [rng.bytes(1)[0] & 1 for _ in range(count)]
    if kind == "ec":
        s_raw = await mesh.recv(peer, "ot-S")

        def parse_s():
            if not J(s_raw):
                raise ValueError("bad S message")
            proof = SchnorrProof(j_pt(s_raw.get("U")), hex_big(s_raw.get("z")))
            return j_pt(s_raw.get("S")), proof

        S, proof = _parsing(mesh, peer, "ot-S", parse_s)
        try:
            res = Ot.mal_base_ot_receiver_respond(S, proof, choices, rng, net_binding(mesh, peer, mesh.self_id, "ot-ec"))
        except Exception as e:  # noqa: BLE001
            ne = NetAbort("commitment" if isinstance(e, BaseOtAbort) else "malformed", peer, mesh.self_id, str(e))
            mesh.fail(ne)
            raise ne from None
        recv_pads = res.recv_pads
        mesh.send(peer, "ot-R", [pt_j(p) for p in res.r])
    else:
        message, state = lwe.receive(choices)
        mesh.send(peer, "ot-recv", {"rn": b64(message.rn), "points": [[b64(a), b64(b)] for a, b in message.points], "rhos": [b64(r) for r in message.rhos]})
        ct_raw = await mesh.recv(peer, "ot-ct")
        cts = _parsing(mesh, peer, "ot-ct", lambda: _pairs(ct_raw, count, "ciphertext"))
        recv_pads = _parsing(mesh, peer, "ot-ct", lambda: lwe.recover_random(state, lwe.SenderMessage(cts, [])))
    mesh.send(peer, "ot-verify", {"choices": choices, "padHashes": [_sha(p) for p in recv_pads]})
    d = await mesh.recv(peer, "ot-done")
    matched = J(d) and d.get("matched") is True
    await mesh.finish()
    return OtNetResult(kind, "receiver", count, (time.perf_counter() - t0) * 1000.0, False, matched, _sha(*recv_pads))
