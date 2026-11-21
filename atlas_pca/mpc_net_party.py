"""One MPC node (a party or the dealer) as its OWN OS process, talking to the others only over the mutual-TLS mesh (reference:
net/party-main.ts). Usage:  python -m atlas_pca.mpc_net_party <config.json>   or   python -m atlas_pca.mpc_net_party keygen <dir> <cn>
Prints exactly one JSON line (the result or the attributable abort) on stdout. Exit codes: 0 ok, 3 abort or refusal to start.
Test hooks (behavior / frameFault / dealerFault) need both "unsafeTestHooks": true in the config and the environment variable
PCA_MPC_UNSAFE_TEST_HOOKS=1, else the node refuses to start."""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, Optional

from .mpc import DecisionVector
from .mpc_certs import generate_identity
from .mpc_mesh import Mesh, MeshConfig, NodeAddr
from .mpc_net import NetWire
from .mpc_net_faults import FrameFault, tamper_for
from .mpc_net_prep import Behavior, CrashParty, SilentParty
from .mpc_spdz import DealerFault

NetAbort = NetWire.NetAbort


def _out(o: Any) -> None:
    sys.stdout.write(json.dumps(o, default=str) + "\n")
    sys.stdout.flush()


def _read(p: str) -> str:
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def _keygen(dir_: str, cn: str) -> None:
    ident = generate_identity(cn)
    os.makedirs(dir_, mode=0o700, exist_ok=True)
    kp, cp = os.path.join(dir_, "key.pem"), os.path.join(dir_, "cert.pem")
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(ident.key_pem)
    with open(cp, "w", encoding="ascii") as f:
        f.write(ident.cert_pem)
    _out({"keyPath": kp, "certPath": cp})


def _result_json(r: Any) -> Dict[str, Any]:
    return {
        "id": r.id, "n": r.n, "Q": r.Q,
        "composed": {"allow": r.composed.allow, "t": r.composed.t, "rQuant": r.composed.r_quant},
        "rounds": [{"rd": x.rd, "ms": x.ms, "bytesOut": x.bytes_out, "bytesIn": x.bytes_in} for x in r.rounds],
        "transcriptDigest": r.transcript_digest, "wallMs": r.wall_ms, "multiplications": r.multiplications, "opens": r.opens,
        "offlineMode": r.offline_mode, "macKeys": r.mac_keys, "sacrificedTriples": r.sacrificed_triples,
        "sacrificePartners": r.sacrifice_partners, "identifiableAbort": r.identifiable_abort,
    }


def _abort_json(role: str, cfg_id: Any, e: Any, mesh: Optional[Mesh]) -> Dict[str, Any]:
    o: Dict[str, Any] = {
        "ok": False, "role": role, "id": cfg_id,
        "error": {"kind": e.kind, "blamed": e.blamed, "reporter": e.reporter, "claimedKind": e.claimed_kind, "claimedBlame": e.claimed_blame,
                  "reason": e.reason, "evidence": e.evidence, "deadlineMs": e.deadline_ms, "message": str(e)},
    }
    if mesh is not None:
        o["links"], o["events"] = mesh.stats(), mesh.events
    return o


def _big(x: Any) -> Optional[int]:
    return None if x is None else int(x)


async def run_node(cfg: Dict[str, Any]) -> int:
    from .mpc_net_protocol import DealerConfig, PartyConfig, run_dealer, run_party  # lazy

    role, nid, n = cfg["role"], cfg["id"], cfg["n"]
    hooks = any(k in cfg for k in ("behavior", "frameFault", "dealerFault"))
    if hooks and not (cfg.get("unsafeTestHooks") is True and os.environ.get("PCA_MPC_UNSAFE_TEST_HOOKS") == "1"):
        _out({"ok": False, "role": role, "id": nid, "error": {"kind": "local", "blamed": None, "reporter": nid,
              "message": "refusing to start: test hooks (behavior/frameFault) are not enabled in this environment"}})
        return 3
    nodes = [NodeAddr(x["id"], x["host"], x["port"], _read(x["certPath"])) for x in cfg["nodes"]]
    ff = cfg.get("frameFault")
    kw: Dict[str, Any] = {}
    if cfg.get("listenHost") is not None:
        kw["listen_host"] = cfg["listenHost"]
    if cfg.get("recvTimeoutMs") is not None:
        kw["recv_timeout_ms"] = cfg["recvTimeoutMs"]
    if cfg.get("connectTimeoutMs") is not None:
        kw["connect_timeout_ms"] = cfg["connectTimeoutMs"]
    mesh = Mesh(MeshConfig(
        nid, nodes, _read(cfg["keyPath"]), _read(cfg["certPath"]), cfg["sessionId"],
        link_to=[x.id for x in nodes if x.id < n] if role == "dealer" else None,
        tamper=tamper_for(FrameFault(ff["kind"], ff["round"], ff.get("to"), ff.get("accuse"))) if ff else None,
        unsafe_test_hooks=hooks, **kw))
    code = 0
    t0 = time.monotonic()
    try:
        await mesh.connect()
        connect_ms = int((time.monotonic() - t0) * 1000)
        if role == "dealer":
            df = cfg.get("dealerFault")
            await run_dealer(DealerConfig(
                n=n, mesh=mesh, Q=cfg.get("Q"), seed=_big(cfg.get("dealerSeed")),
                insecure_trusted_dealer=cfg.get("insecureTrustedDealer") is True,
                mac_fault_at_input=df.get("macFaultAtInput") if df else None,
                fault=DealerFault(_big(df.get("keepCDelta")), [_big(x) for x in df["partnerCDelta"]] if df.get("partnerCDelta") is not None else None) if df else None))
            _out({"ok": True, "role": "dealer", "id": nid, "connectMs": connect_ms, "links": mesh.stats(), "events": mesh.events})
        elif role in ("ot-sender", "ot-receiver"):
            from . import mpc_net_ot as ot  # lazy: only these roles need the OT stack
            k = cfg.get("ot") or {"kind": "ec", "count": 128}
            if role == "ot-sender":
                r = await ot.run_ot_sender(mesh, 1, k["kind"], k["count"])
            else:
                r = await ot.run_ot_receiver(mesh, 0, k["kind"], k["count"])
            _out({"ok": True, "role": role, "connectMs": connect_ms, "result": {"kind": r.kind, "role": r.role, "count": r.count, "ms": r.ms, "wasmCurveActive": r.wasm_curve_active, "matched": r.matched, "padDigest": r.pad_digest}, "links": mesh.stats(), "events": mesh.events})
        else:
            inp = cfg["input"]
            b = cfg.get("behavior")
            r = await run_party(PartyConfig(
                id=nid, n=n, input=DecisionVector(inp["allow"], inp["t"], inp["rQuant"]), mesh=mesh, session_id=cfg["sessionId"], Q=cfg.get("Q"),
                offline=cfg.get("offline"), insecure_trusted_dealer=cfg.get("insecureTrustedDealer") is True,
                behavior=Behavior(b["kind"], b.get("round")) if b else None, unsafe_test_hooks=hooks))
            _out({"ok": True, "role": "party", "connectMs": connect_ms, "result": _result_json(r), "links": mesh.stats(), "events": mesh.events})
    except asyncio.CancelledError:
        raise
    except CrashParty:
        os._exit(7)  # abrupt, like the reference: no abort frames, no output, no flush
    except SilentParty:
        # stay connected and say nothing: the peers must time out (bounded here so the process never hangs)
        await asyncio.sleep(4 * (cfg.get("recvTimeoutMs") or 20_000) / 1000)
        return 0
    except Exception as e:  # noqa: BLE001
        ne = e if isinstance(e, NetAbort) else (mesh.failed or NetAbort("local", None, nid, str(e)))
        _out(_abort_json(role, nid, ne, mesh))
        code = 3
    # give sockets a moment to flush abort frames, then close regardless of lingering handles
    await asyncio.sleep(0.3)
    mesh._close_all()
    return code


def main(argv: Optional[list] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "keygen":
        if len(argv) < 2:
            sys.stderr.write("usage: mpc_net_party keygen <dir> [cn]\n")
            return 2
        _keygen(argv[1], argv[2] if len(argv) > 2 else "mpc-node")
        return 0
    if len(argv) != 1:
        sys.stderr.write("usage: mpc_net_party <config.json> | keygen <dir> [cn]\n")
        return 2
    return asyncio.run(run_node(json.loads(_read(argv[0]))))


if __name__ == "__main__":
    sys.exit(main())
