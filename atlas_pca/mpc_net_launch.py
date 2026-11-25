"""Local launcher for the distributed MPC (reference: net/launch-local.ts + launch-support.ts): runs n parties and, in trusted-dealer
mode, a dealer node in THIS process on loopback as asyncio tasks, each with its own fresh per-run identity and its own mutual-TLS
mesh, talking only over sockets exactly as separate hosts would. A stuck run is cut off after kill_after_ms."""
from __future__ import annotations

from ._fin import fin
import asyncio
import math
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .mpc import DecisionVector
from .mpc_certs import generate_identity
from .mpc_mesh import Mesh, MeshConfig, NodeAddr
from .mpc_net import NetWire
from .mpc_net_faults import FaultProxy, WireFault
from .mpc_net_prep import Behavior, CrashParty, SilentParty
from .mpc_spdz import DealerFault

NetAbort = NetWire.NetAbort


def _scale() -> float:
    try:
        v = float(os.environ.get("PCA_MPC_TEST_TIMEOUT_SCALE", "1"))
    except ValueError:
        return 1.0
    return v if fin(v) and v > 0 else 1.0


TIMEOUT_SCALE = _scale()


def T(ms: float) -> int:
    """Scale a duration (ms) by the one timeout knob (env PCA_MPC_TEST_TIMEOUT_SCALE, default 1)."""
    return math.ceil(ms * TIMEOUT_SCALE)


def bind_listeners(count: int) -> List[socket.socket]:
    """`count` loopback sockets, each bound to port 0 by the node's own listener: the port is whatever the OS gave and the socket stays open
    until the node serves on it, so no other socket can be handed the same port in between."""
    socks: List[socket.socket] = []
    try:
        for _ in range(count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socks.append(s)
            s.bind(("127.0.0.1", 0))
        return socks
    except BaseException:
        for s in socks:
            s.close()
        raise


@dataclass
class WireFaultSpec:
    dialer: int
    target: int
    fault: WireFault


@dataclass
class LaunchOptions:
    n: int
    vectors: List[DecisionVector]
    Q: Optional[int] = None
    recv_timeout_ms: int = 30_000
    connect_timeout_ms: int = 120_000
    kill_after_ms: int = 120_000  # hard wall-clock cap for the whole run
    behaviors: Dict[int, Behavior] = field(default_factory=dict)  # TEST ONLY, parties only
    offline: str = "no-dealer"  # or 'trusted-dealer' (spawns a dealer node; needs insecure_trusted_dealer)
    insecure_trusted_dealer: bool = False
    dealer_seed: Optional[int] = None
    dealer_fault: Optional[DealerFault] = None
    mac_fault_at_input: Optional[int] = None
    wire_fault: Optional[WireFaultSpec] = None  # TEST ONLY


@dataclass
class NodeOutput:
    """What a node ended with: a result (parties only), or the exception that stopped it."""

    id: int
    role: str
    result: Any = None
    error: Optional[BaseException] = None

    @property
    def abort(self) -> Optional[Exception]:
        return self.error if isinstance(self.error, NetAbort) else None


@dataclass
class Launched:
    outputs: List[NodeOutput]
    wall_ms: int
    proxy_log: List[str]


async def launch_local(o: LaunchOptions) -> Launched:
    from .mpc_net_protocol import DealerConfig, PartyConfig, run_dealer, run_party  # lazy: written alongside this module

    n = o.n
    if len(o.vectors) != n:
        raise ValueError("launch_local: one decision vector per party")
    dealer_mode = o.offline == "trusted-dealer"
    if o.offline not in ("trusted-dealer", "no-dealer"):
        raise ValueError("launch_local: offline must be 'trusted-dealer' or 'no-dealer'")
    if dealer_mode and not o.insecure_trusted_dealer:
        raise ValueError("launch_local: offline 'trusted-dealer' requires insecure_trusted_dealer=True")
    count = n + 1 if dealer_mode else n
    session_id = secrets.token_hex(8)
    socks = bind_listeners(count + 1)  # the last one is for the optional fault proxy
    ports = [s.getsockname()[1] for s in socks]
    ids = [generate_identity("mpc-node-%d" % i) for i in range(count)]
    nodes = [NodeAddr(i, "127.0.0.1", ports[i], ids[i].cert_pem) for i in range(count)]
    proxy: Optional[FaultProxy] = None
    if o.wire_fault is not None:
        wf = o.wire_fault
        f = wf.fault
        proxy = FaultProxy(ports[count], ("127.0.0.1", ports[wf.target]),
                           WireFault(f.kind, f.dir, f.after_bytes, T(f.ms) if f.ms is not None else None), listen_sock=socks[count])
        await proxy.listen()

    def role_of(i: int) -> str:
        return "dealer" if dealer_mode and i == n else "party"

    meshes: List[Mesh] = []
    for i in range(count):
        ns = nodes
        if o.wire_fault is not None and i == o.wire_fault.dialer:
            ns = list(nodes)
            t = nodes[o.wire_fault.target]
            ns[o.wire_fault.target] = NodeAddr(t.id, t.host, ports[count], t.cert_pem)
        hooks = i in o.behaviors or (role_of(i) == "dealer" and (o.dealer_fault is not None or o.mac_fault_at_input is not None))
        meshes.append(Mesh(MeshConfig(
            i, ns, ids[i].key_pem, ids[i].cert_pem, session_id, link_to=list(range(n)) if role_of(i) == "dealer" else None,
            listen_host="127.0.0.1", connect_timeout_ms=T(o.connect_timeout_ms), recv_timeout_ms=T(o.recv_timeout_ms),
            unsafe_test_hooks=hooks, listen_sock=socks[i])))

    state = {"active": count, "idle": 0}

    async def run_node(i: int) -> NodeOutput:
        mesh, role = meshes[i], role_of(i)
        try:
            await mesh.connect()
            if role == "dealer":
                await run_dealer(DealerConfig(n=n, mesh=mesh, insecure_trusted_dealer=o.insecure_trusted_dealer, Q=o.Q, seed=o.dealer_seed,
                                              fault=o.dealer_fault, mac_fault_at_input=o.mac_fault_at_input))
                return NodeOutput(i, role)
            b = o.behaviors.get(i)
            res = await run_party(PartyConfig(
                id=i, n=n, input=o.vectors[i], mesh=mesh, session_id=session_id, Q=o.Q,
                offline="trusted-dealer" if dealer_mode else "no-dealer", insecure_trusted_dealer=o.insecure_trusted_dealer,
                behavior=b, unsafe_test_hooks=b is not None))
            return NodeOutput(i, role, res)
        except CrashParty as e:
            mesh._close_all()  # abrupt: no abort frame, peers see a disconnect
            return NodeOutput(i, role, None, e)
        except SilentParty as e:
            # stays connected and stops participating; peers must time out. Idle until every other node has finished.
            state["idle"] += 1
            while state["active"] > state["idle"]:
                await asyncio.sleep(0.05)
            return NodeOutput(i, role, None, e)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            return NodeOutput(i, role, None, mesh.failed if (mesh.failed is not None and not isinstance(e, NetAbort)) else e)
        finally:
            state["active"] -= 1

    t0 = time.monotonic()
    tasks = [asyncio.ensure_future(run_node(i)) for i in range(count)]
    try:
        await asyncio.wait(tasks, timeout=T(o.kill_after_ms) / 1000.0)
        outs: List[NodeOutput] = []
        stuck = [t for t in tasks if not t.done()]
        for m in meshes if stuck else []:
            m._close_all()
        for t in stuck:
            t.cancel()
        if stuck:
            await asyncio.gather(*stuck, return_exceptions=True)
        for i, t in enumerate(tasks):
            if t in stuck or t.cancelled():
                outs.append(NodeOutput(i, role_of(i), None, NetAbort("local", None, i, "killed after %dms" % T(o.kill_after_ms))))
            else:
                outs.append(t.result())
    finally:
        for t in tasks:
            t.cancel()
        for m in meshes:
            m._close_all()
        if proxy is not None:
            proxy.close()
        for sk in socks:  # a listener no node served on (the unused proxy slot, a node that failed early)
            sk.close()
    return Launched(outs, int((time.monotonic() - t0) * 1000), list(proxy.log) if proxy else [])
