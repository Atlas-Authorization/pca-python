"""Agreement on the joint choice-bit gadget seeds: a signed commit-reveal with an echo round, so that ONE corrupt party cannot make the honest
parties derive different gadgets and then blame each other. Port of the reference's net/gadget.ts.

Every commitment and every opening is SIGNED by its sender with the sender's pinned TLS identity key. After the reveal each party echoes, to
every peer, the signed values it received from each third party (`gd-e`). A receiver checks each echoed statement against what it received
directly: an echoed signature that does not verify is a forgery by the echoer (blame the echoer); an echoed statement that verifies but differs
from the one received directly means the signer signed two values for the same round (blame the signer, with both statements as transferable
evidence). With n = 2 there is no third party, so the echo round is skipped."""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .mpc_net import NetAbort, NetCodec

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEXSIG = re.compile(r"[0-9a-f]{16,200}")


@dataclass
class GadgetIo:
    """exchange(rd, mine, parse) = one un-echoed all-to-all round (a raise inside parse aborts naming that peer); bad(p, what) raises."""

    exchange: Callable[..., Awaitable[Dict[int, Any]]]
    bad: Callable[[int, str], Any]


def _is_signed(x: Any, value_re) -> bool:
    return (isinstance(x, dict) and isinstance(x.get("v"), str) and value_re.fullmatch(x["v"]) is not None
            and isinstance(x.get("s"), str) and _HEXSIG.fullmatch(x["s"]) is not None)


async def agree_gadget_seeds(net, n: int, io: GadgetIo, my_seed: Optional[bytes] = None) -> List[bytes]:
    """Run the signed commit / reveal / echo and return every party's seed in party order (mine included). `net` provides self_id, session_id,
    sign(data) and verify(peer, data, sig) (the Mesh); `my_seed` is injectable for tests."""
    if my_seed is None:
        my_seed = secrets.token_bytes(32)
    ident = net.self_id
    sid = net.session_id

    def sign(rnd: str, value: str) -> dict:
        return {"v": value, "s": bytes(net.sign(NetCodec.gadget_statement(sid, rnd, ident, value))).hex()}

    def check(signer: int, rnd: str, m: dict) -> bool:
        return bool(net.verify(signer, NetCodec.gadget_statement(sid, rnd, signer, m["v"]), bytes.fromhex(m["s"])))

    def parse_commit(p, raw):
        if not _is_signed(raw, _HEX64):
            return io.bad(p, "bad gadget commitment")
        if not check(p, "gd-c", raw):
            return io.bad(p, "gadget commitment signature does not verify")
        return raw

    my_commit = NetCodec.gadget_commit(sid, ident, my_seed)
    commits = await io.exchange("gd-c", lambda _p: sign("gd-c", my_commit), parse_commit)
    my_seed_hex = bytes(my_seed).hex()

    def parse_open(p, raw):
        if not _is_signed(raw, _HEX64):
            return io.bad(p, "bad gadget seed")
        if not check(p, "gd-o", raw):
            return io.bad(p, "gadget seed signature does not verify")
        if NetCodec.gadget_commit(sid, p, bytes.fromhex(raw["v"])) != commits[p]["v"]:
            raise NetAbort("commitment", p, ident, "party %d opened a gadget seed that does not match its commitment" % p)
        return raw

    opens = await io.exchange("gd-o", lambda _p: sign("gd-o", my_seed_hex), parse_open)

    if n >= 3:
        others = [i for i in range(n) if i != ident]

        def mine(peer):
            return [{"j": j, "c": commits[j], "o": opens[j]} for j in others if j != peer]

        def parse_echo(p, raw):
            expect = [j for j in others if j != p]
            if not isinstance(raw, list) or len(raw) != len(expect):
                return io.bad(p, "bad gadget echo")
            for k, j in enumerate(expect):
                e = raw[k]
                ej = e.get("j") if isinstance(e, dict) else None
                if (not isinstance(e, dict) or isinstance(ej, bool) or not isinstance(ej, (int, float)) or ej != j
                        or not _is_signed(e.get("c"), _HEX64) or not _is_signed(e.get("o"), _HEX64)):
                    return io.bad(p, "bad gadget echo entry")
                # a statement that does not verify under j's pinned key was forged by the echoer p
                if not check(j, "gd-c", e["c"]) or not check(j, "gd-o", e["o"]):
                    return io.bad(p, "gadget echo carries a statement that party %d did not sign" % j)
                mine_c, mine_o = commits[j], opens[j]
                c_diff = e["c"]["v"] != mine_c["v"]
                if c_diff or e["o"]["v"] != mine_o["v"]:
                    # both statements verify under j's key and differ: j signed two values for one round
                    raise NetAbort("equivocation", j, ident,
                                   "party %d signed different gadget %s for different parties (shown by party %d's echo)" % (j, "commitments" if c_diff else "seeds", p),
                                   None, None, None,
                                   {"signer": j, "round": "gd-c" if c_diff else "gd-o",
                                    "statements": [mine_c, e["c"]] if c_diff else [mine_o, e["o"]]})
            return True

        await io.exchange("gd-e", mine, parse_echo)
    return [bytes(my_seed) if p == ident else bytes.fromhex(opens[p]["v"]) for p in range(n)]
