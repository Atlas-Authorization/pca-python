"""Commit-first forensic disclosure exchange of a failed offline triple (port of the reference's net/forensics.ts `exchangeDisclosures`).
Nobody opens before every commitment is in hand, so no party's disclosure can depend on another's; a late or absent party times out at the
shared deadline. The pure parts (strict parsing, audit, blame, the commitment) are NetForensics in mpc_net."""
from __future__ import annotations

import re
import secrets
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .mpc_net import NetAbort, NetForensics, SlotDisclosure

_HEX64 = re.compile(r"[0-9a-f]{64}")


async def exchange_disclosures(*, session_id: str, id: int, n: int, triple_index: int, mine: List[SlotDisclosure], slots: int, rows: int,
                               deadline_ms: int, exchange: Callable[..., Awaitable[Dict[int, Any]]],
                               bad: Callable[[int, str], Any]) -> Dict[int, List[SlotDisclosure]]:
    """Every OTHER party's verified disclosure. `exchange(rd, mine_fn, parse_fn, timeout_ms)` is one un-echoed all-to-all round whose receive
    deadline is `deadline_ms`; `bad(p, what)` raises a malformed-data abort naming peer p."""
    wire = NetForensics.wire_disclosure(mine)
    nonce = secrets.token_hex(32)
    my_commit = NetForensics.disclosure_commit(session_id, id, triple_index, deadline_ms, nonce, wire)

    def parse_commit(p: int, raw: Any) -> str:
        if not isinstance(raw, dict):
            return bad(p, "bad forensic commitment")
        c = raw.get("c")
        if not isinstance(c, str) or _HEX64.fullmatch(c) is None:
            return bad(p, "bad forensic commitment")
        d = raw.get("d")
        if isinstance(d, bool) or not isinstance(d, (int, float)) or d != deadline_ms:
            return bad(p, "forensic deadline %s differs from the agreed %s" % (d, deadline_ms))
        return c

    commits = await exchange("forensic-c", lambda peer: {"c": my_commit, "d": deadline_ms}, parse_commit, deadline_ms)

    def parse_open(p: int, raw: Any) -> List[SlotDisclosure]:
        nn = raw.get("nonce") if isinstance(raw, dict) else None
        if not isinstance(nn, str) or _HEX64.fullmatch(nn) is None:
            return bad(p, "bad forensic opening")
        if NetForensics.disclosure_commit(session_id, p, triple_index, deadline_ms, nn, raw.get("w")) != commits.get(p):
            raise NetAbort("commitment", p, id, "party %d opened a forensic disclosure that does not match its commitment" % p)
        return NetForensics.parse_disclosure(raw.get("w"), slots, rows, [q for q in range(n) if q != p])

    return await exchange("forensic-o", lambda peer: {"w": wire, "nonce": nonce}, parse_open, deadline_ms)
