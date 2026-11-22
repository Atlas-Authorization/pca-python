"""Chain compaction (the TypeScript ``chain-compact``): a long delegation chain folds into one handle, a Merkle root over the ordered hop
hashes, plus the leaf hop. A verifier that has already verified the full chain once remembers it under that root; later presentations
carry only ``{depth, hops_root, leaf}``.

Nothing is trusted from the presentation: a compact chain is accepted only when the verifier's OWN memo holds an entry for ``hops_root``
that its own ``verify_chain`` produced (:meth:`ChainMemo.remember_verified` runs the verification itself), the depth equals the memoized
depth and the presented leaf hashes to the memoized last hop. What it gives the caveat language is a
:class:`atlas_pca.caveat_lang.ChainView`. The PCActn wire still carries ``cap_chain``."""
import math
from ._fin import fin
from typing import Any, Dict, List, Optional

from .caveat_lang import ChainView, chain_view
from .intent_wb import _closed_members, _is_safe_int
from .pca import MAX_CHAIN_DEPTH, cap_hash, merkle_root, verify_chain

__all__ = ["CHAIN_HOP_DOMAIN", "CHAIN_MEMO_MAX_TTL_MS", "CHAIN_MEMO_DEFAULT_MAX_ENTRIES", "hop_leaf", "hops_root", "compact_chain",
           "compact_chain_shape_error", "ChainMemo", "view_of_chain"]

CHAIN_HOP_DOMAIN = "atlas-pca/chain-hop/v1"
#: A memo entry lives at most this long (the chain's caveats may expire sooner; the verifier still evaluates them every time).
CHAIN_MEMO_MAX_TTL_MS = 3_600_000
CHAIN_MEMO_DEFAULT_MAX_ENTRIES = 10_000


def hop_leaf(hop: dict) -> dict:
    """The Merkle leaf of one hop: its content hash under a domain tag."""
    return {"d": CHAIN_HOP_DOMAIN, "hop": cap_hash(hop)}


def hops_root(chain: List[dict]) -> str:
    """The handle of a chain: Merkle root over the ordered hop leaves."""
    if not isinstance(chain, list):  # JS: chain.map is not a function
        raise TypeError("chain.map is not a function")
    return merkle_root([hop_leaf(h) for h in chain])


def compact_chain(chain: List[dict]) -> Dict[str, Any]:
    """Fold a chain. Raises on an empty or over-deep chain. Does not verify it (the memo does)."""
    if not isinstance(chain, list) or len(chain) == 0 or len(chain) > MAX_CHAIN_DEPTH:
        raise ValueError("compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops")
    return {"v": 1, "kind": "pca-chain-compact", "depth": len(chain), "hops_root": hops_root(chain), "leaf": chain[-1]}


def compact_chain_shape_error(c: Any) -> Optional[str]:
    if not isinstance(c, dict):
        return "not an object"
    e = _closed_members(c, ["v", "kind", "depth", "hops_root", "leaf"], [], "compact chain")
    if e:
        return e
    if c.get("v") != 1 or isinstance(c.get("v"), bool) or c.get("kind") != "pca-chain-compact":
        return "not a pca-chain-compact v1"
    d = c.get("depth")
    if not (_is_safe_int(d) and 1 <= d <= MAX_CHAIN_DEPTH):
        return "depth must be 1..%d" % MAX_CHAIN_DEPTH
    if not isinstance(c.get("hops_root"), str) or len(c["hops_root"]) != 43:
        return "hops_root must be a 43 character digest"
    if not isinstance(c.get("leaf"), dict):
        return "leaf must be a capability"
    return None


class ChainMemo:
    """The verifier's memo of chains it has fully verified. ``max_entries`` / ``ttl_ms`` bound it."""

    def __init__(self, max_entries: Optional[int] = None, ttl_ms: Optional[int] = None):
        self._entries: Dict[str, dict] = {}
        self._max = CHAIN_MEMO_DEFAULT_MAX_ENTRIES if max_entries is None else max_entries
        self._ttl = CHAIN_MEMO_MAX_TTL_MS if ttl_ms is None else ttl_ms

    @property
    def size(self) -> int:
        return len(self._entries)

    def remember_verified(self, chain: List[dict], expected_root_issuer: str, now: int, **policy: Any) -> Dict[str, Any]:
        """Verify `chain` (rooted at `expected_root_issuer`) with the full verifier (`policy` = its keywords: allowed_suites, pq_pins,
        trusted_root) and remember it. Raises when the chain does not verify or the memo is full of live entries (fail closed: a full
        memo never evicts a live entry, so one tenant cannot push another out). Returns the compact form a holder presents."""
        if not _is_safe_int(now):
            raise ValueError("rememberVerified: the clock is not a safe integer")
        ok, reason = verify_chain(chain, expected_root_issuer, **policy)
        if not ok:
            raise ValueError("rememberVerified: the chain does not verify: %s" % (reason or "invalid"))
        compact = compact_chain(chain)
        ttl = min(self._ttl, CHAIN_MEMO_MAX_TTL_MS)
        self.prune(now)
        if compact["hops_root"] not in self._entries and not (len(self._entries) < self._max):
            raise ValueError("rememberVerified: the memo is full of live entries")
        self._entries[compact["hops_root"]] = {
            "depth": len(chain), "hops_root": compact["hops_root"], "hashes": [cap_hash(h) for h in chain],
            "counts": [len(h["caveats"]) for h in chain], "expires_at": now + ttl}
        return compact

    def prune(self, now: int) -> None:
        """Drop entries whose time is up."""
        for k in [k for k, e in self._entries.items() if not (fin(now) and e["expires_at"] >= now)]:
            del self._entries[k]

    def forget(self, hops_root_value: str) -> bool:
        """Forget a chain (e.g. when it is revoked)."""
        return self._entries.pop(hops_root_value, None) is not None

    def resolve(self, compact: Any, now: int) -> Dict[str, Any]:
        """Resolve a presented compact chain against the memo: ``{"ok": True, "view": ChainView}`` or ``{"ok": False, "reason"}``. Total."""
        try:
            if not _is_safe_int(now):
                return {"ok": False, "reason": "the verifier clock is not a safe integer (fail closed)"}
            e = compact_chain_shape_error(compact)
            if e:
                return {"ok": False, "reason": "malformed compact chain: %s" % e}
            m = self._entries.get(compact["hops_root"])
            if m is None:
                return {"ok": False, "reason": "the chain is not in this verifier memo (present the full chain)"}
            if m["expires_at"] < now:
                del self._entries[compact["hops_root"]]
                return {"ok": False, "reason": "the memoized chain has expired (present the full chain)"}
            if m["depth"] != compact["depth"]:
                return {"ok": False, "reason": "the depth differs from the memoized chain"}
            leaf = compact["leaf"]
            if cap_hash(leaf) != m["hashes"][m["depth"] - 1]:
                return {"ok": False, "reason": "the leaf is not the memoized last hop"}
            if not isinstance(leaf.get("caveats"), list) or len(leaf["caveats"]) != m["counts"][m["depth"] - 1]:
                return {"ok": False, "reason": "the leaf caveats differ from the memoized chain"}
            return {"ok": True, "view": ChainView(m["depth"], leaf, lambda i: m["hashes"][i], lambda i: m["counts"][i])}
        except Exception as err:  # noqa: BLE001 - total
            return {"ok": False, "reason": "compact chain error (fail closed): %s" % (str(err) or "unknown")}


def view_of_chain(grant: dict, chain: List[dict]) -> ChainView:
    """The view of a full chain, for symmetry with :meth:`ChainMemo.resolve` (both feed the caveat language)."""
    return chain_view(grant, chain)
