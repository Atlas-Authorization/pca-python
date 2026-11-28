"""The issuing side of the transparency primitives the verifiers already check (the TypeScript ``revocation`` ``RevocationSet`` and
``ledger`` ``TransparencyLedger`` proofs): a sorted revocation set with its size-bound Merkle root and membership / non-membership proofs,
and RFC 9162 inclusion and consistency proof generation over a list of commitments. The verifiers are ``verify_non_membership``
(:mod:`atlas_pca.intent_v2`), ``verify_ledger_inclusion`` and ``verify_ledger_consistency`` (:mod:`atlas_pca.ledger`)."""
import functools
from typing import Any, Dict, List, Optional

from .grants import merkle_proof
from .intent_v2 import _EMPTY_TREE, _bind_root, compare_utf8
from .pca import _build, _leaf_hash, b64u, merkle_root
from .store_errors import RangeError

__all__ = ["RevocationSet", "consistency_proof", "inclusion_proof", "ledger_root_of", "TransparencyLedger"]

_ORDER = functools.cmp_to_key(compare_utf8)


class RevocationSet:
    """A sorted set of revoked ids (UTF-8 byte order). ``root`` is bound to the size, so a prefix of the set never has the full root."""

    def __init__(self, initial: Any = ()) -> None:
        self._ids: List[str] = []
        for i in initial:
            self.revoke(i)

    @property
    def size(self) -> int:
        return len(self._ids)

    def _lower_bound(self, rid: str) -> int:
        lo, hi = 0, len(self._ids)
        while lo < hi:
            mid = (lo + hi) >> 1
            if compare_utf8(self._ids[mid], rid) < 0:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def revoke(self, rid: Any) -> bool:
        """Idempotent. True when newly revoked."""
        if not isinstance(rid, str):
            raise TypeError("revoke: id must be a string")
        lo = self._lower_bound(rid)
        if lo < len(self._ids) and self._ids[lo] == rid:
            return False
        self._ids.insert(lo, rid)
        return True

    def has(self, rid: str) -> bool:
        lo = self._lower_bound(rid)
        return lo < len(self._ids) and self._ids[lo] == rid

    def list(self) -> List[str]:
        """Sorted revoked ids (a copy)."""
        return list(self._ids)

    @property
    def root(self) -> str:
        return _bind_root(len(self._ids), merkle_root(self._ids) if self._ids else _EMPTY_TREE)

    def membership_proof(self, rid: str) -> Dict[str, Any]:
        lo = self._lower_bound(rid)
        if not (lo < len(self._ids) and self._ids[lo] == rid):
            raise ValueError("membershipProof: id is not revoked")
        return merkle_proof(self._ids, lo)

    def non_membership_proof(self, rid: str) -> Dict[str, Any]:
        """Raises when the id IS revoked (no such proof can exist)."""
        if self.has(rid):
            raise ValueError("nonMembershipProof: id is revoked")
        n = len(self._ids)
        lo = self._lower_bound(rid)
        p: Dict[str, Any] = {"size": n}
        if lo > 0:
            p["lo"] = {"id": self._ids[lo - 1], "proof": merkle_proof(self._ids, lo - 1)}
        if lo < n:
            p["hi"] = {"id": self._ids[lo], "proof": merkle_proof(self._ids, lo)}
        return p


def ledger_root_of(commits: List[str]) -> str:
    """Root of a commit sequence (the empty log is SHA-256 of the empty string)."""
    from .pca import sha256
    return b64u(_build([_leaf_hash(c) for c in commits])) if commits else b64u(sha256(b""))


def inclusion_proof(commits: List[str], index: int) -> Dict[str, Any]:
    """RFC 9162 audit path of commit `index`."""
    return merkle_proof(commits, index)


def consistency_proof(commits: List[str], old_size: int, new_size: Optional[int] = None) -> Dict[str, Any]:
    """RFC 6962 SUBPROOF(m, D[n], true): the consistency proof between the first `old_size` and the first `new_size` commits."""
    n_all = len(commits)
    new_size = n_all if new_size is None else new_size
    ok = lambda x: isinstance(x, int) and not isinstance(x, bool)  # noqa: E731
    if not ok(old_size) or not ok(new_size) or old_size < 0 or old_size > new_size or new_size > n_all:
        raise RangeError("consistencyProof: invalid sizes")
    out: List[bytes] = []

    def sub(m: int, hs: List[bytes], b: bool) -> None:
        n = len(hs)
        if m == n:
            if not b:
                out.append(_build(hs))
            return
        k = 1
        while k * 2 < n:
            k *= 2
        if m <= k:
            sub(m, hs[:k], b)
            out.append(_build(hs[k:]))
        else:
            sub(m - k, hs[k:], False)
            out.append(_build(hs[:k]))

    if 0 < old_size < new_size:
        sub(old_size, [_leaf_hash(c) for c in commits[:new_size]], True)
    return {"oldSize": old_size, "newSize": new_size, "path": [b64u(h) for h in out]}


class TransparencyLedger:
    """An in-memory RFC 9162 transparency log over opaque commits (the verifier-side checks are in :mod:`atlas_pca.ledger`). Build it from
    entries with :meth:`from_entries` and extend it with :meth:`append_commitment`; ``head`` is ``{"size", "root"}``."""

    def __init__(self, principal: str = "") -> None:
        self.principal = principal
        self._commits: List[str] = []
        self._hashes: List[bytes] = []
        self._openings: Dict[int, dict] = {}

    @classmethod
    def from_entries(cls, entries: List[dict], principal: str = "") -> "TransparencyLedger":
        t = cls(principal)
        for e in entries:
            if e.get("opening"):
                t._openings[len(t._commits)] = e["opening"]
            t._commits.append(e["commit"])
            t._hashes.append(_leaf_hash(e["commit"]))
        return t

    def append(self, pcactn: Any, salt: Optional[str] = None) -> dict:
        """Append a PCActn as a salted commitment (pass `salt` for deterministic output)."""
        import os
        from .ledger import entry_commit
        salt = salt if salt is not None else b64u(os.urandom(16))
        commit = entry_commit(salt, pcactn)
        index = len(self._commits)
        self._openings[index] = {"salt": salt, "pcactn": pcactn}
        self._commits.append(commit)
        self._hashes.append(_leaf_hash(commit))
        return {"index": index, "commit": commit}

    def entry(self, index: Any) -> dict:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self._commits):
            raise RangeError("entry: index out of range")
        e = {"commit": self._commits[index]}
        if index in self._openings:
            e["opening"] = self._openings[index]
        return e

    def audit_openings(self) -> List[int]:
        """Indices whose stored opening no longer matches its commit (storage tamper detection)."""
        from .ledger import verify_opening
        return [i for i, o in sorted(self._openings.items()) if not verify_opening(self._commits[i], o)]

    def shred(self, index: Any) -> bool:
        """Crypto-shred: destroy the opening, keep the commit (root and proofs are unchanged). True if one was removed."""
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self._commits):
            raise RangeError("shred: index out of range")
        return self._openings.pop(index, None) is not None

    def witness_head(self, witness: Any, alg: Optional[str] = None, pq: Any = None) -> dict:
        """Sign the current head for third-party witnessing / anti-equivocation. Suite-agile."""
        from .ledger import witness_head
        h = self.head()
        return witness_head(self.principal, h["size"], h["root"], witness, alg, pq)

    @property
    def size(self) -> int:
        return len(self._commits)

    def append_commitment(self, commit: Any) -> dict:
        """Append a precomputed opaque commitment leaf; refuses a non-string or empty commit."""
        if not isinstance(commit, str) or len(commit) == 0:
            raise ValueError("appendCommitment: commit must be a non-empty string")
        self._commits.append(commit)
        self._hashes.append(_leaf_hash(commit))
        return {"index": len(self._commits) - 1, "commit": commit}

    def head(self) -> dict:
        return {"size": self.size, "root": ledger_root_of(self._commits)}

    def root_at(self, size: Any) -> str:
        """The root the log had when it contained only the first `size` entries."""
        if isinstance(size, bool) or not isinstance(size, (int, float)) or size != size or int(size) != size or size < 0 or size > self.size:
            raise RangeError("rootAt: size out of range")
        return ledger_root_of(self._commits[:int(size)])

    def commits(self) -> List[str]:
        return list(self._commits)

    def inclusion_proof(self, index: Any) -> Dict[str, Any]:
        try:
            return merkle_proof(self._commits, index)
        except ValueError as e:
            raise RangeError(str(e)) from None

    def consistency_proof(self, old_size: Any, new_size: Optional[int] = None) -> Dict[str, Any]:
        return consistency_proof(self._commits, old_size, self.size if new_size is None else new_size)
