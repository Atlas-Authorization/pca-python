"""The FROST signer's nonce store contract: the round-1 nonces a signer has issued and not yet spent, kept so that a restart can neither lose a live session
nor sign a spent one twice. ``create`` refuses an existing live or spent id, ``load`` returns a COPY, ``spend`` is one-way (the secret is wiped, the id is
remembered and ``create`` refuses it forever), ``drop`` removes a live record without marking it spent, ``isSpent`` is true only for a spent id. A record is a
dict {hiding, binding, hidingCommitment, bindingCommitment (32 bytes each), createdAt}. :func:`assert_nonce_store_contract` is the self-test a custom
(durable) store must pass. A port of the reference ``frost-nonce-store`` module."""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

__all__ = ["MemoryNonceStore", "assert_nonce_store_contract"]


def _copy(r: Dict[str, Any]) -> Dict[str, Any]:
    return {"hiding": bytes(r["hiding"]), "binding": bytes(r["binding"]), "hidingCommitment": bytes(r["hidingCommitment"]),
            "bindingCommitment": bytes(r["bindingCommitment"]), "createdAt": r["createdAt"]}


class MemoryNonceStore:
    """An in-process nonce store (tests, single-process signers): it forgets everything at exit, so a signer that must survive a restart needs a durable one."""

    def __init__(self) -> None:
        self._live: Dict[str, Dict[str, Any]] = {}
        self._spent: set = set()

    def create(self, session_id: Any, record: Dict[str, Any]) -> None:
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("nonce-store: session id must be a non-empty string")
        if session_id in self._live or session_id in self._spent:
            raise ValueError("nonce-store: session already exists")
        self._live[session_id] = _copy(record)

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        r = self._live.get(session_id)
        return _copy(r) if r else None

    def spend(self, session_id: str) -> None:
        if session_id not in self._live:
            raise ValueError("nonce-store: cannot spend a session that is not live")
        del self._live[session_id]
        self._spent.add(session_id)

    def drop(self, session_id: str) -> None:
        self._live.pop(session_id, None)

    def is_spent(self, session_id: str) -> bool:
        return session_id in self._spent


def assert_nonce_store_contract(make: Callable[[], Any], reopen: Callable[[Any], Any] = lambda s: s) -> None:
    """Exercise a store: ``make()`` builds one, ``reopen(store)`` simulates a restart (return the store a restarted process would see). Raises ValueError
    "nonce-store contract: ..." naming the first violated property."""
    def rec(n: int) -> Dict[str, Any]:
        return {"hiding": bytes([n]) * 32, "binding": bytes([n + 1]) * 32, "hidingCommitment": bytes([n + 2]) * 32, "bindingCommitment": bytes([n + 3]) * 32,
                "createdAt": n}

    def must(ok: bool, what: str) -> None:
        if not ok:
            raise ValueError("nonce-store contract: %s" % what)

    def throws(f: Callable[[], None]) -> bool:
        try:
            f()
        except Exception:  # noqa: BLE001
            return True
        return False

    s = make()
    must(s.load("a") is None and not s.is_spent("a"), "an unknown id is neither live nor spent")
    s.create("a", rec(1))
    must(throws(lambda: s.create("a", rec(9))), "create must refuse an existing live id")
    s.create("b", rec(5))
    s = reopen(s)
    got = s.load("a")
    must(got is not None and got["hiding"][0] == 1 and got["createdAt"] == 1, "a live record survives a restart")
    got["hiding"] = bytes([0xEE]) * 32  # a returned record is the caller's: replacing it must not reach the store
    must(s.load("a")["hiding"][0] == 1, "load returns a copy")
    s.spend("a")
    must(s.load("a") is None and s.is_spent("a"), "spend removes the secret and records the marker")
    must(throws(lambda: s.spend("a")), "a second spend must throw")
    must(throws(lambda: s.create("a", rec(2))), "create must refuse a spent id")
    must(throws(lambda: s.spend("zzz")), "spend of an unknown id must throw")
    s = reopen(s)
    must(s.is_spent("a") and s.load("a") is None, "a spent marker survives a restart")
    must(s.load("b") is not None, "the other live record survives")
    s.drop("b")
    must(s.load("b") is None and not s.is_spent("b"), "drop removes a live record without marking it spent")
    s.drop("never-existed")
