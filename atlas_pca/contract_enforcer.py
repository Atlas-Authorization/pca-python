"""Durable enforcement of a signed behavioural contract (port of packages/pca/src/contract-enforcer.ts).

The monitor state is one document in an atomic key/value store (``get(key)`` and ``update(key, fn)``, see
:class:`atlas_pca.atomic_kv.MemoryAtomicKv`); the whole read-check-advance runs inside ``update``. Only a contract signed by the
PINNED principal is loaded, the state document is bound to the contract id, every corrupt or unreadable state or store error DENIES, and
a real violation LATCHES the enforcer until the principal signs a reset."""
import time
from typing import Any, Callable, Dict, List, Optional

from . import ed25519
from .contracts import check_and_advance_contract, check_contract, contract_id, verify_contract
from .pca import _verify_b64u, b64u, sha256
from .prohibitions import _fin, _is_integer, _is_version, _neg_zero, empty_state, state_problem

CONTRACT_RESET_DOMAIN = "atlas-pca/contract-reset/v1\0"
_DOC_VERSION = 1
_CORRUPT = "<state>: stored state is corrupt or belongs to another contract"


class ContractEnforcerError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__("ContractEnforcer: %s" % message)


def _msg(id_: str, seq: int) -> bytes:
    return CONTRACT_RESET_DOMAIN.encode("utf-8") + sha256(("%s:%d" % (id_, seq)).encode("utf-8"))


def sign_contract_reset(principal_seed: bytes, contract_id_value: str, seq: int) -> str:
    """The principal's authorisation to un-latch a contract at sequence ``seq`` (binds both, so it cannot be replayed later)."""
    return b64u(ed25519.sign_secret(principal_seed, _msg(contract_id_value, seq)))


def _is_doc(d: Any, id_: str) -> bool:
    if not isinstance(d, dict):
        return False
    if not _is_version(d.get("v"), _DOC_VERSION) or d.get("contract_id") != id_ or state_problem(d.get("state")) is not None:
        return False
    if "latched" not in d:
        return True
    l = d["latched"]
    return (isinstance(l, dict) and _is_integer(l.get("seq")) and not _neg_zero(l["seq"]) and isinstance(l.get("violated"), list)
            and all(isinstance(v, str) for v in l["violated"]))


def _result(allow: bool, reason: str, violated: List[str], reasons: List[str], seq: int) -> Dict[str, Any]:
    return {"allow": allow, "reason": reason, "violated": violated, "reasons": reasons, "seq": seq}


class ContractEnforcer:
    def __init__(self, kv: Any, contract: Dict[str, Any], key: str, now: Callable[[], float], latch: bool) -> None:
        self._kv, self._contract, self._key, self._now, self._latch = kv, contract, key, now, latch

    @staticmethod
    def open(kv: Any, contract: Any, principal: Any, key: Optional[str] = None, now: Optional[Callable[[], float]] = None,
             latch_on_violation: bool = True) -> "ContractEnforcer":
        """Raises ``ContractEnforcerError`` unless the contract verifies under the pinned principal."""
        if not isinstance(principal, str) or len(principal) == 0:
            raise ContractEnforcerError("a pinned principal is required")
        v = verify_contract(contract, principal)
        if not v["ok"]:
            raise ContractEnforcerError("contract refused: %s" % v["reason"])
        return ContractEnforcer(kv, contract, key if key is not None else "contract/%s" % contract_id(contract),
                                now if now is not None else (lambda: int(time.time() * 1000)), latch_on_violation is not False)

    def check(self, action: Any, permitted: Any = True) -> Dict[str, Any]:
        """Check one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never raises."""
        id_ = self._contract["id"]
        out = [_result(False, "store-error", [], ["store unavailable"], 0)]
        try:
            wall = self._now()

            def fn(prev: Any) -> Any:
                if prev is not None and not _is_doc(prev, id_):
                    out[0] = _result(False, "state-error", [], [_CORRUPT], 0)
                    return None
                if prev is not None and not _fin(wall):
                    out[0] = _result(False, "state-error", [], ["<state>: clock is not finite"], prev["state"]["seq"])
                    return None
                doc = prev if prev is not None else {"v": _DOC_VERSION, "contract_id": id_, "state": empty_state(wall if _fin(wall) else 0)}
                if "latched" in doc:
                    out[0] = _result(False, "latched", doc["latched"]["violated"], ["<latched>: contract violated at seq %d" % doc["latched"]["seq"]], doc["state"]["seq"])
                    return None
                r = check_and_advance_contract(permitted, doc["state"], action, self._contract, {"now": max(wall, doc["state"]["now"]), "expectedSeq": doc["state"]["seq"]})
                if r["allow"]:
                    out[0] = _result(True, "ok", [], [], r["next"]["seq"])
                    return {**doc, "state": r["next"]}
                structural = r["decidedBy"] == "state"
                real = not structural and len(r["violated"]) > 0
                out[0] = _result(False, "state-error" if structural else ("violated" if real else "permission"), r["violated"] if real else [], r["reasons"], doc["state"]["seq"])
                return {**doc, "latched": {"seq": doc["state"]["seq"], "violated": r["violated"]}} if real and self._latch else None

            self._kv.update(self._key, fn)
        except Exception:  # noqa: BLE001
            out[0] = _result(False, "store-error", [], ["store error (fail closed)"], 0)
        return out[0]

    def peek(self, action: Any) -> Dict[str, Any]:
        """Read-only evaluation against the stored state: nothing is advanced or latched. Never raises."""
        try:
            prev = self._kv.get(self._key)
            if prev is not None and not _is_doc(prev, self._contract["id"]):
                return _result(False, "state-error", [], [_CORRUPT], 0)
            if prev is not None and "latched" in prev:
                return _result(False, "latched", prev["latched"]["violated"], ["<latched>: contract violated at seq %d" % prev["latched"]["seq"]], prev["state"]["seq"])
            wall = self._now()
            r = check_contract(action, self._contract, prev["state"] if prev is not None else empty_state(wall if _fin(wall) else 0))
            seq = prev["state"]["seq"] if prev is not None else 0
            if r["ok"]:
                return _result(True, "ok", [], [], seq)
            return _result(False, "violated", r["violated"], r["reasons"], seq)
        except Exception:  # noqa: BLE001
            return _result(False, "store-error", [], ["store error (fail closed)"], 0)

    def state(self) -> Optional[Dict[str, Any]]:
        """The stored state and whether it is latched, or None when nothing was admitted yet. Raises ContractEnforcerError on a corrupt document."""
        d = self._kv.get(self._key)
        if d is None:
            return None
        if not _is_doc(d, self._contract["id"]):
            raise ContractEnforcerError("stored state is corrupt or belongs to another contract")
        return {"state": d["state"], "latched": "latched" in d}

    def reset(self, sig: Any) -> bool:
        """Un-latch with the principal's signature (see ``sign_contract_reset``) at the latched sequence. Returns whether it cleared."""
        cleared = [False]

        def fn(prev: Any) -> Any:
            if not _is_doc(prev, self._contract["id"]) or "latched" not in prev:
                return None
            if not isinstance(sig, str) or not _verify_b64u(self._contract["principal"], _msg(self._contract["id"], prev["latched"]["seq"]), sig):
                return None
            cleared[0] = True
            return {k: v for k, v in prev.items() if k != "latched"}

        try:
            self._kv.update(self._key, fn)
        except Exception:  # noqa: BLE001
            return False
        return cleared[0]
