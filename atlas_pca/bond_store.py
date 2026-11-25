"""Durable bond settlement, the store half (the TypeScript ``bond-store``): the ``BondStore`` contract (``read(scope)``,
``commit(plan, observed_at)``, ``deposit(account, amount)``), the exact micro-unit arithmetic every store shares, the pure transition
function and :class:`KvBondStore`, one document in any atomic key-value store (``get`` and ``update``). INTERNAL ACCOUNTING ONLY: nothing
here moves money.

A plan is ``{claimId, expect, next, open?: {amount, depositor, maxOpenClaims, maxOpenAmount, window?}, moves: [{account, op, amount}],
record}``. ``commit`` applies it ALL OR NOTHING: the compare-and-swap on the bond's phase, every balance movement, the new phase and the signed
record become visible together; committing the same transition twice is a replay (the stored record, nothing moved). Records are dicts
with the reference's member names."""
import copy
import math
from ._fin import fin
from typing import Any, Callable, Dict, List, Optional, Sequence

from .pca import hash_canonical
from .store_errors import BondStoreError, RangeError

__all__ = ["BondStoreError", "to_micros", "from_micros", "exact_add", "apply_bond_moves", "same_settlement", "commit_bond_plan", "snapshot_of",
           "KvBondStore", "is_bond_store", "empty_bond_doc"]

_MICROS = 1_000_000
_MAX_SAFE_MICROS = 1e15
DOC_KEY = "pca-bond-store/v1"
_PHASES = ("open", "released", "slashed")


def _fin(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)


def _round(x: float) -> int:
    return int(math.floor(x + 0.5))  # JavaScript Math.round


def to_micros(x: Any) -> Optional[int]:
    """Integer micro-units of `x` when it is a micro-grid amount below 1e15 micros, else None."""
    if not _fin(x) or x < 0:
        return None
    scaled = x * _MICROS
    if scaled > _MAX_SAFE_MICROS:
        return None
    r = _round(scaled)
    if r / _MICROS != x and abs(scaled - r) > 1e-3:  # genuinely sub-micro: not a micro-grid amount
        return None
    return r


def from_micros(m: int) -> float:
    return m / _MICROS


def exact_add(a: Any, b: Any, sign: int) -> float:
    """a + sign*b in exact micro-unit integers when both are micro-grid amounts; plain float otherwise."""
    ma, mb = to_micros(a), to_micros(b)
    if ma is None or mb is None:
        return a + sign * b
    return from_micros(ma + mb if sign == 1 else ma - mb)


def apply_bond_moves(balance_of: Callable[[str], float], moves: Sequence[dict]) -> Dict[str, float]:
    """Apply moves in order over a balance reader; RAISES (applying nothing) on an invalid amount or an overdraft."""
    out: Dict[str, float] = {}

    def bal(a: str) -> float:
        return out[a] if a in out else balance_of(a)
    for m in moves:
        if not _fin(m.get("amount")) or m["amount"] < 0:
            raise ValueError("%s: invalid amount" % m.get("op"))
        if not _fin(bal(m["account"])):
            raise ValueError("%s: balance of %s is not finite" % (m.get("op"), m["account"]))
        if m.get("op") == "debit" and not (bal(m["account"]) >= m["amount"]):
            raise ValueError("debit: insufficient balance for %s" % m["account"])
        out[m["account"]] = exact_add(bal(m["account"]), m["amount"], -1 if m.get("op") == "debit" else 1)
    return out


def same_settlement(a: dict, b: dict) -> bool:
    """Same settlement: action, bond, amount, parties, evidence and split (time and signature bytes ignored)."""
    return (a.get("claimId") == b.get("claimId") and a.get("action") == b.get("action") and a.get("amount") == b.get("amount")
            and a.get("from") == b.get("from") and a.get("to") == b.get("to") and a.get("evidenceDigest") == b.get("evidenceDigest")
            and hash_canonical(a.get("split")) == hash_canonical(b.get("split")))


def _same_window(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is b
    return a.get("windowMs") == b.get("windowMs") and a.get("claimDigest") == b.get("claimDigest")  # registeredAt is the first call's


def empty_bond_doc() -> dict:
    return {"balances": {}, "bonds": {}, "highWater": 0}


def commit_bond_plan(doc: dict, plan: dict, observed_at: Any) -> dict:
    """Apply `plan` to `doc` (``balances``: account -> number, ``bonds``: claim id -> row, ``highWater``) following the BondStore.commit
    rules. Mutates `doc` ONLY on ``committed`` (the moves are checked on an overlay first)."""
    claim_id = plan["claimId"]
    bond = doc["bonds"].get(claim_id)
    cur = bond["status"] if bond else "none"
    o = plan.get("open")
    if plan.get("expect") == "none":
        if not o or plan.get("next") != "open":
            return {"outcome": "conflict", "reason": "malformed open plan", "current": cur}
        if bond:
            same = (bond["depositor"] == o["depositor"] and bond["amount"] == o["amount"] and _same_window(bond.get("window"), o.get("window"))
                    and len(bond["records"]) > 0 and same_settlement(bond["records"][0], plan["record"]))
            return {"outcome": "replayed", "record": bond["records"][0]} if same else \
                {"outcome": "conflict", "reason": "bond %s already exists" % claim_id, "current": bond["status"]}
        count, total = 0, 0
        for b in doc["bonds"].values():
            if b["status"] == "open" and b["depositor"] == o["depositor"]:
                count += 1
                total += b["amount"]
        if not (_fin(count) and count + 1 <= o["maxOpenClaims"]):
            return {"outcome": "conflict", "reason": "depositor open-claim cap reached", "current": "none"}
        if not (_fin(total + o["amount"]) and total + o["amount"] <= o["maxOpenAmount"]):
            return {"outcome": "conflict", "reason": "depositor aggregate open-bond cap exceeded", "current": "none"}
    elif not bond:
        return {"outcome": "conflict", "reason": "no bond for %s" % claim_id, "current": "none"}
    elif bond["status"] != plan.get("expect"):
        last = bond["records"][-1] if bond["records"] else None
        if bond["status"] == plan.get("next") and last is not None and same_settlement(last, plan["record"]):
            return {"outcome": "replayed", "record": last}
        return {"outcome": "conflict", "reason": "bond %s is already %s" % (claim_id, bond["status"]), "current": bond["status"]}
    try:
        nxt = apply_bond_moves(lambda a: doc["balances"].get(a, 0), plan["moves"])
    except ValueError as e:
        return {"outcome": "conflict", "reason": str(e), "current": cur}
    doc["balances"].update(nxt)
    if o:
        row = {"claimId": claim_id, "amount": o["amount"], "depositor": o["depositor"], "status": "open"}
        if o.get("window"):
            row["window"] = o["window"]
        row["records"] = [plan["record"]]
        doc["bonds"][claim_id] = row
    else:
        bond["status"] = plan["next"]
        bond["records"].append(plan["record"])
    doc["highWater"] = max(doc["highWater"], observed_at if _fin(observed_at) else 0)
    return {"outcome": "committed", "record": plan["record"]}


def snapshot_of(doc: dict, claim_id: str, depositor: Optional[str] = None) -> dict:
    """What a planner may read: the bond, the depositor's balance and open totals, and the store's time high-water mark."""
    bond = doc["bonds"].get(claim_id)
    count, total, balances = 0, 0, []
    if depositor is not None:
        for b in doc["bonds"].values():
            if b["status"] == "open" and b["depositor"] == depositor:
                count += 1
                total += b["amount"]
        balances.append([depositor, doc["balances"].get(depositor, 0)])
    out: Dict[str, Any] = {}
    if bond:
        out["bond"] = copy.deepcopy(bond)
    out.update({"balances": balances, "openTotals": {"count": count, "sum": total}, "highWater": doc["highWater"]})
    return out


def _bad(why: str) -> BondStoreError:
    return BondStoreError("store_corrupt", why)


def _decode_doc(raw: Any) -> dict:
    if raw is None:
        return empty_bond_doc()
    if not isinstance(raw, dict) or raw.get("v") != 1 or isinstance(raw.get("v"), bool) or not isinstance(raw.get("balances"), list) \
            or not isinstance(raw.get("bonds"), list) or isinstance(raw.get("highWater"), bool) or not isinstance(raw.get("highWater"), (int, float)):
        raise _bad("bond document has the wrong shape")
    doc = empty_bond_doc()
    if not _fin(raw["highWater"]) or raw["highWater"] < 0:
        raise _bad("highWater is not a non-negative number")
    doc["highWater"] = raw["highWater"]
    for e in raw["balances"]:
        if not isinstance(e, list) or len(e) != 2 or not isinstance(e[0], str) or not _fin(e[1]) or e[1] < 0:
            raise _bad("malformed balance entry")
        doc["balances"][e[0]] = e[1]
    for b in raw["bonds"]:
        if not isinstance(b, dict) or not isinstance(b.get("claimId"), str) or not isinstance(b.get("depositor"), str) or not _fin(b.get("amount")) \
                or b.get("status") not in _PHASES or not isinstance(b.get("records"), list) or len(b["records"]) == 0:
            raise _bad("malformed bond row")
        if b["claimId"] in doc["bonds"]:
            raise _bad("duplicate bond row")
        doc["bonds"][b["claimId"]] = copy.deepcopy(b)
    return doc


def _encode_doc(d: dict) -> dict:
    return {"v": 1, "balances": [[a, v] for a, v in d["balances"].items()], "bonds": list(d["bonds"].values()), "highWater": d["highWater"]}


def is_bond_store(s: Any) -> bool:
    return s is not None and all(callable(getattr(s, m, None)) for m in ("read", "commit", "deposit"))


class KvBondStore:
    """The reference bond store: the whole book is one document in an atomic key-value store, so every transition is a single atomic
    read-modify-write (:class:`atlas_pca.SqliteAtomicKv` is crash-safe; :class:`atlas_pca.MemoryAtomicKv` is for tests).
    LIMIT: one document, rewritten on every commit; a production deployment implements the store over a database transaction."""

    def __init__(self, kv: Any, key: str = DOC_KEY) -> None:
        if kv is None or not callable(getattr(kv, "get", None)) or not callable(getattr(kv, "update", None)):
            raise BondStoreError("store_missing", "KvBondStore needs an atomic kv")
        self._kv, self._key = kv, key

    def read(self, claim_id: str, depositor: Optional[str] = None) -> dict:
        return snapshot_of(_decode_doc(self._kv.get(self._key)), claim_id, depositor)

    def commit(self, plan: dict, observed_at: Any) -> dict:
        out: List[dict] = []

        def fn(prev: Any) -> Any:
            doc = _decode_doc(prev)
            res = commit_bond_plan(doc, plan, observed_at)
            out.append(res)
            return _encode_doc(doc) if res["outcome"] == "committed" else None  # None: leave the key untouched
        self._kv.update(self._key, fn)
        return out[0]

    def deposit(self, account: str, amount: float) -> float:
        """Atomically credit `account` with `amount` (a positive finite number). Returns the new balance."""
        if not isinstance(account, str) or len(account) == 0:
            raise RangeError("deposit: account is required")
        if not _fin(amount) or amount <= 0:
            raise RangeError("deposit: amount must be a positive finite number")
        res: List[float] = []

        def fn(prev: Any) -> Any:
            doc = _decode_doc(prev)
            bal = apply_bond_moves(lambda a: doc["balances"].get(a, 0), [{"account": account, "op": "credit", "amount": amount}])[account]
            doc["balances"][account] = bal
            res.append(bal)
            return _encode_doc(doc)
        self._kv.update(self._key, fn)
        return res[0]
