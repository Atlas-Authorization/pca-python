"""Durable bond settlement (the TypeScript ``bond-settlement`` planner and ``StoreBondLedger``): exact micro-unit money arithmetic, the slash
split, bond sizing, the evidence digests a signed settlement record commits to, :class:`BondSettlementPlanner` (the pure half: validates a
transition against a read view, re-derives every slash verdict ITSELF, computes the balance movements and signs the record) and
:class:`StoreBondLedger` (commits the plans to a bond store atomically, fails closed, and stamps every time from a clock the claimant cannot
touch). INTERNAL ACCOUNTING ONLY: nothing here moves money.

THE CHALLENGE-WINDOW CLOCK: the window opens at the ledger's own ``registeredAt`` (its clock at ``open_claim``), lasts the claim's
``challenge_window_ms`` and is never derived from the claim's ``issued_at``. The ledger's "now" is ``max(clock(), highest time the store has
ever recorded)``, so a clock that steps backwards cannot reopen a closed window or release early. Records are dicts with the reference's
member names; the keys are :class:`atlas_pca.agent.KeyPair`."""
import math
from ._fin import fin
import time
from typing import Any, Callable, Dict, List, Optional

from .agent import KeyPair, _bind_suite, sign_with_suite
from .bond_store import exact_add, from_micros, is_bond_store, same_settlement, to_micros
from .optimistic import DEFAULT_WINDOW_POLICY, _validate_window, claim_check
from .optimistic_adjudication import adjudicate_dispute, verify_fraud_proof
from .pca import b64u, canonical_bytes, hash_canonical, sha256
from .store_errors import BondStoreError

__all__ = ["ESCROW_ACCOUNT", "COMPENSATION_POOL_ACCOUNT", "DEFAULT_MIN_CHALLENGE_WINDOW_MS", "default_bond_policy", "default_slash_split_policy",
           "quantize_up", "compute_slash_split", "bond_amount", "settlement_evidence_digest", "revocation_evidence_digest", "dispute_evidence_digest",
           "BondSettlementPlanner", "StoreBondLedger", "verify_settlement", "settlement_record_digest", "settlement_commit",
           "InsuranceCapitalPool"]

ESCROW_ACCOUNT = "escrow"
COMPENSATION_POOL_ACCOUNT = "pca:pool:compensation"
SETTLEMENT_DOMAIN = "atlas-pca/bond-settlement/v1\x00"
SETTLEMENT_LEAF_DOMAIN = "atlas-pca/settlement-leaf/v1"
DEFAULT_MIN_CHALLENGE_WINDOW_MS = 30_000
_MAX_SAFE_MICROS = 1e15
_MIN_SHARE_QUANTUM = 2.0 ** -30


def _fin(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)


def _lenient(v: Any) -> str:
    return b64u(sha256(canonical_bytes(v)))


def default_slash_split_policy() -> dict:
    """The conservative reference split: challenger 50%, victim pool 40%, treasury the remainder."""
    return {"challengerBps": 5000, "victimBps": 4000}


def default_bond_policy() -> dict:
    return {"floor": 1, "k": 1, "maxOpenClaims": 100, "maxOpenAmount": float("inf")}


def quantize_up(x: float) -> float:
    """Snap a computed amount UP onto the micro grid (a bond is never rounded down); float noise below 1e-3 micro-units is absorbed."""
    if not _fin(x) or x <= 0:
        return x
    scaled = x * 1_000_000
    if scaled > _MAX_SAFE_MICROS:
        return x
    r = math.floor(scaled + 0.5)
    m = r if r / 1_000_000 == x or abs(scaled - r) <= 1e-3 else math.ceil(scaled)
    return m / 1_000_000


def _assert_split_policy(p: Any) -> None:
    total = 0
    for k in ("challengerBps", "victimBps"):
        v = p.get(k) if isinstance(p, dict) else None
        if not _fin(v) or v != math.floor(v) or v < 0 or v > 10_000:
            raise ValueError("slash split: %s must be an integer in [0,10000]" % k)
        total += v
    if total > 10_000:
        raise ValueError("slash split: challengerBps + victimBps must not exceed 10000")


def _share_quantum(amount: float) -> float:
    u = math.ulp(amount)
    return max(1, u) if amount == math.floor(amount) else max(_MIN_SHARE_QUANTUM, u)


def compute_slash_split(amount: Any, policy: dict, dest: dict) -> dict:
    """The challenger / victim / treasury division of a slashed `amount`: exact (treasury = amount - challenger - victim). `dest` has
    ``challengerAccount`` (a string, or an explicit None for an anonymous challenge, which pays the whole bond to the treasury),
    ``victimAccount`` and ``treasuryAccount``."""
    if not _fin(amount) or amount <= 0:
        raise ValueError("computeSlashSplit: amount must be a positive finite number")
    _assert_split_policy(policy)
    victim, treasury = dest.get("victimAccount"), dest.get("treasuryAccount")
    if not isinstance(victim, str) or not victim:
        raise ValueError("computeSlashSplit: victimAccount is required")
    if not isinstance(treasury, str) or not treasury:
        raise ValueError("computeSlashSplit: treasuryAccount is required")
    has = "challengerAccount" in dest
    ch = dest.get("challengerAccount")

    def out(c: float, v: float, t: float, amt: float) -> dict:
        r: Dict[str, Any] = {"amount": amt, "challengerReward": c, "victimCompensation": v, "treasuryRemainder": t}
        if has:
            r["challengerAccount"] = ch
        r.update({"victimAccount": victim, "treasuryAccount": treasury})
        return r
    if has and ch is None:
        return out(0, 0, amount, amount)
    micros = None if amount == math.floor(amount) else to_micros(amount)  # integer bonds keep whole-unit shares
    cbps, vbps = policy["challengerBps"], policy["victimBps"]
    if micros is not None:
        c, v = micros * int(cbps) // 10_000, micros * int(vbps) // 10_000
        t = micros - c - v
        return out(from_micros(c), from_micros(v), from_micros(t), from_micros(micros))
    q = _share_quantum(amount)

    def share(bps: float) -> float:
        return math.floor(((amount * bps) / 10_000) / q) * q
    challenger = min(share(cbps), amount)
    victim_comp = min(share(vbps), amount - challenger)
    return out(challenger, victim_comp, amount - challenger - victim_comp, amount)


def _curve_component(curve: Any, k: float, e: float) -> float:
    kind = curve.get("kind") if isinstance(curve, dict) else None
    if curve is None or kind == "linear":
        return k * e
    if kind == "power":
        g = curve.get("gamma")
        if not (_fin(g) and g >= 1):
            raise ValueError("bondAmount: power curve requires finite gamma >= 1")
        return k * e ** g
    tiers = curve.get("tiers")
    if not isinstance(tiers, list) or not tiers:
        raise ValueError("bondAmount: piecewise curve requires at least one tier")
    acc = prev_up = prev_marginal = 0
    for tier in tiers:
        if not isinstance(tier, dict):
            raise ValueError("bondAmount: malformed tier")
        up_to, mk = tier.get("upTo"), tier.get("marginalK")
        if not ((_fin(up_to) and up_to > prev_up) or up_to == float("inf")):
            raise ValueError("bondAmount: piecewise tier `upTo` must be strictly increasing")
        if not (_fin(mk) and mk >= 0):
            raise ValueError("bondAmount: piecewise `marginalK` must be a finite number >= 0")
        if mk < prev_marginal:
            raise ValueError("bondAmount: piecewise marginal rates must be non-decreasing (convex)")
        width = min(e, up_to) - prev_up
        if width > 0:
            acc += width * mk
        prev_up, prev_marginal = up_to, mk
        if e <= up_to:
            break
    if e > prev_up:
        acc += (e - prev_up) * prev_marginal
    return k * acc


def bond_amount(policy: dict, exposure: Any) -> float:
    """``max(floor, curve(k, exposure))`` snapped up onto the micro grid; no curve = linear. A non-finite or non-positive exposure gives the floor."""
    e = exposure if _fin(exposure) and exposure > 0 else 0
    return quantize_up(max(policy["floor"], _curve_component(policy.get("curve"), policy["k"], e)))


def _claim_identity(claim: dict) -> dict:
    return {"claimDigest": claim.get("pcactn_digest"), "bond_ref": claim.get("bond_ref")}


def settlement_evidence_digest(claim: dict, fraud_verdict: dict) -> str:
    """Binds a slash to the server-derived fraud verdict."""
    return _lenient(dict(_claim_identity(claim), fraudulent=fraud_verdict.get("fraudulent"), slashBondRef=fraud_verdict.get("slashBondRef"),
                         reason=fraud_verdict.get("reason")))


def revocation_evidence_digest(claim: dict, revoked_cap_id: str) -> str:
    return _lenient(dict(_claim_identity(claim), kind="revocation", revokedCapId=revoked_cap_id))


def dispute_evidence_digest(claim: dict, verdict: dict) -> str:
    """Evidence digest of a dispute-game slash: the adjudicator's own verdict, never a challenger assertion."""
    return _lenient(dict(_claim_identity(claim), kind="dispute", outcome=verdict.get("outcome"), input=verdict.get("input"),
                         agentValue=verdict.get("agentValue"), oracleValue=verdict.get("oracleValue"), slashBondRef=verdict.get("slashBondRef"),
                         reason=verdict.get("reason")))


def _message(body: dict) -> bytes:
    return SETTLEMENT_DOMAIN.encode("utf-8") + canonical_bytes(body)


def verify_settlement(record: Any, guardian_public: str, pins: Optional[dict] = None) -> bool:
    """Verify a settlement record's signature under the guardian public key (suite-agile; a PQ / hybrid record verifies only
    under `pins[guardian_public]`). The signature ONLY, as the reference: the wire shape of the record (its action, amounts and
    a slash split that conserves the amount) is :func:`atlas_pca.optimistic.settlement_wire_check`, which also ends in this
    signature check. Never raises."""
    from .optimistic import _UNDEF, _pinned_suite_error, suite_capability_error
    try:
        if not isinstance(record, dict) or not isinstance(record.get("sig"), str) or suite_capability_error(record.get("alg", _UNDEF)) is not None:
            return False
        body = {k: v for k, v in record.items() if k not in ("sig", "pq_sig")}
        return _pinned_suite_error(record.get("alg", _UNDEF), guardian_public, record.get("pq_pk", _UNDEF), _message(body), record["sig"],
                                   record.get("pq_sig", _UNDEF), pins) is None
    except Exception:  # noqa: BLE001
        return False


def settlement_record_digest(record: dict) -> str:
    return _lenient({"t": SETTLEMENT_LEAF_DOMAIN, "record": record})


def settlement_commit(salt: str, record: dict) -> str:
    """The salted commitment of a settlement record (the opaque transparency-log leaf)."""
    if not isinstance(salt, str) or not salt:
        raise ValueError("settlementCommit: salt must be a non-empty string")
    return _lenient({"salt": salt, "settlement_digest": settlement_record_digest(record)})


class BondSettlementPlanner:
    """The pure half of bond settlement. A plan is ``{claimId, expect, next, open?, moves, record}`` (see :mod:`atlas_pca.bond_store`).
    `view` is ``{"bond": id -> row | None, "balance_of": account -> number, "open_totals": depositor -> (count, sum)}`` (callables)."""

    def __init__(self, guardian: KeyPair, guardian_epoch: Optional[int] = None, alg: Optional[str] = None, pq: Any = None,
                 escrow_account: Optional[str] = None, bond_policy: Optional[dict] = None, slash_split_policy: Optional[dict] = None) -> None:
        if not isinstance(guardian, KeyPair):
            raise ValueError("BondLedger: guardian must be a KeyPair")
        if guardian_epoch is not None and (isinstance(guardian_epoch, bool) or not isinstance(guardian_epoch, int) or guardian_epoch < 0 or guardian_epoch > 9007199254740991):
            raise ValueError("BondLedger: guardianEpoch must be a non-negative safe integer")
        self._g, self._epoch, self._alg, self._pq = guardian, guardian_epoch, alg, pq
        self.guardian_public_key = guardian.public
        self.escrow = escrow_account or ESCROW_ACCOUNT
        self.bond_policy = bond_policy or default_bond_policy()
        self.slash_split_policy = slash_split_policy or default_slash_split_policy()

    def _sign(self, base: dict) -> dict:
        with_epoch = dict(base)
        if self._epoch is not None:
            with_epoch["guardian_epoch"] = self._epoch
        body = _bind_suite(with_epoch, self._alg, self._pq)
        parts = sign_with_suite(self._alg, self._g, self._pq, _message(body))
        return dict(body, **parts)

    @staticmethod
    def _move(account: str, op: str, amount: float) -> dict:
        return {"account": account, "op": op, "amount": amount}

    @staticmethod
    def _base(claim_id: str, action: str, amount: float, frm: str, to: str, at: Any, evidence: str) -> dict:
        return {"claimId": claim_id, "action": action, "amount": amount, "from": frm, "to": to, "at": at, "evidenceDigest": evidence}

    @staticmethod
    def _plan(claim_id: str, expect: str, nxt: str, moves: list, record: dict) -> dict:
        return {"claimId": claim_id, "expect": expect, "next": nxt, "moves": moves, "record": record}

    @staticmethod
    def _open_bond(view: dict, who: str, claim_id: str) -> dict:
        bond = view["bond"](claim_id)
        if bond is None:
            raise ValueError("%s: no bond for %s" % (who, claim_id))
        if bond["status"] != "open":
            raise ValueError("%s: bond %s is already %s (double-settle refused)" % (who, claim_id, bond["status"]))
        return bond

    @staticmethod
    def _need_treasury(p: dict, who: str) -> None:
        if not isinstance(p.get("treasury"), str) or not p["treasury"]:
            raise ValueError("%s: treasury is required" % who)

    def _slash_plan(self, bond: dict, claim_id: str, now: Any, evidence: str, p: dict) -> dict:
        treasury, amount = p["treasury"], bond["amount"]
        policy = p["splitPolicy"] if isinstance(p.get("splitPolicy"), dict) else self.slash_split_policy
        dest = {"challengerAccount": p.get("challengerAccount"), "victimAccount": p.get("compensationAccount") or COMPENSATION_POOL_ACCOUNT,
                "treasuryAccount": treasury}
        split = compute_slash_split(amount, policy, dest)
        moves = [self._move(self.escrow, "debit", amount)]  # the full bond leaves escrow
        if split.get("challengerAccount") and split["challengerReward"] > 0:
            moves.append(self._move(split["challengerAccount"], "credit", split["challengerReward"]))
        if split["victimCompensation"] > 0:
            moves.append(self._move(split["victimAccount"], "credit", split["victimCompensation"]))
        if split["treasuryRemainder"] > 0:
            moves.append(self._move(split["treasuryAccount"], "credit", split["treasuryRemainder"]))
        b = self._base(claim_id, "slash", amount, self.escrow, treasury, now, evidence)
        b["split"] = split
        return self._plan(claim_id, "open", "slashed", moves, self._sign(b))

    def plan_open(self, view: dict, claim_id: Any, amount: Any, depositor: Any, exposure: Any, now: Any, window: Optional[dict] = None) -> dict:
        """Open (lock) a bond: refuses an unaffordable bond, one below ``bond_amount(policy, exposure)``, one that breaches the depositor's caps and a
        double-open. The bond moves from the depositor into escrow."""
        if not isinstance(claim_id, str) or not claim_id:
            raise ValueError("openBond: claimId is required")
        if not _fin(amount) or amount <= 0:
            raise ValueError("openBond: amount must be a positive finite number")
        if not isinstance(depositor, str) or not depositor:
            raise ValueError("openBond: depositor is required")
        if view["bond"](claim_id) is not None:
            raise ValueError("openBond: bond %s already exists (double-open refused)" % claim_id)
        required = bond_amount(self.bond_policy, exposure if exposure is not None else 0)
        if not (amount >= required):
            raise ValueError("openBond: amount %s is below the required bond %s" % (_js_num(amount), _js_num(required)))
        count, total = view["open_totals"](depositor)
        if not (_fin(count) and count + 1 <= self.bond_policy["maxOpenClaims"]):
            raise ValueError("openBond: depositor open-claim cap reached")
        if not (_fin(total + amount) and total + amount <= self.bond_policy["maxOpenAmount"]):
            raise ValueError("openBond: depositor aggregate open-bond cap exceeded")
        if not (_fin(view["balance_of"](depositor)) and view["balance_of"](depositor) >= amount):
            raise ValueError("openBond: insufficient balance for the bond")
        record = self._sign(self._base(claim_id, "open", amount, depositor, self.escrow, now, ""))
        open_ = {"amount": amount, "depositor": depositor, "maxOpenClaims": self.bond_policy["maxOpenClaims"],
                 "maxOpenAmount": self.bond_policy["maxOpenAmount"]}
        if window is not None:
            open_["window"] = window
        p = self._plan(claim_id, "none", "open", [self._move(depositor, "debit", amount), self._move(self.escrow, "credit", amount)], record)
        p["open"] = open_
        return p

    def plan_release(self, view: dict, claim_id: str, now: Any) -> dict:
        """Release a bond back to its depositor after an unchallenged window; refuses a missing or already settled bond."""
        bond = view["bond"](claim_id)
        if bond is None:
            raise ValueError("releaseBond: no bond for %s" % claim_id)
        if bond["status"] != "open":
            raise ValueError("releaseBond: bond %s is already %s (double-settle refused)" % (claim_id, bond["status"]))
        amount, depositor = bond["amount"], bond["depositor"]
        return self._plan(claim_id, "open", "released", [self._move(self.escrow, "debit", amount), self._move(depositor, "credit", amount)],
                          self._sign(self._base(claim_id, "release", amount, self.escrow, depositor, now, "")))

    def plan_slash(self, view: dict, p: dict, now: Any) -> dict:
        """Slash against a VERIFIED fraud verdict; re-runs the policy VM itself. `p`: claimId, claim, fraudProof, grant, openSnapshot, treasury, and
        optionally challengerAccount, compensationAccount, splitPolicy."""
        claim_id, claim = p.get("claimId"), p.get("claim")
        bond = self._open_bond(view, "slashBond", claim_id)
        self._need_treasury(p, "slashBond")
        if claim.get("bond_ref") != claim_id:
            raise ValueError("slashBond: claim.bond_ref does not match claimId")
        verdict = verify_fraud_proof(claim, p.get("fraudProof"), p.get("grant"), p.get("openSnapshot"))
        if verdict.get("fraudulent") is not True or verdict.get("slashBondRef") != claim_id:
            raise ValueError("slashBond: refused — no verified fraud verdict slashing %s (%s)" % (claim_id, verdict.get("reason")))
        return self._slash_plan(bond, claim_id, now, settlement_evidence_digest(claim, verdict), p)

    def plan_slash_on_revocation(self, view: dict, p: dict, now: Any) -> dict:
        """Slash because a capability in the claim's chain was revoked after the bond opened (server-derived evidence). `p` adds revokedCapId."""
        claim_id, claim = p.get("claimId"), p.get("claim")
        bond = self._open_bond(view, "slashBondOnRevocation", claim_id)
        self._need_treasury(p, "slashBondOnRevocation")
        if claim.get("bond_ref") != claim_id:
            raise ValueError("slashBondOnRevocation: claim.bond_ref does not match claimId")
        revoked = p.get("revokedCapId")
        if not isinstance(revoked, str) or not revoked:
            raise ValueError("slashBondOnRevocation: revokedCapId is required")
        return self._slash_plan(bond, claim_id, now, revocation_evidence_digest(claim, revoked), p)

    def plan_slash_on_dispute(self, view: dict, p: dict, now: Any) -> dict:
        """Slash the AGENT's bond because a dispute proved it understated a risk input; re-runs the adjudication itself. `p` adds dispute, oracle, rMargin?."""
        claim_id, claim = p.get("claimId"), p.get("claim")
        bond = self._open_bond(view, "slashBondOnDispute", claim_id)
        self._need_treasury(p, "slashBondOnDispute")
        if claim.get("bond_ref") != claim_id:
            raise ValueError("slashBondOnDispute: claim.bond_ref does not match claimId")
        v = adjudicate_dispute(claim, p.get("dispute"), p.get("grant"), p.get("openSnapshot"), p.get("oracle"), p.get("rMargin"))
        if v.get("outcome") != "agent-fraud" or v.get("fraudulent") is not True or v.get("slashBondRef") != claim_id:
            raise ValueError("slashBondOnDispute: refused — no verified agent-fraud verdict slashing %s (%s: %s)" % (claim_id, v.get("outcome"), v.get("reason")))
        return self._slash_plan(bond, claim_id, now, dispute_evidence_digest(claim, v), p)

    def plan_slash_counter_bond(self, view: dict, p: dict, now: Any) -> dict:
        """Slash the CHALLENGER's counter-bond because the dispute was frivolous (anti-griefing); an anonymous slash, 100% to the treasury."""
        cid, claim = p.get("counterBondId"), p.get("claim")
        bond = view["bond"](cid)
        if bond is None:
            raise ValueError("slashCounterBond: no counter-bond for %s" % cid)
        if bond["status"] != "open":
            raise ValueError("slashCounterBond: counter-bond %s is already %s (double-settle refused)" % (cid, bond["status"]))
        self._need_treasury(p, "slashCounterBond")
        v = adjudicate_dispute(claim, p.get("dispute"), p.get("grant"), p.get("openSnapshot"), p.get("oracle"), p.get("rMargin"))
        if v.get("outcome") != "claim-upheld" or v.get("slashCounterBond") is not True:
            raise ValueError("slashCounterBond: refused — the dispute is not frivolous (%s: %s)" % (v.get("outcome"), v.get("reason")))
        return self._slash_plan(bond, cid, now, dispute_evidence_digest(claim, v),
                                {"treasury": p["treasury"], "challengerAccount": None, "compensationAccount": p.get("compensationAccount"),
                                 "splitPolicy": p.get("splitPolicy")})


def _js_num(x: Any) -> str:
    from .predicates import _js_number_string
    return _js_number_string(float(x))


class StoreBondLedger:
    """Durable, restart-safe bond settlement over a bond store (:class:`atlas_pca.bond_store.KvBondStore` or your own). Every method is
    idempotent under retry: repeating a transition that already committed returns the stored record and moves nothing, while a conflicting
    transition (a release after a slash, a second slash with different evidence) raises. Every failure is a :class:`BondStoreError`:
    ``store_missing``, ``guardian_key_missing``, ``clock_invalid``, ``store_unavailable``, ``store_corrupt``, ``invalid_claim``, ``window_open``,
    ``window_closed``, ``unregistered``, ``claim_mismatch`` or ``conflict``. Planner failures keep their own message (a plain ``ValueError``)."""

    def __init__(self, store: Any, guardian: Any, clock: Optional[Callable[[], float]] = None, window_policy: Optional[dict] = None,
                 guardian_epoch: Optional[int] = None, alg: Optional[str] = None, pq: Any = None, escrow_account: Optional[str] = None,
                 bond_policy: Optional[dict] = None, slash_split_policy: Optional[dict] = None) -> None:
        if not is_bond_store(store):
            raise BondStoreError("store_missing", "a BondStore is required (there is no in-memory default)")
        if not isinstance(guardian, KeyPair):
            raise BondStoreError("guardian_key_missing", "a guardian secret key is required")
        self._store = store
        self._planner = BondSettlementPlanner(guardian, guardian_epoch, alg, pq, escrow_account, bond_policy, slash_split_policy)
        self._clock = clock or (lambda: time.time() * 1000)
        self._wp = window_policy or DEFAULT_WINDOW_POLICY

    @property
    def guardian_public_key(self) -> str:
        return self._planner.guardian_public_key

    def _guard(self, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except BondStoreError:
            raise
        except Exception as e:  # noqa: BLE001
            raise BondStoreError("store_unavailable", str(e) or "store failed") from None

    def _load(self, claim_id: str, depositor: Optional[str] = None) -> tuple:
        snap = self._guard(lambda: self._store.read(claim_id, depositor))
        t = self._clock()
        if not _fin(t):
            raise BondStoreError("clock_invalid", "the clock returned a non-finite time")
        bond = snap.get("bond")
        bal = {a: v for a, v in snap["balances"]}
        view = {"bond": lambda cid: bond if bond and bond["claimId"] == cid else None, "balance_of": lambda a: bal.get(a, 0),
                "open_totals": lambda _d: (snap["openTotals"]["count"], snap["openTotals"]["sum"])}
        return snap, view, max(t, snap["highWater"])

    def _submit(self, plan: dict, now: Any) -> dict:
        out = self._guard(lambda: self._store.commit(plan, now))
        if out["outcome"] == "conflict":
            raise BondStoreError("conflict", out["reason"])
        return out["record"]

    def _settle(self, claim_id: str, plan: Callable[[dict, Any], dict], gate: Optional[Callable[[dict, Any], None]] = None) -> dict:
        snap, view, now = self._load(claim_id)
        bond = snap.get("bond")
        if bond and bond["status"] != "open":
            last = bond["records"][-1] if bond["records"] else None
            as_open = dict(view, bond=lambda _c: dict(bond, status="open"))
            again = plan(as_open, now)  # raises if the evidence no longer holds
            if last and same_settlement(last, again["record"]):
                return last
            return plan(view, now)["record"]  # raises the standard double-settle refusal
        if bond and gate:
            gate(bond, now)
        return self._submit(plan(view, now), now)

    def deposit(self, account: str, amount: Any) -> float:
        """Top up an account of the internal books (a positive finite amount)."""
        return self._guard(lambda: self._store.deposit(account, amount))

    def balance_of(self, account: str) -> float:
        snap = self._guard(lambda: self._store.read("", account))
        return snap["balances"][0][1] if snap["balances"] else 0

    def bond_status(self, claim_id: str) -> str:
        snap = self._guard(lambda: self._store.read(claim_id, None))
        return snap["bond"]["status"] if snap.get("bond") else "none"

    def get_bond(self, claim_id: str) -> Optional[dict]:
        return self._guard(lambda: self._store.read(claim_id, None)).get("bond")

    def challenge_status(self, claim_id: str) -> dict:
        """Where the claim's challenge window stands on the ledger's clock; raises ``unregistered`` for a bond with no claim."""
        snap, _, now = self._load(claim_id)
        w = (snap.get("bond") or {}).get("window")
        if not w:
            raise BondStoreError("unregistered", "bond %s has no registered claim" % claim_id)
        ends = w["registeredAt"] + w["windowMs"]
        if not (_fin(now) and _fin(ends)):  # a non-finite clock or window end is a refusal, never a phase: finalized opens settlement
            raise BondStoreError("clock_invalid", "the clock or the challenge window end is not finite")
        return {"phase": "finalized" if now > ends else "open", "endsAt": ends, "now": now}

    def _replay_open(self, prior: dict, depositor: str, amount: Any, window: Optional[dict] = None) -> dict:
        same = prior["depositor"] == depositor and prior["amount"] == amount and (prior.get("window") or {}).get("claimDigest") == (window or {}).get("claimDigest")
        if same and prior["records"]:
            return prior["records"][0]
        raise BondStoreError("conflict", "openBond: bond %s already exists (double-open refused)" % prior["claimId"])

    def open_claim(self, claim: dict, pcactn: dict, signer_public: str, amount: Any, depositor: str, exposure: Any = None) -> dict:
        """Register an optimistic claim and lock its bond in one atomic commit. The claim must pass the claim check against the ledger's clock and
        its window must be at least the realistic floor; the window then runs from the ledger's own ``registeredAt``."""
        snap, view, now = self._load(str(claim.get("bond_ref")), depositor)
        check = claim_check(claim, hash_canonical(pcactn), signer_public, now, self._wp)
        if check != "ok":
            reason = {"malformed": "malformed claim", "irreversible": "irreversible action is ineligible for the optimistic path",
                      "digest": "claim does not cover this PCActn", "claimed_r": "claimed_r is not finite",
                      "signature": "claim signature does not verify"}.get(check)
            if check == "window":
                reason = _validate_window(claim.get("issued_at"), claim.get("challenge_window_ms"), now, self._wp)
            raise BondStoreError("invalid_claim", reason or check)
        floor = max(self._wp["minWindowMs"], DEFAULT_MIN_CHALLENGE_WINDOW_MS)
        if claim["challenge_window_ms"] < floor:
            raise BondStoreError("invalid_claim", "challenge window %s ms is below the %s ms floor" % (_js_num(claim["challenge_window_ms"]), _js_num(floor)))
        if not isinstance(claim.get("bond_ref"), str) or not claim["bond_ref"]:
            raise BondStoreError("invalid_claim", "claim has no bond_ref")
        window = {"registeredAt": now, "windowMs": claim["challenge_window_ms"], "claimDigest": _lenient(claim)}
        if snap.get("bond"):
            return self._replay_open(snap["bond"], depositor, amount, window)
        return self._submit(self._planner.plan_open(view, claim["bond_ref"], amount, depositor, exposure, now, window), now)

    def open_bond(self, claim_id: str, amount: Any, depositor: str, exposure: Any = None) -> dict:
        """Open a bond that backs no claim (a challenger's counter-bond). It has no window; settle it with ``slash_counter_bond`` or
        ``release_unregistered``."""
        snap, view, now = self._load(claim_id, depositor)
        if snap.get("bond"):
            return self._replay_open(snap["bond"], depositor, amount)
        return self._submit(self._planner.plan_open(view, claim_id, amount, depositor, exposure, now, None), now)

    def release(self, claim_id: str) -> dict:
        """Release a registered claim's bond once its challenge window has closed on the ledger's clock."""
        def gate(bond: dict, now: Any) -> None:
            w = bond.get("window")
            if not w:
                raise BondStoreError("unregistered", "bond %s has no registered claim; use release_unregistered for a counter-bond" % claim_id)
            if not (_fin(now) and now > w["registeredAt"] + w["windowMs"]):
                raise BondStoreError("window_open", "the challenge window of %s closes at %s" % (claim_id, _js_num(w["registeredAt"] + w["windowMs"])))
        return self._settle(claim_id, lambda view, now: self._planner.plan_release(view, claim_id, now), gate)

    def release_unregistered(self, claim_id: str) -> dict:
        """Release a bond that backs no claim (a counter-bond)."""
        def gate(bond: dict, _now: Any) -> None:
            if bond.get("window"):
                raise BondStoreError("conflict", "bond %s backs a registered claim; use release" % claim_id)
        return self._settle(claim_id, lambda view, now: self._planner.plan_release(view, claim_id, now), gate)

    def _challenge_gate(self, claim: dict) -> Callable[[dict, Any], None]:
        def gate(bond: dict, now: Any) -> None:
            w = bond.get("window")
            if not w:
                raise BondStoreError("unregistered", "bond %s has no registered claim" % bond["claimId"])
            if w["claimDigest"] != _lenient(claim):
                raise BondStoreError("claim_mismatch", "the claim is not the one registered for %s" % bond["claimId"])
            if not (_fin(now) and now <= w["registeredAt"] + w["windowMs"]):
                raise BondStoreError("window_closed", "the challenge window of %s closed at %s" % (bond["claimId"], _js_num(w["registeredAt"] + w["windowMs"])))
        return gate

    def slash_bond(self, params: dict) -> dict:
        """Slash on a fraud proof the ledger re-verifies itself, inside the challenge window."""
        return self._settle(params["claimId"], lambda view, now: self._planner.plan_slash(view, params, now), self._challenge_gate(params["claim"]))

    def slash_bond_on_dispute(self, params: dict) -> dict:
        """Slash on a dispute the ledger re-adjudicates itself, inside the challenge window."""
        return self._settle(params["claimId"], lambda view, now: self._planner.plan_slash_on_dispute(view, params, now), self._challenge_gate(params["claim"]))

    def slash_bond_on_revocation(self, params: dict) -> dict:
        """Slash because a capability in the claim's chain was revoked (server-derived evidence; not window-gated)."""
        def gate(bond: dict, _now: Any) -> None:
            if bond.get("window") and bond["window"]["claimDigest"] != _lenient(params["claim"]):
                raise BondStoreError("claim_mismatch", "the claim is not the one registered for %s" % bond["claimId"])
        return self._settle(params["claimId"], lambda view, now: self._planner.plan_slash_on_revocation(view, params, now), gate)

    def slash_counter_bond(self, params: dict) -> dict:
        """Slash a challenger's counter-bond after a frivolous dispute."""
        return self._settle(params["counterBondId"], lambda view, now: self._planner.plan_slash_counter_bond(view, params, now))


class InsuranceCapitalPool:
    """A finite, fail-closed insurance capital pool. Premiums (priced by :func:`atlas_pca.reputation.price_coverage`) are credited;
    payouts are debited and REFUSED when they exceed the free capital. Every amount is checked finite and non-negative, and the three
    ledgers (``initial``, ``premiumsIn``, ``payoutsOut``) always reconcile to ``balance``. Accounting only: nothing here moves money."""

    def __init__(self, initial: Any = 0):
        if not _pool_finite(initial) or initial < 0:
            raise ValueError("InsuranceCapitalPool: initial capital must be a non-negative finite number")
        self._initial, self._premiums_in, self._payouts_out = initial, 0, 0

    @property
    def balance(self) -> Any:
        return self._initial + self._premiums_in - self._payouts_out

    @property
    def premiums_in(self) -> Any:
        return self._premiums_in

    @property
    def payouts_out(self) -> Any:
        return self._payouts_out

    def state(self) -> Dict[str, Any]:
        """The accounting snapshot ``{"initial", "premiumsIn", "payoutsOut", "balance"}``."""
        return {"initial": self._initial, "premiumsIn": self._premiums_in, "payoutsOut": self._payouts_out, "balance": self.balance}

    def quote(self, rep: Dict[str, Any], exposure: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
        """Price coverage of ``exposure`` for ``rep`` without changing the pool."""
        from .reputation import price_coverage
        return price_coverage(rep, exposure, opts)

    def collect_premium(self, rep: Dict[str, Any], exposure: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
        """Price coverage and, unless declined, credit the premium: ``{"pricing", "state"}``."""
        pricing = self.quote(rep, exposure, opts)
        if not pricing["declined"] and pricing["premium"] > 0:
            if not _pool_finite(pricing["premium"]):
                raise ValueError("collectPremium: priced premium is not a non-negative finite number")
            self._premiums_in += pricing["premium"]
        return {"pricing": pricing, "state": self.state()}

    def can_cover(self, amount: Any) -> bool:
        """True iff the pool holds at least ``amount`` of free capital."""
        return _pool_finite(amount) and amount >= 0 and self.balance >= amount

    def pay_claim(self, amount: Any) -> Dict[str, Any]:
        """Pay ``amount`` out of the pool and return the new state. Raises ValueError when the amount is not positive and finite or
        exceeds the free capital: the pool never pays what it does not hold."""
        if not _pool_finite(amount) or amount <= 0:
            raise ValueError("payClaim: amount must be a positive finite number")
        if not (_pool_finite(self.balance) and amount <= self.balance):
            raise ValueError("payClaim: insufficient pool capital (need %s, have %s)" % (amount, self.balance))
        self._payouts_out += amount
        return self.state()


def _pool_finite(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)
