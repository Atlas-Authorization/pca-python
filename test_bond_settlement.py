"""Bond settlement over the durable bond store (atlas_pca.bond_settlement): exact micro-unit arithmetic, the slash split, the signed records,
the fail-closed refusals and the retry semantics. Hand-written; the store itself is replayed against the reference in test_ref_core_stores."""
import pytest

from atlas_pca.agent import keypair_from_seed
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.bond_settlement import StoreBondLedger, bond_amount, compute_slash_split, default_bond_policy, verify_settlement
from atlas_pca.bond_store import KvBondStore, apply_bond_moves, exact_add
from atlas_pca.store_errors import BondStoreError

G = keypair_from_seed(b"\x04" * 32, allow_insecure_signer=True)


def ledger(clock):
    return StoreBondLedger(KvBondStore(MemoryAtomicKv()), G, clock=lambda: clock[0])


def test_micro_unit_arithmetic_is_exact():
    assert exact_add(0.1, 0.2, 1) == 0.3 and exact_add(1, 0.000001, -1) == 0.999999
    assert apply_bond_moves(lambda a: 5, [{"account": "a", "op": "debit", "amount": 2.5}]) == {"a": 2.5}
    with pytest.raises(ValueError):
        apply_bond_moves(lambda a: 1, [{"account": "a", "op": "debit", "amount": 2}])  # an overdraft applies nothing
    assert bond_amount(default_bond_policy(), 0) == 1 and bond_amount({"floor": 1, "k": 2, "maxOpenClaims": 1, "maxOpenAmount": 1}, 3.3) == 6.6


def test_the_slash_split_sums_exactly():
    s = compute_slash_split(100, {"challengerBps": 5000, "victimBps": 4000}, {"challengerAccount": "ch", "victimAccount": "v", "treasuryAccount": "t"})
    assert (s["challengerReward"], s["victimCompensation"], s["treasuryRemainder"]) == (50, 40, 10)
    anon = compute_slash_split(7.25, {"challengerBps": 5000, "victimBps": 4000}, {"challengerAccount": None, "victimAccount": "v", "treasuryAccount": "t"})
    assert anon["treasuryRemainder"] == 7.25 and anon["challengerReward"] == 0
    f = compute_slash_split(10.333333, {"challengerBps": 3333, "victimBps": 3333}, {"challengerAccount": "c", "victimAccount": "v", "treasuryAccount": "t"})
    assert exact_add(exact_add(f["challengerReward"], f["victimCompensation"], 1), f["treasuryRemainder"], 1) == 10.333333
    with pytest.raises(ValueError):
        compute_slash_split(1, {"challengerBps": 9000, "victimBps": 2000}, {"victimAccount": "v", "treasuryAccount": "t"})


def test_open_release_and_retry_semantics():
    clock = [1_000]
    b = ledger(clock)
    assert b.deposit("alice", 100) == 100 and b.bond_status("c1") == "none"
    rec = b.open_bond("c1", 40, "alice")
    assert verify_settlement(rec, G.public) and b.balance_of("alice") == 60 and b.bond_status("c1") == "open"
    assert b.open_bond("c1", 40, "alice") == rec  # a retried open returns the original record
    with pytest.raises(BondStoreError) as e:
        b.open_bond("c1", 41, "alice")
    assert e.value.code == "conflict"
    out = b.release_unregistered("c1")
    assert out["action"] == "release" and verify_settlement(out, G.public) and b.balance_of("alice") == 100
    assert b.release_unregistered("c1") == out  # idempotent under retry
    assert b.bond_status("c1") == "released"


def test_refusals_fail_closed():
    clock = [1_000]
    b = ledger(clock)
    b.deposit("alice", 10)
    with pytest.raises(ValueError):
        b.open_bond("big", 50, "alice")  # insufficient balance
    with pytest.raises(ValueError):
        b.release_unregistered("nothing")
    bad = StoreBondLedger(KvBondStore(MemoryAtomicKv()), G, clock=lambda: float("nan"))
    with pytest.raises(BondStoreError) as e:
        bad.open_bond("x", 1, "alice")
    assert e.value.code == "clock_invalid"
    with pytest.raises(BondStoreError) as e2:
        StoreBondLedger(None, G)
    assert e2.value.code == "store_missing"
    with pytest.raises(BondStoreError) as e3:
        StoreBondLedger(KvBondStore(MemoryAtomicKv()), None)
    assert e3.value.code == "guardian_key_missing"
    with pytest.raises(BondStoreError) as e4:
        b.challenge_status("c9")
    assert e4.value.code == "unregistered" or e4.value.code == "store_unavailable"


def test_a_clock_that_steps_back_cannot_release_early():
    clock = [5_000]
    b = ledger(clock)
    b.deposit("alice", 10)
    b.open_bond("c", 5, "alice")
    clock[0] = 1  # the store's high-water mark keeps "now" from going backwards
    b.release_unregistered("c")
    assert b.get_bond("c")["records"][-1]["at"] >= 5_000


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_challenge_status_refuses_a_nonfinite_clock(bad):
    from atlas_pca.optimistic import open_optimistic
    clock = [1_000]
    b = ledger(clock)
    b.deposit("alice", 100)
    pca = {"action": {"reversibility_class": "reversible"}}
    claim = open_optimistic(pca, {"bondRef": "c1", "claimedR": 0.5, "issuedAt": 1_000, "serverNow": 1_000}, b"\x04" * 32, True)
    b.open_claim(claim, pca, G.public, 5, "alice")
    assert b.challenge_status("c1")["phase"] == "open"
    clock[0] = 1_000 + 300_000 + 1
    assert b.challenge_status("c1")["phase"] == "finalized"
    clock[0] = bad
    with pytest.raises(BondStoreError) as e:
        b.challenge_status("c1")  # a -Infinity or NaN clock must never read as finalized (that opens settlement)
    assert e.value.code == "clock_invalid"
