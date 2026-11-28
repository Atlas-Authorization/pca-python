"""Replays the TS-reference oracle of the core sweep (testdata/ref-core-sweep-java.json.gz, 2167 cases): chain compaction and its memo, receipt
chains (op scripts with tampering), reputation and signed coverage quotes, the insurance capital pool, the frontier signals, the budget forecast,
the multi-agent budget algebra and the pure half of approvals. Every fn has a handler and the totals are asserted. The underwriter key is
sha256("atlas-pca-conformance/sweep/underwriter"); "@u" in a quote case stands for its public key; a script op the reference refuses is
{"$err": "Error"} (or "bad op" is not used here): the native must raise there."""
import copy
import hashlib
import math
import os

import pytest

from atlas_pca import approvals as AP
from atlas_pca import bond_settlement as BS
from atlas_pca import budget_forecast as BF
from atlas_pca import chain_compact as CC
from atlas_pca import frontier_signals as FS
from atlas_pca import receipt as RC
from atlas_pca import reputation as RP
from atlas_pca import risk as RK
from atlas_pca.agent import KeyPair
from base_oracle import HERE, load, run

COUNT, CASES = load("core-sweep-java", os.path.join(HERE, "testdata", "ref-core-sweep-java.json.gz"))
UW = KeyPair(hashlib.sha256(b"atlas-pca-conformance/sweep/underwriter").digest(), allow_insecure_signer=True)
ERR = {"$err": "Error"}


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _script(ops, step):
    st, out = {}, []
    for op in ops:
        try:
            out.append(step(st, op))
        except Exception:  # noqa: BLE001 - a refused op, compared against the reference's {"$err": "Error"}
            out.append(ERR)
    return out


def _memo_step(st, op):
    k = op[0]
    if k == "new":
        o = op[1] or {}
        st["m"] = CC.ChainMemo(o.get("maxEntries"), o.get("ttlMs"))
        return None
    m = st["m"]
    if k == "remember":
        return m.remember_verified(op[1], op[2], op[3])
    if k == "resolve":
        r = m.resolve(op[1], op[2])
        if not r["ok"]:
            return r
        v = r["view"]
        return {"ok": True, "view": {"n": v.n, "hashes": [v.hash(i) for i in range(v.n)], "counts": [v.count(i) for i in range(v.n)], "leaf": v.leaf}}
    if k == "prune":
        m.prune(op[1])
        return None
    if k == "forget":
        return m.forget(op[1])
    if k == "size":
        return m.size
    raise ValueError("op")


def _receipt_step(st, op):
    log = st.setdefault("log", [])
    k = op[0]
    if k == "append":
        st["log"] = RC.append_receipt(log, op[1], op[2], op[3])
        return st["log"][-1]
    if k == "head":
        return RC.receipt_head(log)
    if k == "verify":
        return RC.verify_receipt_chain(log)
    if k == "set":
        st["log"] = copy.deepcopy(op[1])
        return None
    if k == "tamper":
        st["log"] = l = copy.deepcopy(log)
        if len(op) > 3 and op[3] == "$del":
            del l[op[1]][op[2]]
        else:
            l[op[1]][op[2]] = op[3]
        return None
    if k == "swap":
        l = copy.deepcopy(log)
        l[op[1]], l[op[2]] = l[op[2]], l[op[1]]
        st["log"] = l
        return None
    if k == "drop":
        st["log"] = [e for i, e in enumerate(log) if i != op[1]]
        return None
    if k == "truncate":
        st["log"] = log[:op[1]]
        return None
    raise ValueError("op")


def _pool_step(st, op):
    k = op[0]
    if k == "new":
        st["p"] = None
        st["p"] = BS.InsuranceCapitalPool(op[1])
        return st["p"].state()
    p = st["p"]
    if k == "quote":
        return p.quote(op[1], op[2], op[3])
    if k == "collect":
        return p.collect_premium(op[1], op[2], op[3])
    if k == "canCover":
        return p.can_cover(op[1])
    if k == "pay":
        return p.pay_claim(op[1])
    if k == "state":
        return p.state()
    raise ValueError("op")


def _verify_quote(q, uw, now):
    return RP.verify_coverage_quote(q, UW.public if uw == "@u" else uw, math.nan if now is None else now)


def _same(got, out, _case):
    """JSON equality with the sign of a zero compared (a budget may come out as -0)."""
    from base_oracle import canon
    return canon(got) == canon(out)


HANDLERS = {
    "hopLeaf": CC.hop_leaf, "hopsRoot": CC.hops_root, "compactChain": CC.compact_chain, "compactChainShapeError": CC.compact_chain_shape_error,
    "chainMemo": lambda ops: _script(ops, _memo_step),
    "receiptFor": RC.receipt_for, "receiptChain": lambda ops: _script(ops, _receipt_step),
    "reputation": RP.reputation, "priceCoverage": RP.price_coverage,
    "issueCoverageQuote": lambda rep, e, now, ttl, opts: RP.issue_coverage_quote(rep, e, UW, now, ttl, opts),
    "verifyCoverageQuote": _verify_quote, "pool": lambda ops: _script(ops, _pool_step),
    "semanticSignal": FS.semantic_signal, "progressSignal": FS.progress_signal, "objectiveSignal": FS.objective_signal,
    "tightenRiskInputs": FS.tighten_risk_inputs,
    "recommendPolicy": BF.recommend_policy, "autonomyBoundOf": BF.autonomy_bound_of,
    "subBudget": RK.sub_budget, "debitConsolidated": RK.debit_consolidated, "debitConsolidatedPath": RK.debit_consolidated_path,
    "rechargeFull": lambda b_max, now: RK.recharge_full({"B": 1, "tau": 1}, b_max, now),
    "approveClass": lambda verbs, ttl, by, now, res: AP.approve_class(verbs, ttl_ms=ttl, by=by, now=now, resource=res),
    "classApprovalCovers": AP.class_approval_covers, "coveredByAny": AP.covered_by_any, "recordDecision": AP.record_decision,
    "pendingRequests": AP.pending_requests, "applyCosign": AP.apply_cosign,
}
TOTALS = {"classApprovalCovers": 675, "debitConsolidated": 288, "priceCoverage": 226, "tightenRiskInputs": 121, "subBudget": 117,
          "recommendPolicy": 110, "approveClass": 75, "debitConsolidatedPath": 72, "receiptFor": 60, "reputation": 48, "applyCosign": 48,
          "issueCoverageQuote": 43, "coveredByAny": 36, "rechargeFull": 28, "compactChainShapeError": 27, "verifyCoverageQuote": 27,
          "semanticSignal": 26, "progressSignal": 26, "objectiveSignal": 26, "receiptChain": 21, "hopsRoot": 14, "compactChain": 14,
          "autonomyBoundOf": 10, "pool": 9, "chainMemo": 8, "hopLeaf": 5, "pendingRequests": 5, "recordDecision": 2}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 2167 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_core_sweep_replay(fn):
    assert run(CASES[fn], lambda *a: HANDLERS[fn](*_dec(list(a))), compare=_same) == (TOTALS[fn], 0)
