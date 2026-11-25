"""Replays the TS-reference oracle of the small public helpers of the flagship (testdata/ref-core-small-surface.json.gz, 1113 cases, 46 functions): the cheap
PCActn claims, goal commitments, discharge requests, the named unmet limit, reversibility class, agent caveat context, threshold assembly, budget caveat,
decision meet, threshold escalation, detector receipts and their policy fold, the replay guard options, workflow commitment and receipt errors, obligation
rules, the cheap chain check, the holder PQ key, discovery documents and fetch, revocation membership and staleness, the canonical compact JWS gate,
policy templates, the fluent builder and linked templates, the undo ledger (transitions, signed receipts, both stores), the catalog risk inputs and the
payment approval profiles. A refusal of the reference is a native refusal; the keys the generator derived from seed labels are derived here the same way.
Where the reference reports a boolean or a verdict the native must report the same value."""
import hashlib
import os

from atlas_pca import pca_surface as S
from atlas_pca import server_surface as SS
from atlas_pca import server_surface as S_server
from base_oracle import HERE, canon, load, norm, run
import pytest

COUNT, CASES = load("core-small-surface", os.path.join(HERE, "testdata", "ref-core-small-surface.json.gz"))


def seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode("utf-8")).digest()


def _try(f, *a):
    try:
        return {"ok": True, "v": f(*a)}
    except Exception:  # noqa: BLE001
        return {"ok": False}


def _camel_to_snake(d):
    import re
    return {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), k): v for k, v in d.items()}


def _guard_seq(opts, steps):
    from atlas_pca.connect_replay import InMemoryReplayStore, guard_pcactn_replay
    store = InMemoryReplayStore()
    out = []
    for st in steps:
        kw = {}
        if "clockSkewMs" in opts:
            kw["clock_skew_ms"] = opts["clockSkewMs"]
        if "requireNonce" in opts:
            kw["require_nonce"] = opts["requireNonce"]
        if opts.get("counters"):
            kw["counters"] = store
        out.append(guard_pcactn_replay(store, st["p"], opts["aud"], st["now"], **kw))
    return out


def _detector_signal(i):
    return S.detector_signal(i.get("policy"), i.get("now"), i.get("receipts"), i.get("input_digests"), i.get("session"))


def _chain(chain, issuer, policy):
    r = S.verify_chain_cheap(chain, issuer, policy)
    return {"ok": True, "pqHops": r["pqHops"]} if r["ok"] else {"ok": False, "reason": r["reason"]}


def _holder_pq(alg, holder, art, hpq):
    r = S.holder_pq_key(alg, holder, art, hpq)
    pq = r.get("pq")
    return None if pq is None else pq.key


def _fetch(base, mode):
    from atlas_pca import discovery as DV
    urls = []
    doc = {"audience": "https://rs.example", "pca_versions": [2], "signature_suites": ["ed25519", "ml-dsa-65"], "action_header": "PCA-Action"}

    class Res:
        ok = mode != "500"
        status = 500 if mode == "500" else 200

        def json(self):
            return {"nope": 1} if mode == "bad" else doc

    def fetch(url, init):
        urls.append(url + "|" + str(init.get("headers", {}).get("accept")))
        if mode == "throw":
            raise RuntimeError("boom")
        return Res()
    try:
        return {"doc": DV.fetch_discovery(base, fetch), "urls": urls}
    except Exception:  # noqa: BLE001
        return {"error": True, "urls": urls}


def _build_doc(opts):
    from atlas_pca import discovery as DV
    o = dict(opts)
    aud = o.pop("audience", None)
    return DV.build_discovery_document(aud, **_camel_to_snake(o))


def _validate_staleness(p):
    try:
        S.validate_revocation_staleness(p)
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return {"ok": False}


def _jws_segments(a, b):
    from atlas_pca import sdjwt_jws as J
    try:
        return {"ok": True, "header": J.assert_canonical_jws_segments(a, b)}
    except Exception:  # noqa: BLE001
        return {"ok": False}


def _jws(**kw):
    from atlas_pca import sdjwt_jws as J
    return lambda t: J.is_canonical_compact_jws(t, **kw)


def _kp(label):
    from atlas_pca.agent import KeyPair
    k = seed("small/tpl/" + label)
    return KeyPair(k, allow_insecure_signer=True)


def _from_template(name, ov):
    try:
        o = {}
        if ov:
            o = _camel_to_snake(ov)
        a = SS.from_template(name, _kp("p"), "g", None, _kp("h"), 1700000000000, o or None)
        pol = a.policy if hasattr(a, "policy") else a["policy"]
        return {"ok": True, "predicates": pol["predicates"], "caveats": pol["caveats"], "riskPolicy": pol["riskPolicy"], "budgetModel": pol["budgetModel"]}
    except Exception:  # noqa: BLE001
        return {"ok": False}


def _builder(ops):
    try:
        b = SS.policy()
        for op, *a in ops:
            b = SS.PolicyBuilder.from_template(a[0]) if op == "from" else getattr(b, op)(*a)
        return {"ok": True, "built": b.build()}
    except Exception:  # noqa: BLE001
        return {"ok": False}


def _link(definition, slots, bind):
    try:
        return {"ok": True, "ref": SS.create_link(definition, slots, bind)}
    except Exception:  # noqa: BLE001
        return {"ok": False}


def _limits():
    from atlas_pca import policy_link as PL
    return {"MAX_SLOTS": PL.MAX_SLOTS, "MAX_SLOT_STRING": PL.MAX_SLOT_STRING, "MAX_SLOT_SET": PL.MAX_SLOT_SET, "TEMPLATE_KIND": PL.TEMPLATE_KIND,
            "TIGHTEN_KIND": PL.TIGHTEN_KIND}


def _undo_lifecycle(rec, steps):
    from atlas_pca import undo as U
    from atlas_pca.agent import KeyPair
    secret = seed("small/undo/service")
    cur = U.with_receipt(rec, {"event": "opened", "note": ""}, rec["opened_at"], secret)
    out = [cur]
    for ev, now in steps:
        t = U.undo_transition(cur, ev, now)
        if t["outcome"] == "applied":
            cur = U.with_receipt(t["record"], t["receipt"], now, secret)
            out.append({"applied": ev["kind"], "record": cur})
        else:
            out.append({t["outcome"]: t.get("code")})
    out.append({"chain": U.undo_receipt_chain_error(cur, KeyPair(secret, allow_insecure_signer=True).public)})
    return out


def _undo_store(kind, ops):
    from atlas_pca.atomic_kv import MemoryAtomicKv
    from atlas_pca.undo_coordinator import KvUndoStore, MemoryUndoStore
    st = MemoryUndoStore() if kind == "memory" else KvUndoStore(MemoryAtomicKv(), True)
    out = []
    for op, a, b, c in [(o + [None, None, None])[:4] for o in ops]:
        try:
            if op == "create":
                out.append(st.create(a))
            elif op == "get":
                out.append(st.get(a))
            elif op == "replace":
                out.append(st.replace(a, b, c))
            else:
                out.append(st.list(a))
        except Exception as e:  # noqa: BLE001
            out.append({"error": str(getattr(e, "code", None) or "x")})
    return out


def _risk(verb, params, grant, taint):
    return S.catalog_risk(verb, params, grant, None, taint)


def _spc(r, as_):
    from atlas_pca import actions_approval_profiles as A
    return _try(lambda: A.spc_expectation(r, "https://shop.example", as_))


def _ciba(r):
    from atlas_pca import actions_approval_profiles as A
    return _try(lambda: A.ciba_approval_details(r))


def _workflow_receipt(body, rs, receipts, now):
    r = S_server.workflow_receipt_error(body, rs, receipts, now)
    return r["at"] if r else None


def _obligations(rules, ctx):
    return S.collect_obligations(rules, ctx)


HANDLERS = {
    "pcactnCheapClaims": S.pcactn_cheap_claims,
    "goalCommitOf": lambda g, s: __import__("atlas_pca.agent", fromlist=["x"]).goal_commit_of(g, s),
    "verifyGoalCommit": S.verify_goal_commit,
    "dischargeRequests": S.discharge_requests,
    "namedUnmetLimitReason": S.named_unmet_limit_reason,
    "resolveReversibilityClass": lambda a, p, n: __import__("atlas_pca.policy_vm", fromlist=["x"]).resolve_reversibility_class(a, p, n),
    "agentCaveatContext": S.agent_caveat_context,
    "assembleThreshold": lambda s: __import__("atlas_pca.threshold", fromlist=["x"]).assemble_threshold(s),
    "isBudgetAllocCaveat": lambda c: __import__("atlas_pca.pca", fromlist=["x"]).is_budget_alloc_caveat(c),
    "meetAll": lambda ds: __import__("atlas_pca.decision", fromlist=["x"]).meet_all(ds),
    "escalateThreshold": lambda rt, m: __import__("atlas_pca.risk", fromlist=["x"]).escalate_threshold(rt, m),
    "detectorReceiptShapeError": lambda r: __import__("atlas_pca.dataflow", fromlist=["x"]).detector_receipt_shape_error(r),
    "detectorReceiptRef": lambda r: __import__("atlas_pca.dataflow", fromlist=["x"]).detector_receipt_ref(r),
    "detectorPolicyError": S.detector_policy_error,
    "detectorSignal": _detector_signal,
    "guardSeq": _guard_seq,
    "workflowCommitmentError": lambda w, p, n: SS.workflow_commitment_error(w, p, n),
    "workflowReceiptError": lambda b, r, rc, n: _workflow_receipt(b, r, rc, n),
    "collectObligations": _obligations,
    "verifyChainCheap": _chain,
    "holderPqKey": _holder_pq,
    "parseDiscoveryDocument": lambda d: __import__("atlas_pca.discovery", fromlist=["x"]).parse_discovery_document(d),
    "parseDiscoveryIntent": lambda d: __import__("atlas_pca.discovery", fromlist=["x"]).parse_discovery_intent(d),
    "acceptsSuite": lambda d, s: __import__("atlas_pca.discovery", fromlist=["x"]).accepts_suite(d, s),
    "buildDiscoveryDocument": _build_doc,
    "fetchDiscovery": _fetch,
    "verifyMembership": S.verify_membership,
    "validateRevocationStaleness": _validate_staleness,
    "isCanonicalCompactJws": _jws(),
    "isCanonicalCompactJwsOpaque": _jws(payload="any"),
    "isCanonicalCompactJwsMax": _jws(max_bytes=40),
    "isCanonicalCompactJwsFive": _jws(parts=5),
    "assertCanonicalJwsSegments": _jws_segments,
    "listTemplates": SS.list_templates,
    "fromTemplate": _from_template,
    "policyBuilder": _builder,
    "createLink": _link,
    "slotsDigest": SS.slots_digest,
    "linkDigest": lambda r: __import__("atlas_pca.policy_link", fromlist=["x"]).link_digest(r),
    "limits": _limits,
    "undoLifecycle": _undo_lifecycle,
    "undoStore": _undo_store,
    "catalogReversibilityScore": lambda: dict(S.CATALOG_REVERSIBILITY_SCORE),
    "catalogRisk": _risk,
    "spcExpectation": _spc,
    "cibaApprovalDetails": _ciba,
}
TOTALS = {"pcactnCheapClaims": 16, "goalCommitOf": 4, "verifyGoalCommit": 16, "dischargeRequests": 7, "namedUnmetLimitReason": 7,
          "resolveReversibilityClass": 8, "agentCaveatContext": 5, "assembleThreshold": 4, "isBudgetAllocCaveat": 8, "meetAll": 7,
          "escalateThreshold": 15, "detectorReceiptShapeError": 25, "detectorReceiptRef": 25, "detectorPolicyError": 18, "detectorSignal": 24,
          "guardSeq": 19, "workflowCommitmentError": 180, "workflowReceiptError": 171, "collectObligations": 18, "verifyChainCheap": 23,
          "holderPqKey": 9, "parseDiscoveryDocument": 32, "parseDiscoveryIntent": 15, "acceptsSuite": 3, "buildDiscoveryDocument": 5,
          "fetchDiscovery": 6, "verifyMembership": 135, "validateRevocationStaleness": 13, "isCanonicalCompactJws": 28, "isCanonicalCompactJwsOpaque":
          28, "isCanonicalCompactJwsMax": 28, "isCanonicalCompactJwsFive": 4, "assertCanonicalJwsSegments": 8, "listTemplates": 1, "fromTemplate": 11,
          "policyBuilder": 9, "createLink": 16, "slotsDigest": 8, "linkDigest": 2, "limits": 1, "undoLifecycle": 8, "undoStore": 6,
          "catalogReversibilityScore": 1, "catalogRisk": 110, "spcExpectation": 22, "cibaApprovalDetails": 4}


def _eq(g, o):
    g = norm(g)
    if isinstance(o, dict):
        if not isinstance(g, dict):
            return False
        g = {("toolSignatureDigest" if k == "tool_signature_digest" else k): v for k, v in g.items()}
        return set(g) == set(o) and all(_eq(g[k], o[k]) for k in o)
    if isinstance(o, list):
        return isinstance(g, (list, tuple)) and len(g) == len(o) and all(_eq(x, y) for x, y in zip(g, o))
    return canon(g) == canon(o)


def _same(got, out, _case):
    return _eq(got, out)


def _refused(got, case):
    return False


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 1113 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_core_small_surface_replay(fn):
    assert run(CASES[fn], HANDLERS[fn], compare=_same, refused=_refused) == (TOTALS[fn], 0)
