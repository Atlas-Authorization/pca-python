"""Replays packages/pca/conformance/stateful-vectors.json: ordered presentations against ONE store (replay, counter ordering, revocation
mid-sequence, trust-budget depletion), the failed checks of every step compared with the reference. The reference runs requirePCA; here
`authorize` is the stateful guard, with the same server state (plan, risk inputs, revoked capability ids, the initial trust budget)."""
import json
import os

import pytest
from prov_harness import prov

from atlas_pca.authorize import MemoryStateStore, SqliteStateStore, authorize, state_key

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "conformance", "stateful-vectors.json"), os.path.join(_HERE, "conformance", "stateful-vectors.json")):
    if os.path.exists(_p):
        with open(_p, encoding="utf-8") as _f:
            DOC = json.load(_f)
        break
SEQS = DOC["stateful"]


def run_sequence(seq, store):
    setup = seq["setup"]
    grants = {g["id"]: g for g in setup["grants"]}
    revoked = set(setup.get("revoked") or [])
    if setup.get("initial_budget"):
        for s in seq["steps"]:
            if s["op"] != "present":
                continue
            chain = s["pcactn"].get("cap_chain") or []
            if s["pcactn"].get("grant_ref") in grants and chain and chain[-1].get("holder"):
                store.put_budget(state_key(s["pcactn"]["grant_ref"], chain[-1]["holder"], setup["audience"]), setup["initial_budget"])
    out = []
    for s in seq["steps"]:
        if s["op"] == "revoke":
            revoked.add(s["id"])
            out.append(None)
            continue
        p = json.loads(json.dumps(s["pcactn"]))
        op = {"verb": p["action"]["verb"], "resource": p["action"]["resource"], "params": s["params"]}
        r = authorize(p, operation=op, audience=setup["audience"], resolve_grant=lambda ref: grants.get(ref), state_store=store,
                      is_revoked=lambda pc, g: any(c.get("id") in revoked for c in (pc.get("cap_chain") or [])), now=s["now"],
                      context=lambda pc: {"plan": setup["plan_nodes"], "plan_authorized": True, "risk": dict(setup["risk"])},
                      seed_budget=(lambda g, now: None) if not setup.get("initial_budget") else "default", **prov(op))
        out.append({"allow": r.allow, "failed": sorted(n for n, st in r.checks.items() if st == "fail")})
    return out


def want(seq):
    return [st["expect"] if st["op"] == "present" else None for st in seq["steps"]]


@pytest.mark.parametrize("seq", SEQS, ids=[s["name"] for s in SEQS])
def test_stateful_sequences_on_the_memory_store(seq):
    assert run_sequence(seq, MemoryStateStore()) == want(seq)


@pytest.mark.parametrize("seq", SEQS, ids=[s["name"] for s in SEQS])
def test_stateful_sequences_on_the_sqlite_store(seq, tmp_path):
    assert run_sequence(seq, SqliteStateStore(str(tmp_path / "s.db"))) == want(seq)


def test_the_corpus_is_complete():
    assert DOC["counts"] == {"sequences": 20, "present_steps": 64, "revoke_steps": 5}
    assert len(SEQS) == 20
