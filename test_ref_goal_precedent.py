"""Differential replay of the TypeScript reference (@atlasauth/pca-goal precedent): the hash-chained precedent log over principal-signed
escalation answers. The log is stateful, so it is driven through a step script exactly as the reference's generator drives it."""
import pytest

from atlas_pca import goal_examples as E
from atlas_pca import goal_precedent as P
from atlas_pca.ed25519 import allow_insecure_signer
from base_oracle import b64d, load_ref, run

COUNT, BY_FN = load_ref("goal-precedent")


@pytest.fixture(autouse=True, scope="module")
def _signer():
    allow_insecure_signer(True)
    yield
    allow_insecure_signer(False)


def _flow(goal, ont, grant, principals, steps):
    log = P.PrecedentLog(principals)
    space = E.build_space([goal])
    out = []
    for s in steps:
        op = s["op"]
        if op == "append":
            r = log.append(s["answer"], s["answered"], grant, space, s["now"])
            out.append({"ok": True, "digest": r["entry"]["digest"], "cell": r["entry"]["cell"], "seq": r["entry"]["seq"]} if r["ok"] else r)
        elif op == "revoke":
            r = log.revoke(s["rev"])
            out.append({"ok": True, "digest": r["entry"]["digest"], "seq": r["entry"]["seq"]} if r["ok"] else r)
        elif op == "verifyChain":
            out.append(log.verify_chain(space))
        elif op == "lookup":
            h = log.lookup(s["policyDigest"], space, s["case"], s["now"])
            out.append({"decision": h["decision"], "digest": h["entry"]["digest"]} if h else None)
        elif op == "authorize":
            a = P.authorize_with_precedents(goal, ont, s["policyDigest"], log, s["case"], s["now"])
            out.append(dict({"decision": a["decision"], "via": a["via"]}, **({"digest": a["precedent"]["digest"]} if a.get("precedent") else {})))
        elif op == "tamper":
            if s.get("del"):
                log.entries[s["index"]].pop(s["key"], None)
            else:
                log.entries[s["index"]][s["key"]] = s["value"]
            out.append(True)
        else:
            out.append(log.head())
    return out


FNS = {
    "flow": _flow, "ceilingsOf": P.ceilings_of, "answerBodyFor": P.answer_body_for,
    "signRevocationSeed": lambda p, seed: P.sign_revocation(p, b64d(seed)),
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
