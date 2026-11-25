"""Replays the TS-reference oracle of the mesh issuing side and the federation primitives (testdata/ref-mesh-issue.json.gz, 787 cases): the
worked example and the fork demonstration, size and latency models, domain / witness lifecycle scripts, cross-domain capability translation,
the federated budget tree and cross-reference commitments. Every fn has a handler and the total is asserted. A secret is {"$seed": label} =
sha256("atlas-pca-conformance/" + label) (script op labels carry the prefix "mesh-issue/d/" or "mesh-issue/w/"); a reference throw is a
native raise; in a script a refused op is {"$err"} on both sides (the text is informative). There is no intended difference."""
import hashlib
import os

import pytest

from atlas_pca import mesh as M
from atlas_pca import mesh_witness as W
from atlas_pca.agent import KeyPair
from base_oracle import HERE, b64d, canon, load

COUNT, CASES = load("mesh-issue", os.path.join(HERE, "testdata", "ref-mesh-issue.json.gz"))
DEVIATIONS = {}  # none: the options object of verifyTranslatedCapability goes through `options=` (a null one is refused, as in the reference)


def _kp(seed32):
    return KeyPair(seed32, allow_insecure_signer=True)  # corpus keys are public labels


def _seed(label):
    return _kp(hashlib.sha256(("atlas-pca-conformance/" + label).encode("utf-8")).digest())


def _secret(v):
    return _kp(b64d(v))  # the loader turned {"$seed": label} into base64url of the seed


def _d(v):
    return v if isinstance(v, dict) else {}


def _example(now):
    ex = W.build_mesh_example() if now is None else W.build_mesh_example(now)
    return {"trust": ex["trust"], "proof": ex["proof"], "evidence": ex["evidence"], "chain": ex["chain"], "heads": ex["heads"],
            "bindings": ex["bindings"], "domains": {k: d.id for k, d in ex["domains"].items()}, "witnesses": [w.id for w in ex["witnesses"]]}


def _translate(chain, a):
    return W.translate_capability(chain, a.get("fromGuardian"), a.get("toGuardian"), _secret(a.get("bridgeSecret")), a.get("issued_at"),
                                  a["additionalCaveats"] if "additionalCaveats" in a else (), a.get("pqPins"))


_VERIFY_KW = {"fromGuardian": "from_guardian", "toGuardian": "to_guardian", "bridge": "bridge", "rootIssuer": "root_issuer", "now": "now", "pqPins": "pq_pins"}


def _verify_translated(tc, *opts):
    if opts and not isinstance(opts[0], dict):
        return W.verify_translated_capability(tc, options=opts[0])  # null is refused; a string or an array carries no member
    return W.verify_translated_capability(tc, **{_VERIFY_KW[k]: v for k, v in (opts[0] if opts else {}).items()})


class _FailingStore:
    def __init__(self, fail_after):
        self._inner, self._saves, self._fail_after = W.MemoryMeshWitnessStore(), 0, fail_after

    def load(self):
        return self._inner.load()

    def save(self, state):
        self._saves += 1
        if self._saves > self._fail_after:
            raise RuntimeError("disk")
        self._inner.save(state)


def _cap(label):
    return {"id": label, "issuer": "iss-%s" % label, "holder": "h", "caveats": [{"type": "scope", "actions": [label]}]}


def _script(ops):
    doms, ws, heads, binds, stores, out = {}, {}, {}, {}, {}, []

    def get(m, k):
        if k not in m:
            raise KeyError("unknown name %s" % k)
        return m[k]

    def one(op):
        kind = op[0]
        if kind == "domain":
            doms[op[1]] = W.MeshDomain(op[1], _seed("mesh-issue/d/" + op[2]))
            return doms[op[1]].id
        if kind == "witness":
            ws[op[1]] = W.MeshWitness(_seed("mesh-issue/w/" + op[2]))
            return ws[op[1]].id
        if kind == "witnessOpts":
            x, kw = op[3] if op[3] is not None else {}, {}
            if x.get("store"):
                kw["store"] = get(stores, x["store"])
            if x.get("clock") is not None:
                kw["clock"] = lambda: x["clock"]
            if x.get("skew") is not None:
                kw["max_clock_skew_ms"] = x["skew"]
            ws[op[1]] = W.MeshWitness(_seed("mesh-issue/w/" + op[2]), **kw)
            return ws[op[1]].id
        if kind == "store":
            stores[op[1]] = W.MemoryMeshWitnessStore()
            return True
        if kind == "failStore":
            stores[op[1]] = _FailingStore(op[2])
            return True
        if kind == "storeLoad":
            return get(stores, op[1]).load()
        if kind == "record":
            return get(doms, op[1]).record(_cap(op[2]))
        if kind == "revoke":
            get(doms, op[1]).revoke(op[2])
            return None
        if kind == "publish":
            heads[op[2]] = get(doms, op[1]).publish_head([get(ws, w) for w in op[4]], op[3], threshold=op[5])
            return heads[op[2]]
        if kind == "fork":
            heads[op[1]] = {**get(heads, op[2]), op[3]: op[4]}
            return None
        if kind == "forkHead":
            h = get(heads, op[2])
            heads[op[1]] = {**h, "head": {**h["head"], op[3]: op[4]}}
            return None
        if kind == "cosign":
            w, h = get(ws, op[1]), get(heads, op[2])
            hd = _d(h.get("head"))
            d = next((x for x in doms.values() if x.id == hd.get("domain")), None)
            if d is None:
                raise KeyError("no such domain")
            consistency = op[3]
            if op[3] == "domain":
                prev = w.last_seen(hd["domain"])
                consistency = d.consistency_proof(prev["size"], hd["size"]) if prev else None
            req = {"head": h, "rev_ids": d.revocation_set_copy().list() if op[4] == "domain" else op[4]}
            if consistency:
                req["consistency"] = consistency
            return w.cosign(req)
        if kind == "lastSeen":
            return get(ws, op[1]).last_seen(doms[op[2]].id if op[2] in doms else op[2])
        if kind == "export":
            return get(ws, op[1]).export_state()
        if kind == "import":
            get(ws, op[1]).import_state(get(ws, op[2]["$export"]).export_state() if isinstance(op[2], dict) and "$export" in op[2] else op[2])
            return None
        if kind == "restart":
            ws[op[1]] = W.MeshWitness(_seed("mesh-issue/w/" + op[3]), store=get(stores, op[2]))
            return ws[op[1]].export_state()
        if kind == "consistency":
            return get(doms, op[1]).consistency_proof(op[2]) if op[3] is None else get(doms, op[1]).consistency_proof(op[2], op[3])
        if kind == "enroll":
            binds[op[2]] = get(doms, op[1]).enroll(op[3], op[4])
            return binds[op[2]]
        if kind == "evidence":
            return get(doms, op[1]).evidence(_cap(op[2]), get(heads, op[3]), None if op[4] is None else get(binds, op[4]))
        raise ValueError("op")

    for op in ops:
        try:
            out.append(one(op))
        except Exception as e:  # noqa: BLE001 - a refused op is part of the script's result
            out.append({"$err": str(e)})
    return out


def _budget(a):
    a = _d(a)
    return W.create_federated_budget(a.get("rootId"), a.get("rootDomain"), a.get("B0"), a.get("kappa"), a.get("bMax"))


def _allocate(state, a):
    a = _d(a)
    return W.allocate_sub(state, a.get("id"), a.get("domain"), a.get("parent"), a.get("alloc"))


HANDLERS = {
    "constants": lambda: {"DEFAULT_MAX_HEAD_AGE_MS": M.DEFAULT_MAX_HEAD_AGE_MS, "DEFAULT_MAX_CLOCK_SKEW_MS": M.DEFAULT_MAX_CLOCK_SKEW_MS,
                          "DEFAULT_MAX_CHAIN_LENGTH": M.DEFAULT_MAX_CHAIN_LENGTH},
    "keyRevocationId": W.key_revocation_id,
    "effectiveAuthority": M.effective_authority,
    "buildMeshExample": _example,
    "demonstrateForkRejection": W.demonstrate_fork_rejection,
    "meshProofSize": M.mesh_proof_size,
    "revocationLatencyBound": M.revocation_latency_bound,
    "meshIssue": _script,
    "translateCapability": _translate,
    "verifyTranslatedCapability": _verify_translated,
    "translatedEffectiveAuthority": W.translated_effective_authority,
    "createFederatedBudget": _budget,
    "allocateSub": _allocate,
    "spendFederated": W.spend_federated,
    "federatedSafetyBound": W.federated_safety_bound,
    "meshActionDigest": W.mesh_action_digest,
    "crossReferenceCommit": W.cross_reference_commit,
    "anchorCrossReference": lambda secret, commit, seq: W.anchor_cross_reference(_secret(secret), commit, seq),
    "verifyCrossReference": W.verify_cross_reference,
}


def _errs(v):
    """A script result with every refusal text removed: both sides must refuse the same ops."""
    return [{"$err": True} if isinstance(x, dict) and set(x) == {"$err"} else x for x in v] if isinstance(v, list) else v


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 787 and set(CASES) == set(HANDLERS)
    assert set(DEVIATIONS) <= {c["name"] for cs in CASES.values() for c in cs}


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_mesh_issue_replay(fn):
    bad = []
    for c in CASES[fn]:
        out = {"$throws": DEVIATIONS[c["name"]]} if c["name"] in DEVIATIONS else c["out"]
        threw = isinstance(out, dict) and "$throws" in out
        try:
            got = HANDLERS[fn](*c["args"])
        except Exception as e:  # noqa: BLE001 - a native refusal, compared against the reference
            if not threw:
                bad.append("%s\n    native raised %s: %s\n    ref:    %s" % (c["name"], type(e).__name__, e, canon(out)[:300]))
            continue
        if threw or canon(_errs(got)) != canon(_errs(out)):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:400], canon(out)[:400]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))


def test_the_worked_example_verifies_and_a_tampered_one_does_not():
    ex = W.build_mesh_example()
    assert M.verify_mesh_proof(ex["proof"], ex["trust"]).ok is True
    assert M.verify_mesh_proof(ex["proof"], {**ex["trust"], "humanPrincipal": ex["keys"]["leaf"].public}).ok is False
