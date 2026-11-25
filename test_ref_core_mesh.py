"""Differential oracles for the issuing side of the mesh (atlas_pca.mesh_witness): the domain's evidence, enroll and pin proofs
(ref-core-mesh-domain-java), proof assembly and action signing over scripted multi-domain sequences (ref-core-mesh-proof-java) and the
witness with its durable store (the `meshWitness` cases of ref-core-stores-java), all generated from the TypeScript reference."""
import hashlib

from atlas_pca.agent import keypair_from_seed
from atlas_pca.ledger_proofs import RevocationSet
from atlas_pca.mesh_witness import MemoryMeshWitnessStore, MeshDomain, MeshWitness
from atlas_pca.signers_more import assemble_mesh_proof, sign_mesh_action
from base_oracle import load_ref, run


def _key(label):
    return keypair_from_seed(hashlib.sha256(("atlas-pca-conformance/" + label).encode("utf-8")).digest(), allow_insecure_signer=True)


def _cap(label):
    return {"id": label, "issuer": "iss-" + label, "holder": "h", "caveats": [{"type": "scope", "actions": [label]}]}


def _err(e, by_message):
    return {"$err": str(e) if by_message else "Error"}


def _domain_script(ops, prefix):
    doms, ws, heads, binds, out = {}, {}, {}, {}, []
    for op in ops:
        try:
            k, v = op[0], None
            if k == "domain":
                d = MeshDomain(op[1], _key(prefix + str(op[2])))
                doms[op[1]], v = d, d.id
            elif k == "witness":
                w = MeshWitness(_key(prefix + str(op[2])))
                ws[op[1]], v = w, w.id
            elif k == "record":
                v = doms[op[1]].record(_cap(op[2]))
            elif k == "revoke":
                doms[op[1]].revoke(op[2])
            elif k == "publish":
                h = doms[op[1]].publish_head([ws[w] for w in op[4]], op[3], op[5])
                heads[op[2]], v = h, h
            elif k == "fork":
                heads[op[1]] = dict(heads[op[2]], **{op[3]: op[4]})
            elif k == "enroll":
                b = doms[op[1]].enroll(op[3], op[4])
                binds[op[2]], v = b, b
            elif k == "evidence":
                v = doms[op[1]].evidence(_cap(op[2]), heads[op[3]], binds.get(op[4]))
            elif k == "pinProof":
                v = doms[op[1]].pin_proof(heads[op[2]]["head"] if isinstance(op[2], str) else op[2], heads[op[3]])
            elif k == "nonMembership":
                if not isinstance(op[2], str):
                    raise TypeError("not a string")
                v = doms[op[1]].revocation_set_copy().non_membership_proof(op[2])
            else:
                raise ValueError("op")
            out.append(v)
        except Exception as e:  # noqa: BLE001 - the reference records a thrown error as {"$err"}
            out.append(_err(e, False))
    return out


def _proof_script(ops):
    doms, ws, store, out = {}, {}, {}, []
    for op in ops:
        try:
            k, v = op[0], None
            if k == "domain":
                d = MeshDomain(op[1], _key("mesh-proof/" + str(op[2])))
                doms[op[1]], v = d, d.id
            elif k == "witness":
                w = MeshWitness(_key("mesh-proof/" + str(op[2])))
                ws[op[1]], v = w, w.id
            elif k == "record":
                v = doms[op[1]].record(_cap(op[2]))
            elif k == "revoke":
                doms[op[1]].revoke(op[2])
            elif k == "publish":
                h = doms[op[1]].publish_head([ws[w] for w in op[4]], op[3], op[5])
                store[op[2]], v = h, h
            elif k == "subcos":
                h = dict(store[op[2]])
                h["cosigs"] = [h["cosigs"][int(i)] for i in op[3]]
                store[op[1]] = h
            elif k == "fork":
                store[op[1]] = dict(store[op[2]], **{op[3]: op[4]})
            elif k == "forkHead":
                h = dict(store[op[2]])
                h["head"] = dict(h["head"], **{op[3]: op[4]})
                store[op[1]] = h
            elif k == "enroll":
                b = doms[op[1]].enroll(op[3], op[4])
                store[op[2]], v = b, b
            elif k == "ev":
                e = doms[op[1]].evidence(_cap(op[3]), store[op[4]], store.get(op[5]))
                store[op[2]], v = e, e
            elif k == "setEv":
                e, val = dict(store[op[2]]), op[4]
                if isinstance(val, dict) and "$del" in val:
                    e.pop(op[3], None)
                elif op[3] == "head" and isinstance(val, str) and val in store:
                    e["head"] = store[val]
                else:
                    e[op[3]] = val
                store[op[1]] = e
            elif k == "pinProofAs":
                pin = op[3]
                p = doms[op[1]].pin_proof(store[pin]["head"] if isinstance(pin, str) else pin, store[op[4]])
                store[op[2]], v = p, p
            elif k == "assemble":
                pins = None if op[5] is None else [store[n] for n in op[5]]
                v = assemble_mesh_proof([_cap(x) for x in op[1]], [store[n] for n in op[2]], op[3], _key("mesh-proof/" + str(op[4])), pins)
            elif k == "sign":
                v = sign_mesh_action([_cap(x) for x in op[1]], op[2], _key("mesh-proof/" + str(op[3])))
            else:
                raise ValueError("op")
            out.append(v)
        except Exception as e:  # noqa: BLE001
            out.append(_err(e, False))
    return out


def _witness_script(ops):
    stores, ws, doms, out = {}, {}, {}, []
    for op in ops:
        try:
            k, v = op[0], None
            if k == "store":
                stores[op[1]], v = MemoryMeshWitnessStore(), True
            elif k == "witness":
                w = MeshWitness(_key(op[3]), store=None if op[2] is None else stores[op[2]])
                ws[op[1]], v = w, w.id
            elif k == "witnessClock":
                now = float(op[3])
                ws[op[1]], v = MeshWitness(_key(op[2]), clock=lambda now=now: now, max_clock_skew_ms=None if op[4] is None else float(op[4])), True
            elif k == "restart":
                w = MeshWitness(_key(op[3]), store=stores[op[2]])
                ws[op[1]], v = w, w.export_state()
            elif k == "domain":
                d = MeshDomain(op[1], _key(op[2]))
                doms[op[1]], v = d, d.id
            elif k == "record":
                v = doms[op[1]].record({"id": op[2], "caveats": [{"type": "scope", "actions": [op[2]]}]})
            elif k == "revoke":
                doms[op[1]].revoke(op[2])
            elif k == "publish":
                v = doms[op[1]].publish_head([ws[w] for w in op[3]], op[2], op[4])
            elif k == "lastSeen":
                v = ws[op[1]].last_seen(op[2])
            elif k == "export":
                v = ws[op[1]].export_state()
            elif k == "import":
                ws[op[1]].import_state(op[2])
            elif k == "load":
                v = stores[op[1]].load()
            elif k == "save":
                stores[op[1]].save(op[2])
            elif k == "domainId":
                v = doms[op[1]].id
            else:
                raise ValueError("op")
            out.append(v)
        except Exception as e:  # noqa: BLE001
            out.append(_err(e, True))
    return out


_DOMAIN = load_ref("core-mesh-domain-java")[1]
_PROOF = load_ref("core-mesh-proof-java")[1]
_STORES = load_ref("core-stores-java")[1]


def test_mesh_domain_matches_the_reference():
    ran, _ = run(_DOMAIN["meshDomain"], lambda ops: _domain_script(ops, "mesh-domain/"))
    assert ran == len(_DOMAIN["meshDomain"])


def test_mesh_proof_assembly_matches_the_reference():
    ran, _ = run(_PROOF["meshProof"], _proof_script)
    assert ran == len(_PROOF["meshProof"])


def test_mesh_witness_matches_the_reference():
    ran, _ = run(_STORES["meshWitness"], _witness_script)
    assert ran == len(_STORES["meshWitness"])


def test_non_membership_proofs_verify():
    from atlas_pca.intent_v2 import verify_non_membership
    s = RevocationSet(["b", "d", "f", "h", "j"])
    for rid in ["a", "c", "e", "g", "i", "k", "", "key:x"]:
        assert verify_non_membership(s.root, s.non_membership_proof(rid), rid), rid
    for rid in ["b", "d", "j"]:
        try:
            s.non_membership_proof(rid)
            raise AssertionError("a revoked id has no non-membership proof")
        except ValueError:
            pass
    assert RevocationSet().non_membership_proof("a")["size"] == 0
