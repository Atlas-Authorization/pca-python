"""Action-kit conformance: every vector of packages/pca-conformance/vectors/actions (mirror: conformance/actions) must reproduce its
`expect` byte for byte through atlas_pca.actions (and the v2 conform path of atlas_pca.intent_v2). No skips, no vector left unread."""
import json
import os
import unittest

from atlas_pca import actions as A
from atlas_pca import actions_registry as R
from atlas_pca import approval as AP
from atlas_pca.escalation import verify_escalation_answer
from atlas_pca.intent_v2 import action_schema_shape_error, conform_action

HERE = os.path.dirname(os.path.abspath(__file__))


def _vector_dir():
    for rel in (("..", "..", "packages", "pca-conformance", "vectors", "actions"), ("conformance", "actions"), ("..", "conformance", "actions")):
        d = os.path.join(HERE, *rel)
        if os.path.isdir(d):
            return d
    raise FileNotFoundError("the action-kit vectors are missing (a vector directory is never skipped)")


def _cases():
    d = _vector_dir()
    out = []
    for f in sorted(os.listdir(d)):
        if f.endswith(".json"):
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                out.append(json.load(fh))
    return out


def _code_of(e):
    return {"ok": True} if e is None else {"ok": False, "code": e.split(":")[0].split(" ")[0]}


def replay(c):
    i, k = c["input"], c["kind"]
    if k == "parse":
        return {"ok": A.validate_def(i["def"]) is None}
    if k == "digest":
        return {"digest": A.def_digest(i["def"]), "normalized": A.normalize(i["def"])}
    if k == "effective":
        e = A.effective(i["def"], A.CORE_REGISTRY, i.get("pins"))
        return {"confirmed": e["confirmed"], "traits": e["traits"], "closure": e["closure"], "eff": e["eff"]}
    if k in ("expand", "schema_verb"):
        try:
            reg = A.extend_registry(A.CORE_REGISTRY, i["custom_traits"]) if i.get("custom_traits") else A.CORE_REGISTRY
            if k == "expand":
                return {"closure": A.closure(reg, i["traits"]), "floor": A.floor_of(reg, i["traits"])}
            return _code_of(A.schema_verb_floor_error(i["verb"], reg, i.get("pins")))
        except A.ActionKitError:
            return {"error": True}
    if k == "floor":
        return {"decision": A.floor_decision(i["grant"], i["call"], i["profile"])}
    if k == "conform":
        r = conform_action(i["schema"], i["verb"], i["params"])
        return {"ok": True} if r["ok"] else {"ok": False, "code": r["code"]}
    if k == "pack":
        ds = i["digests"]
        return {"root": A.pack_root(ds), "proof": A.pack_proof(ds, ds[i["index"]])}
    if k == "rule22_schema":
        return R.rule22_integrity(i["doc"], i.get("pins"))
    if k == "schema_shape":
        return {"ok": action_schema_shape_error(i["doc"], False) is None}
    if k == "rule22":
        g = R.rule22_integrity(i["doc"], i.get("pins"))
        if not g["ok"]:
            return {"integrity": g["code"], "decision": "deny"}
        return {"integrity": "ok", "decision": R.rule22_decide(i["doc"], i["verb"], i["grant"], i["context"])}
    if k == "pack_verify":
        v = R.verify_pack(i["pack"], i["keys"], i.get("shards"))
        return {"ok": True, "digest": v["digest"], "defs": len(v["defs"])} if v["ok"] else {"ok": False}
    if k == "evolution_verify":
        try:
            d = R.evolution_diff_digest(i["record"])
        except Exception:
            d = None
        return {"ok": R.verify_evolution_record(i["record"], i["keys"])["ok"], "diff": d}
    if k == "reapproval_verify":
        return {"ok": R.reapproval_valid(i["reapproval"], i["grant"]["id"], i["grant"]["issuer"], i["verb"], i["diff"])}
    if k == "pin":
        d = R.decide_pin(i)
        if d["ok"]:
            return {"ok": True, "via": d["via"]}
        o = {"ok": False, "code": d["code"], "escalate": d["escalate"]}
        if "needs_reapproval" in d:
            o["needs_reapproval"] = d["needs_reapproval"]
        return o
    if k == "pack_proof_verify":
        return {"ok": R.verify_pack_proof(i["root"], i["proof"], i["digest"])}
    if k == "tracker":
        t = R.PackTracker(i["keys"])
        out = []
        for st in i["steps"]:
            r = t.accept(st["pack"], st.get("shards"))
            out.append({"ok": True, "status": r["status"]} if r["ok"] else {"ok": False, "code": r["code"]})
        return out
    if k == "approval_render":
        try:
            r = AP.render_approval(i["def"], i["params"], i["confirmed"] is True)
            d = AP.approval_render_digest(r)
            return {"ok": True, "render": r, "digest": d, "words": AP.binding_words(d)}
        except A.ActionKitError as e:
            return {"ok": False, "code": e.code}
    if k == "approval_digest":
        if AP.approval_render_shape_error(i["render"]) is not None:
            return {"ok": False}
        return {"ok": True, "digest": AP.approval_render_digest(i["render"])}
    if k == "approval_challenge":
        try:
            return {"ok": True, "challenge": AP.approval_challenge(i["action_digest"], i["render_digest"])}
        except ValueError:
            return {"ok": False}
    if k == "approval_escalation":
        v = verify_escalation_answer(i["answer"], i["principals"], i["bind"], i["now"])
        return {"ok": True, "decision": v["decision"]} if v["ok"] else {"ok": False, "reason": v["reason"]}
    if k == "approval_psd2":
        try:
            return {"ok": True, "linking": AP.psd2_linking(i["render"])}
        except A.ActionKitError as e:
            return {"ok": False, "code": e.code}
    if k == "approval_batch":
        try:
            b = AP.approval_batch(i["items"])
            return {"ok": True, "batch": b["batch"], "action_digest": b["action_digest"], "render_digest": b["render_digest"], "challenge": b["challenge"], "words": b["words"]}
        except A.ActionKitError as e:
            return {"ok": False, "code": e.code}
    raise AssertionError("unknown vector kind " + k)


class ActionVectors(unittest.TestCase):
    def test_every_vector_replays(self):
        cases = _cases()
        self.assertGreaterEqual(len(cases), 400)
        kinds = {}
        for c in cases:
            kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
            self.assertEqual(replay(c), c["expect"], c["id"])
        for k in ("parse", "digest", "effective", "expand", "floor", "conform", "pack", "schema_verb", "rule22", "rule22_schema", "pack_verify", "evolution_verify", "reapproval_verify", "pin", "pack_proof_verify", "tracker", "schema_shape", "approval_render", "approval_digest", "approval_escalation"):
            self.assertGreaterEqual(kinds.get(k, 0), 8, k)

    def test_approval_profile_vectors(self):
        d = os.path.join(os.path.dirname(_vector_dir()), "approval-profiles")
        if not os.path.isdir(d):
            d = os.path.join(HERE, "conformance", "approval-profiles")
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
        self.assertGreaterEqual(len(files), 12)
        for f in files:
            with open(os.path.join(d, f), encoding="utf-8") as fh:
                c = json.load(fh)
            self.assertEqual(replay(c), c["expect"], c["id"])

    def test_pinned_values(self):
        self.assertEqual(A.traits_digest(A.CORE_REGISTRY), "W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM")
        self.assertEqual(A.tables_digest(), "I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU")

    def test_pack_proof_verifies_and_tamper_fails(self):
        from atlas_pca.pca import verify_inclusion
        c = next(x for x in _cases() if x["id"] == "pack-builtin")
        ds = c["input"]["digests"]
        root = c["expect"]["root"]
        for d in ds:
            self.assertTrue(verify_inclusion(root, A.pack_proof(ds, d), A._leaf(d)))
        self.assertFalse(verify_inclusion(root, A.pack_proof(ds, ds[0]), A._leaf(ds[1])))

    def test_whole_document_rule_22(self):
        c = next(x for x in _cases() if x["id"] == "schema-verb-adv-honest")
        doc = {"verbs": [c["input"]["verb"]]}
        self.assertIsNone(A.schema_floor_error(doc, c["input"].get("pins")))
        doc["traits_digest"] = "A" * 43
        self.assertTrue(A.schema_floor_error(doc, c["input"].get("pins")).startswith("traits_digest_mismatch"))


if __name__ == "__main__":
    unittest.main()
