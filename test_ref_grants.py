"""Differential replay of the TypeScript reference (@atlasauth/pca-grants): signing, bundles, decision log and replay, shadow rollout,
list-authorized, the grant service and its HTTP binding, lease HTTP and renewal, blueprint group kill and admission, freshness helpers.

Stateful cases are scenarios (spec in, JSON out) driven here exactly as the reference's generator drives them. A secret key is a label;
its seed is sha256("atlas-pca-conformance/" + label). In scenario specs "$key:LABEL" stands for that key's public key and
{"$sign": {kind, label, fields}} for the signed record."""
import hashlib
import json

import pytest

from atlas_pca import grants as G
from atlas_pca import grants_list as L
from atlas_pca import grants_service as GS
from atlas_pca import grants_shadow as S
from atlas_pca import k3 as K
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.blueprint import BlueprintRegistry, MemoryBlueprintStore
from atlas_pca.ed25519 import allow_insecure_signer
from atlas_pca.lease import LeaseRegistry, check_lease
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("grants")
T0 = 1_800_000_000_000
_PUB = {}


@pytest.fixture(autouse=True, scope="module")
def _signer():
    allow_insecure_signer(True)
    yield
    allow_insecure_signer(False)


def sk(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode("utf-8")).digest()


def pub(label):
    if label not in _PUB:
        _PUB[label] = G.signer_of(sk(label))
    return _PUB[label]


_SIGNERS = {"lease": G.sign_lease, "leaseOver": G.sign_lease_unsafe_over_cap, "revocation": G.sign_lease_revocation,
            "blueprint": G.sign_blueprint, "breakglass": G.sign_break_glass, "review": G.sign_break_glass_review}


def resolve(v):
    if isinstance(v, str):
        return pub(v[5:]) if v.startswith("$key:") else v
    if isinstance(v, list):
        return [resolve(x) for x in v]
    if isinstance(v, dict):
        if "$sign" in v:
            s = v["$sign"]
            return _SIGNERS[s["kind"]](sk(s["label"]), resolve(s["fields"]))
        return {k: resolve(x) for k, x in v.items()}
    return v


def err_code(e):
    c = getattr(e, "code", None)
    return {"$err": c if isinstance(c, str) else "x"}


def strip_none(v):
    """The reference's JSON round trip drops an undefined member."""
    if isinstance(v, list):
        return [strip_none(x) for x in v]
    if isinstance(v, dict):
        return {k: strip_none(x) for k, x in v.items() if x is not None}
    return v


# ---- scenarios ------------------------------------------------------------------------------------------------------------

def log_scenario(spec):
    log = G.DecisionLog(sk(spec["label"]), spec.get("mask") or [])
    recs = [log.append(r) for r in spec["records"]]
    signer = pub(spec["label"])
    head = log.head(spec["now"])
    out = {"recs": recs, "head": head, "size": log.size}
    proofs = []
    for i in spec.get("proofs") or []:
        try:
            proofs.append(log.proof(i))
        except Exception:  # noqa: BLE001
            proofs.append({"$err": True})
    out["proofs"] = proofs
    out["incl"] = [{"$err": True} if p.get("$err") else K.verify_record_inclusion(recs[i], p, head, signer)
                   for i, p in zip(spec.get("proofs") or [], proofs)]
    batches = []
    for b in spec.get("batches") or []:
        try:
            bt = G.next_batch(log, b["from"], b["max"], spec["now"])
            st = {"next": b["from"], "lastCommit": "" if b["from"] == 0 else K.record_commit(recs[b["from"] - 1])}
            tampered = {**bt, "records": [{**bt["records"][0], "at": 1}, *bt["records"][1:]]} if bt["records"] else bt
            batches.append({"bt": bt, "verdict": K.verify_batch(bt, st, signer), "tampered": K.verify_batch(tampered, st, signer),
                            "wrong": K.verify_batch(bt, st, pub("zz"))})
        except Exception:  # noqa: BLE001
            batches.append({"$err": True})
    out["batches"] = batches
    return out


def replay_scenario(spec):
    def dec(t):
        return lambda i: t.get(i)
    diff = G.semantic_diff(spec["cases"], dec(spec["oldT"]), dec(spec["newT"]))
    audit = G.audit_replay(spec["records"], spec["cases"], lambda i, rev: spec["revT"].get("%s@%s" % (i, rev)))
    return {"diff": strip_none(diff), "audit": audit}


def fresh_scenario(spec):
    iss = G.FreshAtIssuer(sk(spec["label"]), spec["scope"], spec["init"])
    out, last = [], None
    for s in spec["steps"]:
        try:
            if s["op"] == "advance":
                last = iss.advance(s["patch"], s["now"])
                out.append(last)
            elif s["op"] == "check":
                out.append(iss.check(last if s["token"] == "last" else s["token"], s["now"], s.get("maxAge")))
            elif s["op"] == "current":
                out.append(iss.current)
            elif s["op"] == "tamper":
                out.append(iss.check({**last, "policy_revision": last["policy_revision"] + 1}, s["now"]))
        except Exception:  # noqa: BLE001
            out.append({"$err": True})
    return out


def shadow_scenario(spec):
    log = S.ShadowLog(sk(spec["label"]))

    def T(t):
        def f(i):
            d = t.get(i)
            if d == "throw":
                raise RuntimeError("boom")
            return "weird" if d == "junk" else d
        return f

    out = {"runs": [], "diffs": {}}
    for ob in spec["obs"]:
        r = S.run_shadow(ob["input"], T(spec["enforcedT"]), [{"digest": c["digest"], "decide": T(c["T"])} for c in spec["cands"]])
        out["runs"].append({"decision": r["decision"], "shadow": r["shadow"]})
        for oc in r["shadow"]:
            log.observe(spec["enforcedDigest"], ob["action_digest"], r["decision"], oc, ob["at"])
    out["stats"] = {c["digest"]: log.stats(c["digest"]) for c in spec["cands"]}
    for c in spec["cands"]:
        out["diffs"][c["digest"]] = log.diffs(c["digest"])
    vsd = S.verify_shadow_diff
    out["verify"] = [[vsd(d, log.signer), vsd(d), vsd(d, pub("zz")), vsd({**d, "sig": d["sig"][1:] + "A"}, log.signer), vsd({**d, "at": d["at"] + 1})]
                     for ds in out["diffs"].values() for d in ds]
    out["signer"] = log.signer
    g = spec.get("gate")
    if g:
        principals = [pub(p) for p in g.get("principals") or []]
        explanations = [S.sign_widening_explanation(sk(e["label"]), {"shadow_digest": e["shadow_digest"], "action_digest": e["action_digest"],
                                                                     "reason_digest": e["reason_digest"]}) for e in g.get("explain") or []]
        approval = None
        if g.get("approval"):
            a = g["approval"]
            approval = S.sign_promotion_approval(sk(a["label"]), {"shadow_digest": a["shadow_digest"], "enforced_digest": a["enforced_digest"], "at": a["at"]})
        out["explanations"] = explanations
        out["approval"] = approval
        opts = g.get("options") or {}
        o = {**opts, "principals": opts["principals"] if opts.get("principals") is not None else principals,
             "explanations": opts["explanations"] if opts.get("explanations") is not None else explanations}
        if approval is not None:
            o["approval"] = approval
        out["gate"] = S.promotion_gate(log, o)
        p = spec.get("promote")
        if p:
            try:
                gate = {"ok": False, "code": "bad_input", "reason": "x"} if p.get("useGate") is False else out["gate"]
                out["promoted"] = S.promote_shadow(p["enforced"], p["candidate"], gate, p["now"])
            except Exception:  # noqa: BLE001
                out["promoted"] = {"$err": True}
    return out


def list_scenario(spec):
    acc = L.WindowReadAccumulator(spec["cap"], spec["windowMs"])
    universe = spec["universe"]

    def page_of(lst, q):
        idx = 0 if "cursor" not in q else int(q["cursor"])
        objects = lst[idx: idx + q["limit"] + (3 if spec.get("overfetch") else 0)]
        out = {"objects": objects}
        if idx + q["limit"] < len(lst):
            out["next"] = str(idx + q["limit"])
        elif spec.get("emptyNext"):
            out["next"] = ""
        return out

    class Cand:
        def page(self, q):
            return page_of(universe, q)

    rs = spec.get("relation")
    allowed = set((rs or {}).get("allowed") or [])

    class Rel:
        def check(self, q):
            return q["object"] in allowed

    rel = Rel()
    if rs and rs.get("useList"):
        rel.list_objects = lambda q: page_of(rs["listed"] if rs.get("listed") is not None else universe, q)
    permitted = set(spec["permitted"]) if spec.get("permitted") is not None else None
    out, cursor = [], None
    for p in range(spec["pages"]):
        t = spec["tamper"] if spec.get("tamper") and p == spec["tamper"]["page"] else None

        def tg(k, d):
            return t[k] if t and k in t else d

        try:
            cands = L.candidates_from_relation(rel, spec["subject"], rs["name"]) if rs and rs.get("asCandidates") else Cand()
            page = {"limit": tg("limit", spec["limit"])}
            if not (t and t.get("dropCursor")) and cursor is not None:
                page["cursor"] = tg("cursor", cursor)
            kw = {}
            if spec.get("maxScan") is not None:
                kw["max_scan"] = spec["maxScan"]
            if rs:
                kw["relation"] = {"source": rel, "relation": tg("relation", rs["name"])}
            r = L.list_authorized(subject=tg("subject", spec["subject"]), resource_type=spec["type"], permits=lambda x: permitted is None or x in permitted,
                                  candidates=cands, filter_id=tg("filterId", spec["filterId"]), policy_digest=spec["policyDigest"],
                                  fresh_at_digest=spec["freshAt"], page=page, reads=acc, now=T0 + p * (spec.get("nowStep") if spec.get("nowStep") is not None else 1),
                                  signing_secret=sk(tg("label", spec["label"])), **kw)
            out.append(r)
            cursor = r.get("next_cursor")
        except Exception as e:  # noqa: BLE001
            out.append({"$err": getattr(e, "code", None) or "x"})
            if not t:
                break
    return out


def window_acc(cap, win, ops):
    a = L.WindowReadAccumulator(cap, win)
    return [a.charge(x["key"], x["units"], x["now"]) for x in ops]


def grant_scenario(spec):
    store = GS.MemoryGrantStore()
    events = []
    ctr = {"grant": 0, "need": 0}

    def new_id(kind):
        ctr[kind] += 1
        return ("g_%d" if kind == "grant" else "n_%d") % ctr[kind]

    providers = {"usage": lambda g: {"rev": g["rev"]}, "remaining_budget": lambda g: {"left": 5}, "residual": lambda g: {"id": g["id"]}} if spec.get("providers") else None
    svc = GS.GrantService(
        store, lambda: T0, new_id, providers=providers,
        verify_step_up=(lambda ref, g: ref == "ok-step") if spec.get("stepUp") else None,
        on_revoke=lambda ids, scope, root: events.append({"revoked": ids, "scope": scope, "root": root["id"]}),
        on_change=lambda kind, g: events.append({"change": kind, "id": g["id"], "rev": g["rev"]}),
        validate_need=(lambda nd: "verb not allowed" if nd.get("verb") == "forbidden" else None) if spec.get("validateNeed") else None)
    handler = GS.grant_resource_handler(svc, lambda req: req.get("who"))

    def sec(by):
        return {"principal": sk("$P"), "holder": sk("$A"), "wrongkey": sk("$X")}[by]

    out = []
    for raw in spec["steps"]:
        s = resolve(raw)
        try:
            op = s["op"]
            if op == "register":
                r = svc.register(s["grant"])
            elif op == "list":
                r = svc.list(s.get("filter") or {})
            elif op == "inspect":
                r = svc.inspect(s["id"])
            elif op == "amend":
                g = svc.inspect(s["id"])
                req = {"action": s["action"], "authority": s["authority"]}
                if s["by"] != "none":
                    req["signed_by"] = s.get("signed_by") or ("holder" if s["by"] == "holder" else "principal")
                    req["sig"] = GS.sign_grant_body(K.GRANT_AMEND_DOMAIN, K.amend_message(g, s["action"], s["authority"]), sec(s["by"]))
                if s.get("stepUp"):
                    req["step_up_ref"] = s["stepUp"]
                r = svc.amend(s["id"], req)
            elif op == "revoke":
                g = svc.inspect(s["id"])
                auth = {"admin": True} if s["by"] == "admin" else {} if s["by"] == "noauth" else \
                    {"sig": GS.sign_grant_body(K.GRANT_REVOKE_DOMAIN, K.grant_revoke_message(g["id"], s["scope"]), sec(s["by"]))}
                r = svc.revoke(s["id"], s["scope"], auth)
            elif op == "needs":
                r = svc.request_needs(s["id"], s["needs"])
            elif op == "approve":
                nid = svc.need_grant_id(s["needId"])
                g = svc.inspect(nid)
                sig = GS.sign_grant_body(K.NEED_APPROVE_DOMAIN, K.need_approve_message({"id": s["needId"], "grant_id": nid}, g["rev"], s["approved"]), sec(s["by"]))
                r = svc.approve_needs(s["needId"], s["approved"], sig, s.get("stepUp"))
            elif op == "deny":
                r = svc.deny_needs(s["needId"])
            elif op == "http":
                req = {k: s[k] for k in ("method", "path", "query", "body", "who") if k in s}
                r = handler(req)
            else:
                raise ValueError("bad op")
            out.append(r)
        except Exception as e:  # noqa: BLE001
            out.append(err_code(e))
    return {"steps": out, "events": events, "grants": sorted(store.list(), key=lambda g: g["id"].encode("utf-16-be", "surrogatepass"))}


def lease_scenario(spec):
    reg = LeaseRegistry({"authorities": [pub("auth")], **(spec.get("policy") or {})}, MemoryAtomicKv(), shards=spec.get("shards", 4), clock=lambda: T0)
    handler = GS.lease_resource_handler(reg, lambda req: req.get("who"), now=lambda: T0)
    out = []
    for raw in spec["steps"]:
        s = resolve(raw)
        try:
            op = s["op"]
            if op == "accept":
                r = reg.accept(s["lease"], s.get("chain") or ())
            elif op == "revoke":
                r = reg.revoke(s["rev"])
            elif op == "get":
                r = reg.get(s["id"])
            elif op == "history":
                r = reg.history(s["id"])
            elif op == "shardRevs":
                r = reg.shard_revocations(s["i"])
            elif op == "renew":
                veto = (lambda c, v=s["vetoSeq"]: c["seq"] >= v) if s.get("vetoSeq") is not None else None
                r = G.renew_lease(sk(s.get("label", "auth")), reg, s["id"], s["now"], s["increment"], s["just"],
                                  approvers=s.get("approvers") if s.get("approvers") is not None else None, veto=veto, chain=s.get("chain"))
                if not r["ok"]:
                    r = {"ok": False, "code": r["code"]}
            elif op == "check":
                r = check_lease(s["lease"], reg, s["now"])
            elif op == "http":
                res = handler({k: s[k] for k in ("method", "path", "query", "body", "who") if k in s})
                r = {"status": res["status"], "body": res["body"]}
            else:
                raise ValueError("bad op")
            out.append(r)
        except Exception as e:  # noqa: BLE001
            out.append(err_code(e))
    return out


def blueprint_scenario(spec):
    reg = BlueprintRegistry([pub("op")], MemoryBlueprintStore())
    adm = G.AdmissionRegistry()
    revoked = []

    class Revoker:
        def revoke(self, i):
            revoked.append(i)

    fresh = G.FreshAtIssuer(sk("iss"), "scope", {"revocation_epoch": 0, "ledger_tree_size": 0, "budget_version": 0, "policy_revision": 0, "policy_digest": "pd"})
    out = []
    for raw in spec["steps"]:
        s = resolve(raw)
        try:
            op = s["op"]
            if op == "accept":
                r = reg.accept(s["bp"])
            elif op == "epoch":
                r = reg.epoch()
            elif op == "kill":
                r = G.group_kill(sk(s.get("label", "op")), reg, s["key"], s["now"], reason=s.get("reason") or None,
                                 revocation=Revoker() if s.get("revoker") else None, fresh_at=fresh if s.get("fresh") else None)
            elif op == "revoked":
                r = list(revoked)
            elif op == "admit":
                adm.admit(s["instance"], reg.get(s["key"]), s["until"])
                r = True
            elif op == "admitRevoke":
                r = adm.revoke(s["instance"], s["key"])
            elif op == "admitCheck":
                r = adm.checker(s["now"])(s["instance"], reg.get(s["key"]))
            else:
                raise ValueError("bad op")
            out.append(r)
        except Exception as e:  # noqa: BLE001
            out.append(err_code(e))
    return out


def admit_case(bp, e):
    def evidence():
        if isinstance(e, dict) and e.get("$throw"):
            raise TypeError("boom")
        return e
    return G.admit_with_evidence(bp, evidence)


MAP = {
    "signerOf": lambda label: G.signer_of(sk(label)),
    "signBody": lambda dom, body, label: G.sign_domain_body(dom, body, sk(label)),
    "verifyBody": lambda dom, body, signer, sig: G.verify_domain_body(dom, body, signer, sig),
    "signLease": lambda label, r: G.sign_lease(sk(label), r),
    "signLeaseUnsafeOverCap": lambda label, r: G.sign_lease_unsafe_over_cap(sk(label), r),
    "signLeaseRevocation": lambda label, r: G.sign_lease_revocation(sk(label), r),
    "signBlueprint": lambda label, r: G.sign_blueprint(sk(label), r),
    "signBreakGlass": lambda label, r: G.sign_break_glass(sk(label), r),
    "signBreakGlassReview": lambda label, r: G.sign_break_glass_review(sk(label), r),
    "signBundle": lambda body, label: G.sign_bundle(body, sk(label)),
    "assembleBundle": G.assemble_bundle,
    "maskRecord": G.mask_record,
    "mergeFreshAt": G.merge_fresh_at,
    "gateDecision": G.gate_decision,
    "logScenario": log_scenario,
    "replayScenario": replay_scenario,
    "freshScenario": fresh_scenario,
    "shadowScenario": shadow_scenario,
    "listScenario": list_scenario,
    "windowAcc": window_acc,
    "grantScenario": grant_scenario,
    "leaseScenario": lease_scenario,
    "blueprintScenario": blueprint_scenario,
    "admitWithEvidence": admit_case,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(MAP), sorted(set(BY_FN) ^ set(MAP))
    assert COUNT > 2000


@pytest.mark.parametrize("fn", sorted(MAP))
def test_replay(fn):
    ran, _ = run(BY_FN[fn], MAP[fn])
    assert ran == len(BY_FN[fn])


# ---- native-only checks (no reference vectors) --------------------------------------------------------------------------------

def test_lease_store_conformance_over_memory_kv():
    passed = G.run_lease_store_conformance(MemoryAtomicKv, reopen=lambda kv: kv)
    assert "spread" in passed and "pruning bounds revocations" in passed


def test_grant_client_folds_only_newer_tokens_and_signs_nothing_it_cannot_verify():
    iss = G.FreshAtIssuer(sk("c"), "scope", {"revocation_epoch": 1, "ledger_tree_size": 1, "budget_version": 1, "policy_revision": 1, "policy_digest": "pd"})
    t1 = iss.advance({"revocation_epoch": 2}, T0)
    sent = []
    toks = [t1, {**t1, "revocation_epoch": 0}, {**t1, "sig": "x"}]

    def fetch(req):
        sent.append(req)
        tok = toks.pop(0)
        return {"status": 200, "headers": {"Pca-Fresh-At": json.dumps(tok)}, "body": "{\"grants\":[]}"}

    c = GS.create_grant_client("https://as.example/", fetch, fresh_signer=pub("c"))
    c.list({"status": "active", "limit": 5})
    assert sent[0]["url"] == "https://as.example/pca/grants?status=active&limit=5"
    assert c.fresh_at["revocation_epoch"] == 2
    c.inspect("a/b")
    c.inspect("a/b")
    assert c.fresh_at == t1 and "pca-fresh-at" in sent[1]["headers"] and sent[1]["url"].endswith("/pca/grants/a%2Fb")

    def boom(req):
        return {"status": 409, "headers": {}, "body": "{\"error\":\"conflict\",\"message\":\"m\"}"}

    with pytest.raises(GS.GrantApiError) as ei:
        GS.create_grant_client("https://as.example", boom).deny_needs("n")
    assert ei.value.status == 409 and ei.value.code == "conflict"
