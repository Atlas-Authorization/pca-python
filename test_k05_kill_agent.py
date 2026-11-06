"""k05 mutation-kill: agent (suite wiring, key reprs, passport, discharge, narrow, act/fetch), decision (units, tighten, key order,
_safe_int), escalation (shape messages, wire escaping, verify) and approval (batch order, flatten, _lone). Expectations follow the
TypeScript reference (packages/pca/src/{decision,escalation}.ts, packages/pca-actions/src/{approval-render,approval-profiles}.ts)."""
import json
import sys
import types
import urllib.request

import pytest

from atlas_pca import agent as G
from atlas_pca import approval as AP
from atlas_pca import decision as D
from atlas_pca import escalation as E
from atlas_pca import pca as PC
from atlas_pca import pq_backends
from atlas_pca.pca import CAP_DOMAIN, b64u, canonical_bytes_strict, hash_canonical, holder_pq_commitment, params_digest, unb64u

P = G.keypair_from_seed(bytes([91]) * 32)
Q = G.keypair_from_seed(bytes([92]) * 32)
HYB = "hybrid-ed25519-ml-dsa-65"


class FakePq:
    family, public = "ML-DSA-65", "PQPK"

    def sign(self, msg):
        return b"PQ:" + msg


def _hdr(h, name):
    return json.loads(unb64u(h[name]))


# ---- agent: keys ----------------------------------------------------------------------------------------------------------

def test_reprs():
    assert repr(P) == "KeyPair(public=%r)" % P.public
    kp = G.PqKeyPair("ML-DSA-65", bytes(20), b"secret")
    assert repr(kp) == "PqKeyPair(family='ML-DSA-65', public='AAAAAAAAAAAA'...)"


def test_ossl_pair_repr_and_generate_families(monkeypatch):
    class FakeKey:
        def __init__(self, family):
            self.family, self.public = family, bytes(20)

        def sign(self, m):
            return b"s" + m

    monkeypatch.setattr(G, "_ML_DSA", {})
    monkeypatch.setattr(pq_backends, "OpensslKey", FakeKey)
    for fam in ("ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-256s"):
        k = G.generate_pq_keypair(fam)
        assert type(k) is G._OsslPair and k.family == fam
        assert repr(k) == "PqKeyPair(family=%r, public='AAAAAAAAAAAA'...)" % fam
        with pytest.raises(G.UnsupportedSuite) as e:
            G.generate_pq_keypair(fam, seed=bytes(32))
        assert str(e.value) == "unsupported_suite: %s (install atlas-pca[pq] or use OpenSSL >= 3.5)" % fam
        with pytest.raises(G.UnsupportedSuite):
            G.generate_pq_keypair(fam.lower())
    with pytest.raises(G.UnsupportedSuite):
        G.generate_pq_keypair("ML-DSA-44")


def test_generate_pq_keypair_seed(monkeypatch):
    class Impl:
        def key_derive(self, seed):
            self.seed = seed
            return b"PK", b"SK"

        def keygen(self):
            return b"PK0", b"SK0"

    impl = Impl()
    monkeypatch.setattr(G, "_ML_DSA", {"ML-DSA-65": impl})
    k = G.generate_pq_keypair("ML-DSA-65", seed=b"\x07" * 32)
    assert impl.seed == b"\x07" * 32 and k.public_bytes == b"PK" and k.secret == b"SK"
    k = G.generate_pq_keypair("ML-DSA-65")
    assert k.public_bytes == b"PK0" and k.secret == b"SK0"


def test_ed_sign_builtin_fallback(monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric.ed25519", None)
    seed, msg = bytes([5]) * 32, b"message"
    got = G._ed_sign(seed, msg)
    assert got == G._ed.sign(seed, msg) and len(got) == 64


# ---- agent: capability sealing --------------------------------------------------------------------------------------------

def _expected_cap(alg, pq, caveats, holder="H", parent=None, holder_pq=None, issuer=None):
    issuer = issuer or P.public
    body = {"issuer": issuer, "holder": holder, "caveats": caveats, "parent": parent}
    if holder_pq is not None:
        body["holder_pq"] = holder_pq
    signable = dict(body)
    if alg:
        signable["alg"], signable["pq_pk"] = alg, pq.public
    dig = hash_canonical(signable)
    msg = CAP_DOMAIN + unb64u(dig)
    cap = {"id": dig, "issuer": issuer, "holder": holder, "caveats": caveats, "body_digest": dig}
    if alg in (None, "ed25519"):
        cap["sig"] = b64u(P.sign(msg))
    elif alg == "ml-dsa-65":
        cap.update(sig=b64u(b"PQ:" + msg), alg=alg, pq_pk=pq.public)
    else:
        cap.update(sig=b64u(P.sign(msg)), alg=alg, pq_pk=pq.public, pq_sig=b64u(b"PQ:" + msg))
    if parent is not None:
        cap["parent"] = parent
    if holder_pq is not None:
        cap["holder_pq"] = holder_pq
    return cap


def test_mint_root_suites():
    cav = [{"type": "x"}]
    pq = FakePq()
    assert G.mint_root(P, "H", cav) == _expected_cap(None, None, cav)
    assert G.mint_root(P, "H", cav, None, "ed25519", None) == _expected_cap(None, None, cav)
    assert G.mint_root(P, "H", cav, None, "ed25519", pq) == _expected_cap(None, None, cav)
    assert G.mint_root(P, "H", cav, None, "ml-dsa-65", pq) == _expected_cap("ml-dsa-65", pq, cav)
    assert G.mint_root(P, "H", cav, None, HYB, pq) == _expected_cap(HYB, pq, cav)
    hp = holder_pq_commitment("HPQ")
    assert G.mint_root(P, "H", cav, "HPQ", HYB, pq) == _expected_cap(HYB, pq, cav, holder_pq=hp)


def test_delegate_and_attenuate_wiring():
    pq = FakePq()
    root = G.mint_root(P, P.public, [{"type": "x"}])
    ch = G.delegate(root, P, "NEWH", [{"type": "c"}], holder_pq="HPQ", alg=HYB, pq=pq)
    assert ch == _expected_cap(HYB, pq, [{"type": "x"}, {"type": "c"}], holder="NEWH", parent=PC.cap_hash(root),
                               holder_pq=holder_pq_commitment("HPQ"), issuer=P.public)
    at = G.attenuate(root, [{"type": "c"}], P, alg=HYB, pq=pq)
    assert at == _expected_cap(HYB, pq, [{"type": "x"}, {"type": "c"}], holder=P.public, parent=PC.cap_hash(root), issuer=P.public)
    plain = G.attenuate(root, [{"type": "c"}], P)
    assert plain["caveats"] == [{"type": "x"}, {"type": "c"}] and plain["holder"] == P.public and plain["sig"]
    assert "alg" not in plain


def test_mint_grant_wiring_and_errors():
    env = {"predicates": [], "caveats": [], "risk_policy": G.DEFAULT_RISK_POLICY}
    pq = FakePq()
    r = G.mint_grant(P, "H", env, "goal", salt="s", holder_pq="HPQ", alg=HYB, pq=pq)
    g = r["grant"]
    assert g["alg"] == HYB and g["pq_pk"] == "PQPK" and "pq_sig" in g and g["holder_pq"] == holder_pq_commitment("HPQ")
    r = G.mint_grant(P, "H", dict(env, model_polarity="legacy"), "goal", salt="s")
    assert r["grant"]["caveats"][0]["model_polarity"] == "legacy"
    for bad in ("LEGACY", "xlegacy", 5):
        with pytest.raises(ValueError) as e:
            G.mint_grant(P, "H", dict(env, model_polarity=bad), "goal")
        assert str(e.value) == "mint_grant: model_polarity must be 'legacy' when present"
    with pytest.raises(ValueError) as e:
        G.mint_grant(P, "H", dict(env, provenance="x"), "goal")
    assert str(e.value) == "mint_grant: provenance must be an object"


def test_risk_policy_boundaries():
    def pol(**kw):
        p = json.loads(json.dumps(G.DEFAULT_RISK_POLICY))
        for k, v in kw.items():
            if k.startswith("w_"):
                p["weights"][k[2:]] = v
            else:
                p[k] = v
        return p

    assert G._risk_policy_error(pol()) is None
    assert G._risk_policy_error(pol(w_alpha=0)) is None
    assert G._risk_policy_error(pol(theta1=0)) is None
    assert G._risk_policy_error(pol(theta1=0.5, theta2=0.5)) is None
    assert G._risk_policy_error(pol(**{"lambda": 0})) is None
    assert G._risk_policy_error(pol(rho=0)) is None
    assert G._risk_policy_error(pol(bMax=0)) is None
    assert G._risk_policy_error(pol(w_alpha=True)) == "risk_policy.weights.alpha must be finite and >= 0"
    assert G._risk_policy_error(pol(w_alpha=-1)) == "risk_policy.weights.alpha must be finite and >= 0"
    assert G._risk_policy_error(pol(theta1=-1)) == "risk_policy requires 0 <= theta1 <= theta2"
    assert G._risk_policy_error(pol(theta1=0.7, theta2=0.5)) == "risk_policy requires 0 <= theta1 <= theta2"
    assert G._risk_policy_error(pol(**{"lambda": -1})) == "risk_policy lambda/rho/bMax must be >= 0"
    assert G._risk_policy_error(pol(rho=-1)) == "risk_policy lambda/rho/bMax must be >= 0"
    assert G._risk_policy_error(pol(bMax=-1)) == "risk_policy lambda/rho/bMax must be >= 0"


# ---- agent: plan + PCActn -------------------------------------------------------------------------------------------------

def test_commit_plan_proofs_verify_for_every_size_and_index():
    for n in range(1, 10):
        nodes = [{"id": "n%d" % i, "verb": "v", "resource": "r%d" % i} for i in range(n)]
        c = G.commit_plan(nodes)
        leaves = G._plan_leaves(nodes)
        for i in range(n):
            proof = c["proof_for"]("n%d" % i)
            assert proof["index"] == i and proof["size"] == n
            assert PC.verify_inclusion(c["root"], proof, leaves[i]) is True
            for j in range(n):
                if j != i:
                    assert PC.verify_inclusion(c["root"], proof, leaves[j]) is False
    with pytest.raises(ValueError) as e:
        c["proof_for"]("zzz")
    assert str(e.value) == "commit_plan: unknown node zzz"


def test_build_pcactn_slots_and_clock(monkeypatch):
    plan = [{"id": "n1", "verb": "v", "resource": "r"}]
    slots = dict(nonce="N", caution=3, rationale_commitment="rc", progress_step={"a": 1}, prohibition_evidence={"b": 2},
                 tool_binding="tb", intent={"c": 3}, intent_session={"d": 4}, fresh_at={"e": 5})
    p = G.build_pcactn({"id": "gid"}, [{"id": "gid"}], plan, "n1", 1, P, "aud", now=1000, **slots)
    for k, v in slots.items():
        assert p[k] == v
    assert p["iat"] == 1000 and p["exp"] == 1000 + G.DEFAULT_TTL_MS
    p = G.build_pcactn({"id": "gid"}, [], plan, "n1", 1, P, "aud", now=1000, iat=7)
    assert p["iat"] == 7
    for k in slots:
        assert k not in p
    monkeypatch.setattr(G, "time", types.SimpleNamespace(time=lambda: 1234.5))
    p = G.build_pcactn({"id": "gid"}, [], plan, "n1", 1, P, "aud")
    assert p["iat"] == 1234500


# ---- agent: headers, escalation answer, discharge, narrow -----------------------------------------------------------------

def test_sign_escalation_answer_wiring(monkeypatch):
    monkeypatch.setattr(G, "_escalation_answer_shape_error", lambda a: None)
    bind = {"policy_digest": "pd", "action_digest": "ad", "history_head": "hh"}
    body = {"v": 1, "kind": "pca-escalation-answer", "principal": P.public, "policy_digest": "pd", "action_digest": "ad",
            "history_head": "hh", "decision": "allow", "iat": 1, "expires_at": 2, "nonce": "NN"}
    got = G.sign_escalation_answer(P, bind, "allow", 1, 2, nonce="NN", alg=HYB, pq=FakePq())
    assert got == G.sign_artifact(G.ESCALATION_ANSWER_DOMAIN, body, P, HYB, FakePq())
    assert got["alg"] == HYB and "pq_sig" in got


def test_sign_discharge_and_narrow_exact():
    pq = FakePq()
    body = {"v": 1, "kind": "pca-discharge", "caveat_id": "cid", "issuer": "lbl", "cap_hash": "ch", "bind": "chain_hop",
            "claims": {"k": 1}, "iat": 10, "not_after": 20, "nonce": "NN", "action_digest": "AD"}
    got = G.sign_discharge(P, "cid", "lbl", "ch", {"k": 1}, 10, 20, action_digest="AD", nonce="NN", alg=HYB, pq=pq)
    assert got == G.sign_artifact(G.DISCHARGE_DOMAIN, body, P, HYB, pq)
    nobind = dict(body)
    del nobind["action_digest"]
    assert G.sign_discharge(P, "cid", "lbl", "ch", {"k": 1}, 10, 20, nonce="NN") == G.sign_artifact(G.DISCHARGE_DOMAIN, nobind, P)
    d1 = G.sign_discharge(P, "cid", "lbl", "ch", {}, 10, 20)
    d2 = G.sign_discharge(P, "cid", "lbl", "ch", {}, 10, 20)
    assert len(unb64u(d1["nonce"])) == 16 and d1["nonce"] != d2["nonce"] and d1["bind"] == "chain_hop"

    nbody = {"v": 1, "kind": "pca-narrow", "cap_hash": "ch", "holder": P.public, "caveats": [{"type": "c"}], "iat": 10,
             "not_after": 20, "nonce": "NN", "action_digest": "AD"}
    got = G.sign_narrow(P, "ch", [{"type": "c"}], 10, 20, action_digest="AD", nonce="NN", alg=HYB, pq=pq)
    assert got == G.sign_artifact(G.NARROW_DOMAIN, nbody, P, HYB, pq)
    n1 = G.sign_narrow(P, "ch", [], 10, 20)
    n2 = G.sign_narrow(P, "ch", [], 10, 20)
    assert len(unb64u(n1["nonce"])) == 16 and n1["nonce"] != n2["nonce"] and "action_digest" not in n1
    got = G.sign_narrow(P, "ch", [{"type": "c"}], 10, 20, nonce="NN")
    assert got == G.sign_artifact(G.NARROW_DOMAIN, {k: v for k, v in nbody.items() if k != "action_digest"}, P)


def test_needs_discharge_caveat_spiffe():
    c = G.needs_discharge_caveat("i", "iss", "cls", [], issuer_spiffe="spiffe://x")
    assert c["issuer_spiffe"] == "spiffe://x" and set(c) == {"type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require", "issuer_spiffe"}
    assert "issuer_spiffe" not in G.needs_discharge_caveat("i", "iss", "cls", [])


# ---- agent: passport ------------------------------------------------------------------------------------------------------

IDENT = {"model_id": "m", "weights_digest": "w", "system_prompt_digest": "s", "tool_manifest_digest": "t",
         "runtime_measurement": "r", "operator": "o", "hardware_rooted": True, "issued_at": 100}


def test_passport_fingerprint_exact():
    want = hash_canonical({"d": "atlas-pca/passport/v1", "model_id": "m", "weights_digest": "w", "system_prompt_digest": "s",
                           "tool_manifest_digest": "t", "runtime_measurement": "r", "operator": "o", "hardware_rooted": True})
    assert G.passport_fingerprint(IDENT) == want
    assert G.issue_passport(IDENT)["id"] == want


def test_sign_passport_evidence_and_suite():
    pp = G.issue_passport(IDENT)
    ev = {"k": "v"}
    s = G.sign_passport(pp, P, "sub", 1000, evidence=ev)
    assert ev == {"k": "v"}
    assert s["evidence"] == {"k": "v", "at": 100} and s["iat"] == 100 and s["nbf"] == 100
    s = G.sign_passport(pp, P, "sub", 1000, iat=50, evidence=ev)
    assert s["evidence"] == {"k": "v", "at": 50} and s["iat"] == 50 and s["nbf"] == 50
    s = G.sign_passport(pp, P, "sub", 1000, iat=50, nbf=60, evidence={"at": 7})
    assert s["evidence"] == {"at": 7} and s["nbf"] == 60
    s = G.sign_passport(pp, P, "sub", 1000, evidence=ev, alg=HYB, pq=FakePq())
    assert s["alg"] == HYB and s["pq_pk"] == "PQPK" and "pq_sig" in s
    body = {k: v for k, v in s.items() if k not in ("sig", "pq_sig")}
    msg = G.PASSPORT_SIG_DOMAIN.encode() + canonical_bytes_strict(body)
    assert s["pq_sig"] == b64u(b"PQ:" + msg)


# ---- agent: Agent.act / delegate / fetch ----------------------------------------------------------------------------------

def test_agent_act_headers_and_options():
    a = G.Agent(P, {"id": "gid"}, "aud", clock=lambda: 5000, alg=HYB, pq=FakePq())
    act = a.act("v", "r", {"x": 1}, node_id="nodeA", reversibility_class="irreversible", nonce="N1", discharges=[{"d": 1}],
                narrow={"n": 1}, escalation_answer={"e": 1}, caution=2)
    p = act.pcactn
    assert act.node_id == "nodeA" and p["plan"]["node_id"] == "nodeA" and p["nonce"] == "N1" and p["caution"] == 2
    assert p["action"]["reversibility_class"] == "irreversible" and p["iat"] == 5000 and p["alg"] == HYB and p["counter"] == 1
    assert p["exp"] == 5000 + G.DEFAULT_TTL_MS
    assert _hdr(act.headers, "PCA-Action") == p
    assert _hdr(act.headers, "PCA-Discharges") == [{"d": 1}]
    assert _hdr(act.headers, "PCA-Narrow") == {"n": 1}
    assert _hdr(act.headers, "PCA-Escalation-Answer") == {"e": 1}
    assert set(act.headers) == {"PCA-Action", "PCA-Discharges", "PCA-Narrow", "PCA-Escalation-Answer"}
    plain = a.act("v", "r")
    assert set(plain.headers) == {"PCA-Action"} and plain.node_id == "n1" and len(unb64u(plain.pcactn["nonce"])) == 16


def test_agent_delegate_carries_everything():
    root = G.mint_root(P, P.public, [{"type": "x"}])
    clk = lambda: 9  # noqa: E731
    parent = G.Agent(P, root, "aud", clock=clk, ttl_ms=777, alg=HYB, pq=FakePq())
    parent.counter = 5
    child = parent.delegate(Q, [{"type": "c"}], holder_pq="HPQ")
    cap = child.chain[-1]
    assert child.chain[:-1] == parent.chain and child.grant is root and child.key is Q and child.aud == "aud"
    assert child.ttl_ms == 777 and child.clock is clk and child.counter == 0 and child.alg is None
    assert cap["caveats"] == [{"type": "x"}, {"type": "c"}] and cap["holder"] == Q.public
    assert cap["holder_pq"] == holder_pq_commitment("HPQ")
    assert cap["alg"] == HYB and cap["pq_pk"] == "PQPK" and "pq_sig" in cap
    plain = G.Agent(P, root, "aud").delegate(Q)
    assert plain.chain[-1]["caveats"] == [{"type": "x"}] and "holder_pq" not in plain.chain[-1] and "alg" not in plain.chain[-1]


def test_agent_fetch(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["req"], seen["timeout"] = req, timeout
        return "RESP"

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    a = G.Agent(P, {"id": "gid"}, "aud", clock=lambda: 5000)
    given = {"X-A": "1"}
    assert a.fetch("PUT", "http://x.test/p", "refund", "orders/1", {"n": 1}, body=b"B", headers=given, caution=3) == "RESP"
    req = seen["req"]
    assert given == {"X-A": "1"} and seen["timeout"] == 30.0
    assert req.full_url == "http://x.test/p" and req.data == b"B" and req.get_method() == "PUT"
    hd = {k.lower(): v for k, v in req.header_items()}
    assert hd["x-a"] == "1"
    p = _hdr(hd, "pca-action")
    assert p["action"]["verb"] == "refund" and p["action"]["resource"] == "orders/1" and p["caution"] == 3
    assert p["action"]["params_digest"] == params_digest({"n": 1})
    assert a.fetch("DELETE", "http://x.test/q", "v", "r", timeout=5.0) == "RESP"
    assert seen["timeout"] == 5.0 and seen["req"].data is None and seen["req"].get_method() == "DELETE"
    assert {k.lower() for k, _ in seen["req"].header_items()} == {"pca-action"}


# ---- decision -------------------------------------------------------------------------------------------------------------

def test_safe_int_boundaries():
    top = 2 ** 53 - 1
    for fn in (D._safe_int, AP._safe_int):
        assert fn(top) and fn(-top) and fn(0) and fn(7)
        assert not fn(top + 1) and not fn(-top - 1) and not fn(True)
        assert fn(float(top)) and fn(-float(top)) and fn(2.0) and fn(-3.0) and fn(1000.0) and fn(0.0)
        assert not fn(float(top + 1)) and not fn(-0.0) and not fn(2.5) and not fn(float("inf")) and not fn(float("nan"))
        assert not fn("1") and not fn(None)


def test_js_keys_array_index_order():
    o = {"b": 1, "10": 2, "2": 3, "4294967294": 4, "4294967295": 5, "a": 6, "01": 7}
    assert D._js_keys(o) == ["2", "10", "4294967294", "b", "4294967295", "a", "01"]


def test_utf8_key_and_model_paths_with_lone_surrogate():
    assert D._utf8_key("\ud800") == b"\xed\xa0\x80" and D._utf8_key("a") == b"a"
    lst = [[{"where": [{"field": "env.class.\ud800"}, {"field": "env.class.a"}]}]]
    assert D.model_paths_read(lst) == ["env.class.a", "env.class.\ud800"]
    assert D.model_paths_read(["junk", [{"where": [{"field": "env.class.a"}]}]]) == ["env.class.a"]


def test_decision_of_unsupported_never_escalates():
    chk = {"a": "fail", "b": "unsupported"}
    rs = ["a: escalate: ask", "b: unsupported: feature"]
    assert D.decision_of({"allow": False, "checks": chk, "reasons": rs}) == "deny"
    assert D.decision_of({"allow": False, "checks": chk, "reasons": ["a: escalate: ask"]}) == "escalate"
    assert D.decision_of({"allow": False, "checks": {"a": "fail"}, "reasons": ["a: escalate: ask"]}) == "escalate"
    assert D.decision_of({"allow": False, "checks": {}, "reasons": []}) == "deny"


def test_is_model_derived_path_edges():
    assert D.is_model_derived_path("env.class") is True
    assert D.is_model_derived_path("foo.class") is False
    assert D.is_model_derived_path("env") is False
    assert D.is_model_derived_path("env.world", ["y"]) is True and D.is_model_derived_path("env.world", []) is False
    assert D.is_model_derived_path("env.world.x", ["y"]) is False
    assert D.is_model_derived_path("env.world.y", ["y"]) is True
    assert D.is_model_derived_path("env.other") is False


def _nest(n, leaf):
    c = leaf
    for _ in range(n):
        c = {"all_of": [c]}
    return c


def test_collect_paths_depth_cap():
    leaf = {"field": "action.params.amount"}
    out = set()
    D._collect_paths(_nest(64, leaf), out, 0)
    assert out == {"action.params.amount"}
    out = set()
    D._collect_paths(_nest(65, leaf), out, 0)
    assert out == set()


def test_unit_tags_error_bounds():
    ok = {"kind": "k"}
    assert D.unit_tags_error({"action.params.k%d" % i: ok for i in range(64)}) is None
    assert D.unit_tags_error({"action.params.k%d" % i: ok for i in range(65)}) == "units has more than 64 entries"
    assert D.unit_tags_error({"action.params.a": {"kind": "k", "currency": "X"}}) is None
    assert D.unit_tags_error({"action.params.a": {"kind": "k", "currency": "X" * 16}}) is None
    for cur in ("", "X" * 17, 5):
        assert D.unit_tags_error({"action.params.a": {"kind": "k", "currency": cur}}) == \
            "units['action.params.a'].currency must be a string of 1..16 characters"


def test_strict_eq_and_same_tag_and_tag_text():
    assert D._strict_eq(True, 1) is False and D._strict_eq(1, True) is False and D._strict_eq(True, True) is True
    assert D._strict_eq(1, 1.0) is True and D._strict_eq("a", "a") is True and D._strict_eq(1, "1") is False
    assert D._strict_eq({}, {}) is False and D._strict_eq([], []) is False
    assert D._same_tag({"kind": "k"}, {"kind": "k"}) is True
    assert D._same_tag({"kind": "k", "currency": None}, {"kind": "k"}) is False
    assert D._same_tag({"kind": "k"}, {"kind": "k", "currency": None}) is False
    assert D._same_tag({"kind": "k", "currency": None}, {"kind": "k", "currency": None}) is True
    assert D._same_tag({"kind": "k", "exponent": 2}, {"kind": "k", "exponent": 2.0}) is True
    assert D._tag_text(None) == "no unit"
    assert D._tag_text({"kind": "money", "currency": "USD", "exponent": 2}) == "money/USD/e2"
    assert D._tag_text({}) == "?" and D._tag_text({"kind": None}) == "?" and D._tag_text({"exponent": 0}) == "?/e0"


def test_fold_v2_reasons():
    v2 = [{"name": "n", "ok": False, "reason": "why"}, {"name": "m", "ok": True, "reason": "fine"},
          {"name": "k", "ok": False}, {"name": "n", "ok": False, "reason": "why"}]
    assert D.fold_v2_reasons(["base"], v2) == ["base", "n: why"]


MONEY = {"kind": "money", "currency": "USD", "exponent": 2}
AMT = "action.params.amount"


def _units_in(**kw):
    d = {"units": {AMT: MONEY}, "verb": "pay", "schema_units": {"usd": MONEY}, "verb_params": {AMT: {"unit": "usd"}},
         "predicates": []}
    d.update(kw)
    return d


def test_decide_units_basic_and_messages():
    assert D.decide_units(_units_in()) == {"ok": True}
    assert D.decide_units(_units_in(units=None)) == {"ok": False, "reason": "units must be an object"}
    assert D.decide_units({"verb": "pay"}) == {"ok": False, "reason": "units must be an object"}
    bad = D.decide_units(_units_in(units={AMT: dict(MONEY, currency="EUR")}))
    assert bad == {"ok": False, "reason": "'%s' is declared as money/USD/e2 by the action schema but the policy term is tagged "
                                          "money/EUR/e2 (unit confusion)" % AMT}
    # an unhashable unit id is "no unit", not an evaluation error
    odd = D.decide_units(_units_in(verb_params={AMT: {"unit": ["usd"]}}))
    assert odd == {"ok": False, "reason": "'%s' is declared as no unit by the action schema but the policy term is tagged "
                                          "money/USD/e2 (unit confusion)" % AMT}


def test_decide_units_loops_skip_not_stop():
    # an undeclared tag sorting first does not end the tag loop
    two = {"action.params.a": MONEY, "action.params.b": dict(MONEY, currency="EUR")}
    r = D.decide_units(_units_in(units=two, verb_params={"action.params.b": {"unit": "usd"}}))
    assert r["ok"] is False and "'action.params.b'" in r["reason"]
    where = [{"field": AMT, "op": "exists"}]
    want = {"ok": False, "reason": "a policy term reads '%s' (money/USD/e2) without a unit tag" % AMT}
    assert D.decide_units(_units_in(units={}, predicates=[[{"verb": "pay", "where": where}]])) == want
    # a non-list predicate list, an out-of-scope predicate and a non-matching path are skipped, not terminal
    assert D.decide_units(_units_in(units={}, predicates=["junk", [{"verb": "pay", "where": where}]])) == want
    assert D.decide_units(_units_in(units={}, predicates=[[{"verb": "other", "where": where}, {"verb": "pay", "where": where}]])) == want
    assert D.decide_units(_units_in(units={}, predicates=[[{"verb": ["x", "pay"], "where": where}]])) == want
    assert D.decide_units(_units_in(units={}, predicates=[[{"verb": "other", "where": where}]])) == {"ok": True}
    both = [{"field": "action.params.a b", "op": "exists"}, {"field": AMT, "op": "exists"}]
    assert D.decide_units(_units_in(units={}, predicates=[[{"verb": "*", "where": both}]])) == want


def test_decide_units_collects_from_depth_zero():
    leaf = {"field": AMT, "op": "exists"}
    want = {"ok": False, "reason": "a policy term reads '%s' (money/USD/e2) without a unit tag" % AMT}
    assert D.decide_units(_units_in(units={}, predicates=[[{"verb": "pay", "where": [_nest(64, leaf)]}]])) == want
    assert D.decide_units(_units_in(units={}, predicates=[[{"verb": "pay", "where": [_nest(65, leaf)]}]])) == {"ok": True}


def _tighten(rules, ctx=None, **kw):
    d = {"tighten": rules, "context": ctx if ctx is not None else {"env": {"a": 1}}}
    d.update(kw)
    return D.decide_tighten(d)


def _rule(i, val, sig="deny"):
    return {"id": i, "when": {"field": "env.a", "op": "eq", "value": val}, "signal": sig}


def test_decide_tighten_rules_in_order():
    r = _tighten([_rule("r1", 2), _rule("r2", 1)])
    assert r == {"outcome": "deny", "legacy": False, "offending": [], "reason": "denied by tighten rule 'r2'"}
    r = _tighten([_rule("r1", 1, "escalate")])
    assert r["outcome"] == "escalate" and r["reason"] == "escalate: asked by tighten rule 'r1'"
    r = _tighten([_rule("r1", 2)])
    assert r == {"outcome": "ok", "legacy": False, "offending": []}
    r = _tighten([{"id": "r1", "when": {"field": "env.zz", "op": "eq", "value": 1}, "signal": "deny"}])
    assert r["outcome"] == "escalate" and r["reason"] == "escalate: rule 'r1' could not be decided (a value it reads is missing or ill-typed)"


# ---- escalation -----------------------------------------------------------------------------------------------------------

PD, AD, HH, RD = (hash_canonical({"x": i}) for i in range(4))
NONCE = b64u(bytes(16))
GRANT = {"id": "g1"}
PCACTN = {"action": {"verb": "pay.send", "resource": "acct:1"}}


def _answer(**over):
    a = {"v": 1, "kind": "pca-escalation-answer", "principal": P.public, "policy_digest": PD, "action_digest": AD,
         "history_head": HH, "decision": "allow", "iat": 10, "expires_at": 20, "nonce": NONCE, "sig": "x"}
    a.update(over)
    return a


def test_utf16_prefix_and_wire():
    assert E._utf16_prefix("ab\U0001F600", 3) == "ab\ud83d"
    assert E._utf16_prefix("ab\U0001F600", 4) == "ab\U0001F600"
    assert E._utf16_prefix("a\ud800bc", 2) == "a\ud800"
    got = E.escalation_reasons_wire({"reasons": ['a"b', "\ud800", "\udfff", "\ud7ff", "\ue000", "\x1f", "\u00e9", "\\", "\n"]})
    assert got == '["a\\"b","\\ud800","\\udfff","\ud7ff","\ue000","\\u001f","\u00e9","\\\\","\\n"]'


def test_build_escalation_request_defaults():
    base = E.build_escalation_request(aud="rs", grant=GRANT, pcactn=PCACTN, last_counter=3, reasons=["r"], now=1000)
    assert base["expires_at"] == 1000 + 3_600_000
    assert E.build_escalation_request(aud="rs", grant=GRANT, pcactn=PCACTN, last_counter=3, reasons=["r"], now=1000,
                                      ttl_ms=None)["expires_at"] == 1000 + 3_600_000
    assert E.build_escalation_request(aud="rs", grant=GRANT, pcactn=PCACTN, last_counter=3, reasons=["r"], now=1000,
                                      ttl_ms=5)["expires_at"] == 1005
    odd = E.build_escalation_request(aud="rs", grant=GRANT, pcactn=None, last_counter=None, reasons=[], now=0)
    assert odd["verb"] == "undefined" and odd["resource"] == "undefined"
    cut = E.build_escalation_request(aud="rs", grant=GRANT, pcactn=PCACTN, last_counter=3, reasons=["a" * 511 + "\U0001F600"], now=0)
    assert cut["reasons"] == ["a" * 511 + "\ud83d"]


def test_escalation_shape_messages_and_bounds():
    assert E.escalation_answer_shape_error(_answer()) is None
    assert E.escalation_answer_shape_error(_answer(iat=0, expires_at=1)) is None
    assert E.escalation_answer_shape_error(_answer(iat=0, expires_at=0)) == "expires_at must be greater than iat"
    assert E.escalation_answer_shape_error(_answer(iat=-1, expires_at=5)) == "iat and expires_at must be non-negative safe integers"
    assert E.escalation_answer_shape_error(_answer(iat=1, expires_at=-1)) == "iat and expires_at must be non-negative safe integers"
    assert E.escalation_answer_shape_error(_answer(iat=1.5)) == "iat and expires_at must be non-negative safe integers"
    assert E.escalation_answer_shape_error(_answer(iat=0, expires_at=86_400_000)) is None
    assert E.escalation_answer_shape_error(_answer(iat=0, expires_at=86_400_001)) == "an answer lives at most 86400000 ms"
    assert E.escalation_answer_shape_error(_answer(v=2)) == "not a pca-escalation-answer v1"
    assert E.escalation_answer_shape_error(_answer(v=True)) == "not a pca-escalation-answer v1"
    assert E.escalation_answer_shape_error(_answer(kind="x")) == "not a pca-escalation-answer v1"
    assert E.escalation_answer_shape_error(_answer(principal="bad")) == "principal must be canonical base64url (32 bytes)"
    assert E.escalation_answer_shape_error(_answer(principal=5)) == "principal must be canonical base64url (32 bytes)"
    assert E.escalation_answer_shape_error(_answer(sig=5)) == "sig must be a string"
    short = b64u(bytes(16))
    for k in ("policy_digest", "action_digest", "history_head"):
        assert E.escalation_answer_shape_error(_answer(**{k: short})) == "%s must be canonical base64url (32 bytes)" % k
    assert E.escalation_answer_shape_error(_answer(render_digest=short)) == "render_digest must be canonical base64url (32 bytes)"
    assert E.escalation_answer_shape_error(_answer(render_digest=5)) == "render_digest must be canonical base64url (32 bytes)"
    assert E.escalation_answer_shape_error(_answer(render_digest=RD)) is None
    nmsg = "nonce must be canonical base64url of at least 16 bytes"
    assert E.escalation_answer_shape_error(_answer(nonce=123)) == nmsg
    assert E.escalation_answer_shape_error(_answer(nonce=b64u(bytes(15)))) == nmsg


def test_verify_escalation_answer_reasons():
    bind = {"policy_digest": PD, "action_digest": AD, "history_head": HH}
    ans = G.sign_escalation_answer(P, bind, "allow", 10, 20, nonce=NONCE)
    assert E.verify_escalation_answer(ans, [P.public], bind, 15) == {"ok": True, "principal": P.public, "decision": "allow"}
    no = lambda r: {"ok": False, "reason": r}  # noqa: E731
    assert E.verify_escalation_answer(ans, [P.public], dict(bind, policy_digest=AD), 15) == no("the answer is bound to another policy")
    assert E.verify_escalation_answer(ans, [P.public], dict(bind, action_digest=PD), 15) == no("the answer is bound to another action")
    assert E.verify_escalation_answer(ans, [P.public], dict(bind, history_head=PD), 15) == no("the answer is bound to another state of the history")
    assert E.verify_escalation_answer(ans, [P.public], bind, 5) == no("the answer is from the future")
    assert E.verify_escalation_answer(ans, [P.public], bind, 25) == no("the answer has expired")
    assert E.verify_escalation_answer(ans, [P.public], bind, 10)["ok"] is True
    assert E.verify_escalation_answer(ans, [P.public], bind, 20)["ok"] is True
    assert E.verify_escalation_answer(ans, [P.public], None, 15) == no("escalation answer error (fail closed): AttributeError")


# ---- approval -------------------------------------------------------------------------------------------------------------

def test_lone_surrogate_edges():
    assert AP._lone("\ud800") and AP._lone("\udfff") and AP._lone("a\udbffb")
    assert not AP._lone("\ud7ff") and not AP._lone("\ue000") and not AP._lone("abc")


def test_flatten_empty_prefix():
    assert AP._flatten({"": {"a": 1}}) == {"a": 1}
    assert AP._flatten({"a": {"b": {"c": 1}}, "d": 2}) == {"a.b.c": 1, "d": 2}


def _pay_render(ccy, payee, minor=100):
    return {"v": 1, "kind": "pca-approval-render", "verb": "pay", "def_digest": hash_canonical("d"), "unreviewed": False,
            "fields": [{"id": "amount", "class": "money.amount", "value": minor, "unit": {"kind": "money", "ccy": ccy, "exp": 2}},
                       {"id": "payee", "class": "party.payee", "value": payee}]}


def test_approval_batch_sorts_by_utf16_code_units():
    hi, lo = "\U00010000", "\uffff"  # UTF-16: D800 DC00 < FFFF, code point order is the opposite
    items = [{"action_digest": hash_canonical("a1"), "render": _pay_render(lo, lo)},
             {"action_digest": hash_canonical("a2"), "render": _pay_render(hi, hi, 5)}]
    out = AP.approval_batch(items)["batch"]
    assert [t["ccy"] for t in out["totals"]] == [hi, lo]
    assert out["payees_root"] == PC.merkle_root([{"d": "atlas-pca/approval-payee/v1", "payee": p} for p in (hi, lo)])
    assert out["n"] == 2
