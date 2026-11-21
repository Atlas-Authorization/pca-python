"""The producer-side signers at their edges, held to the TypeScript reference: the suite fields of a share (threshold.ts
signPreparedShare), a PQ binding's pin refusals in order (pq.ts pqPinFor), the caution body and intent-required bounds
(agent-native.ts, intent-required.ts), the session root's optional members and suite (intent-session.ts), the session
grant's defaults (mintSessionGrant), the discovery key entry (action-schema.ts actionSchemaKeyOf) and the compact mesh proof
(mesh.ts assembleMeshProof). Keys come from fixed seeds; a stand-in PQ key (deterministic, hash based) shows where a PQ
signature lands without needing a PQ backend. Nothing here calls the package at import time."""
import base64
import copy
import hashlib
import json
import os

import pytest

HYB = "hybrid-ed25519-ml-dsa-65"
MAX_SAFE = 2 ** 53 - 1
_VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance",
                        "producer-vectors.json")
_DOC = []


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class _FakePq:
    """Stands in for an ML-DSA-65 key pair: a 1952-byte public key and a deterministic hash as its 'signature'."""
    family = "ML-DSA-65"

    def __init__(self, tag=b"pq"):
        self.tag = tag
        self.public = _b64u((hashlib.sha512(tag).digest() * 31)[:1952])

    def sign(self, msg):
        return hashlib.sha512(b"fake-pq\x00" + self.tag + b"\x00" + msg).digest()


def _kp(n):
    from atlas_pca.agent import keypair_from_seed
    return keypair_from_seed(bytes([n]) * 32)


def _vec(name):
    if not _DOC:
        with open(_VECTORS, encoding="utf-8") as f:
            _DOC.append(json.load(f))
    return copy.deepcopy(next(c for c in _DOC[0]["cases"] if c["name"] == name)["args"])


def _vkey(name):
    from atlas_pca.agent import keypair_from_seed
    from atlas_pca.pca import unb64u
    _vec("caution")
    return keypair_from_seed(unb64u(_DOC[0]["keys"][name]["seed"]))


def _refuses(fn, text):
    with pytest.raises(ValueError) as e:
        fn()
    assert str(e.value) == text


# ---- threshold shares ---------------------------------------------------------------------------------------------------------

def test_prepared_share_hybrid_and_pure_suite_fields():
    from atlas_pca import signers_more as S
    key, pq, prepared = _kp(11), _FakePq(), b"prepared share bytes"
    assert S.sign_prepared_share("principal", key, prepared, HYB, pq) == {
        "role": "principal", "publicKey": key.public, "sig": _b64u(key.sign(prepared)), "alg": HYB,
        "pq_sig": _b64u(pq.sign(prepared))}
    # a pure PQ suite: the PQ signature IS `sig`, no pq_sig member; publicKey stays the Ed25519 identity
    assert S.sign_prepared_share("principal", key, prepared, "ml-dsa-65", pq) == {
        "role": "principal", "publicKey": key.public, "sig": _b64u(pq.sign(prepared)), "alg": "ml-dsa-65"}
    assert S.sign_prepared_share("principal", key, prepared) == {
        "role": "principal", "publicKey": key.public, "sig": _b64u(key.sign(prepared))}


def _signer_set():
    return [{"role": "agent", "publicKey": _kp(12).public}, {"role": "principal", "publicKey": _kp(13).public}]


def test_threshold_share_binds_the_suite_tag():
    from atlas_pca import signers_more as S
    from atlas_pca.pca import signer_set_hash
    key, pq, msg, ss = _kp(12), _FakePq(), b"threshold message", _signer_set()
    # shareMessage: "atlas-pca/share/<role>\0" || sha256(message) || signerSetHash || t || "\0atlas-pca/share-suite/v1\0" alg
    prepared = (b"atlas-pca/share/agent\x00" + hashlib.sha256(msg).digest() + signer_set_hash(ss) + bytes([2])
                + b"\x00atlas-pca/share-suite/v1\x00" + HYB.encode())
    assert S.sign_threshold_share("agent", key, msg, ss, 2, HYB, pq) == {
        "role": "agent", "publicKey": key.public, "sig": _b64u(key.sign(prepared)), "alg": HYB, "pq_sig": _b64u(pq.sign(prepared))}


def test_threshold_share_signer_set_list_tuple_iterator():
    from atlas_pca import signers_more as S
    key, msg, ss = _kp(12), b"m", _signer_set()
    want = S.sign_threshold_share("agent", key, msg, ss, 1)
    assert S.sign_threshold_share("agent", key, msg, tuple(ss), 1) == want
    # an iterator is not an array: refused (signerSetHash of a non-array set is malformed)
    _refuses(lambda: S.sign_threshold_share("agent", key, msg, iter(ss), 1), "sign_threshold_share: malformed signer set")


# ---- PQ binding -> pin ------------------------------------------------------------------------------------------------------------

PQ_PK = _b64u(bytes(1952))


def _binding(key, pq=PQ_PK, epoch=1, aud="rs", signer=None):
    msg = b"atlas-pca/pq-binding/v2\x00" + ("%s\x00%s\x00%d\x00%s" % (key.public, pq, epoch, aud)).encode("utf-8")
    return {"ed": key.public, "pq": pq, "epoch": epoch, "aud": aud, "sig": _b64u((signer or key).sign(msg))}


def test_pq_pin_for_refusals_of_signed_bindings():
    from atlas_pca import signers_more as S
    key = _kp(21)
    assert S.pq_pin_for(_binding(key), "rs") == {key.public: PQ_PK}
    assert S.sign_pq_binding(key, PQ_PK, 1, "rs") == _binding(key)
    big = S.sign_pq_binding(key, PQ_PK, MAX_SAFE, "rs")
    assert big == _binding(key, epoch=MAX_SAFE) and S.pq_pin_for(big, "rs") == {key.public: PQ_PK}
    assert S.pq_pin_for(_binding(key, aud=""), "") is None  # aud is required, even when the binding names ""
    assert S.pq_pin_for(_binding(key, epoch=0), "rs") is None
    assert S.pq_pin_for(_binding(key, epoch=MAX_SAFE + 1), "rs") is None
    assert S.pq_pin_for(_binding(key, pq=_b64u(bytes(31))), "rs") is None  # not a registered PQ key length
    assert S.pq_pin_for(_binding(key, signer=_kp(22)), "rs") is None  # signed by another key


class _Rec(dict):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.seen = []

    def get(self, k, d=None):
        self.seen.append(k)
        return super().get(k, d)

    def __getitem__(self, k):
        self.seen.append(k)
        return super().__getitem__(k)


def test_pq_pin_for_stops_at_a_non_string_ed_or_sig():
    from atlas_pca import signers_more as S
    b = _Rec(_binding(_kp(21)), ed=5)
    assert S.pq_pin_for(b, "rs") is None and b.seen == ["ed"]
    b = _Rec(_binding(_kp(21)), sig=5)
    assert S.pq_pin_for(b, "rs") is None and b.seen == ["ed", "sig"]


# ---- caution ------------------------------------------------------------------------------------------------------------------

def test_caution_bounds():
    from atlas_pca import signers_more as S
    h = _kp(31)
    body = {"action_digest": _b64u(bytes(32)), "caution": 0, "holder": h.public}
    for c in (0, 1, 0.0, 1.0):
        assert S.sign_caution(dict(body, caution=c), h)["caution"] == c
    for r in ("a" * 64, "Az09_.:-"):
        assert S.sign_caution(dict(body, reason=r), h)["reason"] == r
    for r in ("", "a" * 65, 5, None, "a b"):
        _refuses(lambda: S.sign_caution(dict(body, reason=r), h), "sign_caution: invalid reason")


# ---- intent_required ----------------------------------------------------------------------------------------------------------

def _ir(mut=None):
    b = _vec("intent-required")["body"]
    if mut:
        mut(b)
    return b


def _coords(c):
    return lambda b: b["cell"].update(coords=c)


def test_intent_required_accepts_every_tier_and_the_edges():
    from atlas_pca import signers_more as S
    site = _vkey("site")
    for f in ("tap", "hold", "typed", "device"):
        assert S.sign_intent_required(_ir(lambda b: b.update(friction=f)), "site-k1", site)["friction"] == f
    assert S.sign_intent_required(_ir(lambda b: b.update(delivered_to="agent")), "site-k1", site)["delivered_to"] == "agent"
    assert S.sign_intent_required(_ir(lambda b: b.update(expires_at=0)), "site-k1", site)["expires_at"] == 0
    for c in ({"d%d" % i: ["a"] for i in range(64)}, {"k" * 256: ["a"]}, {"\U0001F600" * 128: ["a"]}, {"x": [3, 3]},
              {"x": [0, MAX_SAFE]}, {"x": ["v%d" % i for i in range(256)]}):
        assert S.sign_intent_required(_ir(_coords(c)), "site-k1", site)["cell"]["coords"] == c


def test_intent_required_refuses_past_the_edges():
    from atlas_pca import signers_more as S
    site = _vkey("site")

    def r(mut, text):
        _refuses(lambda: S.sign_intent_required(_ir(mut), "site-k1", site), "sign_intent_required: " + text)
    r(lambda b: b["cell"].update(verb=""), "cell must be {verb, coords}")
    r(lambda b: b["cell"].update(verb=5), "cell must be {verb, coords}")
    r(_coords({"d%d" % i: ["a"] for i in range(65)}), "coords must be an object of 1..64 dimensions")
    r(_coords({"k" * 257: ["a"]}), "a coordinate path must be 1..256 characters")
    # the reference counts UTF-16 code units: 129 astral characters are 258
    r(_coords({"\U0001F600" * 129: ["a"]}), "a coordinate path must be 1..256 characters")
    r(_coords({"x": [-MAX_SAFE, 0]}), "coords 'x': need 0 <= lo <= hi")
    r(_coords({"x": [0, MAX_SAFE + 1]}), "coords 'x': an index range [lo, hi] or a value set")
    r(_coords({"x": ["v%d" % i for i in range(257)]}), "coords 'x': an index range [lo, hi] or a value set")


# ---- session root and session grant ------------------------------------------------------------------------------------------

def test_session_root_keeps_revocation_and_flows_and_signs_the_suite():
    from atlas_pca import signers_more as S
    from atlas_pca.agent import sign_artifact
    from atlas_pca.intent_v2 import INTENT_SESSION_SIG_DOMAIN, verify_session_root
    principal = _vkey("principal")
    rev = {"epoch_uri": "https://guardian.example/epoch", "max_age_s": 60, "key": _vkey("guardian").public}
    body = dict(_vec("session-root")["body"], revocation=rev, flows={"pay": {"max": 1}})
    s = S.sign_session_root(body, principal)
    assert s["revocation"] == rev and s["flows"] == {"pay": {"max": 1}}
    assert s == sign_artifact(INTENT_SESSION_SIG_DOMAIN, dict(body, signer=principal.public), principal)
    assert verify_session_root(s, {})["ok"]
    pq = _FakePq()
    h = S.sign_session_root(body, principal, HYB, pq)
    assert h == sign_artifact(INTENT_SESSION_SIG_DOMAIN, dict(body, signer=principal.public), principal, HYB, pq)
    assert h["alg"] == HYB and h["pq_pk"] == pq.public and "pq_sig" in h


def _grant_args():
    a = _vec("session-grant-g0")
    return dict(principal=_vkey("principal"), holder=_vkey("agent").public, session=a["session"], seq=0, root=a["root"],
                map_digest=a["map_digest"], predicates=a["predicates"])


def test_session_grant_random_salt_is_16_bytes():
    from atlas_pca import signers_more as S
    from atlas_pca.agent import goal_commit_of
    from atlas_pca.pca import INTENT_GOAL_V2_PREFIX, decode_b64u_strict
    kw = _grant_args()
    r = S.mint_session_grant(**kw)
    assert isinstance(r["goal_salt"], str) and decode_b64u_strict(r["goal_salt"], 16) is not None
    env = r["grant"]["caveats"][0]
    assert env["goal_commit"] == goal_commit_of(INTENT_GOAL_V2_PREFIX + kw["session"] + ":" + kw["map_digest"], r["goal_salt"])
    assert S.mint_session_grant(**kw)["goal_salt"] != r["goal_salt"]


def test_session_grant_carries_binding_policy_holder_pq_and_suite():
    from atlas_pca import signers_more as S
    from atlas_pca.agent import goal_commit_of, mint_root
    from atlas_pca.pca import INTENT_GOAL_V2_PREFIX
    kw = _grant_args()
    pq, holder_pq = _FakePq(b"principal"), _FakePq(b"holder").public
    binding, policy = {"model_id": "m1"}, {"mode": "strict"}
    r = S.mint_session_grant(**kw, salt="s1", agent_binding=binding, risk_policy=policy, holder_pq=holder_pq, alg=HYB, pq=pq)
    env = {"type": "envelope",
           "goal_commit": goal_commit_of(INTENT_GOAL_V2_PREFIX + kw["session"] + ":" + kw["map_digest"], "s1"),
           "predicates": kw["predicates"], "caveats": [], "agent_binding": binding, "risk_policy": policy}
    sc = {"type": "intent_session", "session": kw["session"], "seq": 0, "root": kw["root"]}
    assert r == {"grant": mint_root(kw["principal"], kw["holder"], [env, sc], holder_pq, HYB, pq), "goal_salt": "s1"}
    assert r["grant"]["alg"] == HYB and r["grant"]["pq_pk"] == pq.public and "holder_pq" in r["grant"]


# ---- discovery key entry --------------------------------------------------------------------------------------------------------

def test_action_schema_key_of_pq_pk_only_for_a_pq_suite():
    from atlas_pca import signers_more as S
    site, pq = _kp(41), _FakePq()
    want = {"kid": "k1", "alg": "ed25519", "pk": site.public}
    assert S.action_schema_key_of("k1", site) == want
    assert S.action_schema_key_of("k1", site, None, pq) == want  # ed25519 carries no pq_pk even when one is given
    assert S.action_schema_key_of("k1", site, HYB, pq) == dict(want, alg=HYB, pq_pk=pq.public)
    assert S.action_schema_key_of("k1", site, "ml-dsa-65") == dict(want, alg="ml-dsa-65")


# ---- compact mesh proof ---------------------------------------------------------------------------------------------------------

def test_assemble_mesh_proof_compacts_heads_and_leaves():
    from atlas_pca import signers_more as S
    from atlas_pca.mesh import MESH_ACTION_DOMAIN
    from atlas_pca.pca import canonical_bytes_strict, hash_canonical
    leaf = _kp(51)
    chain = [{"id": "c0", "holder": "a"}, {"id": "c1", "holder": "b"}]
    action = {"verb": "read", "resource": "doc/1", "at": 5}
    la, lb, lc = {"key": "a", "index": 0}, {"key": "b", "index": 1}, {"key": "c", "index": 2}
    lb_reordered = {"index": 1, "key": "b"}
    w1, w1_again, w2 = {"witness": "w1", "sig": "x1"}, {"witness": "w1", "sig": "x1-other"}, {"witness": "w2", "sig": "x2"}
    ev1_cosigs = [w1]
    hops = [
        {"domain": "d1", "head": {"head": {"size": 3, "root": "r1"}, "sig": "s1", "cosigs": ev1_cosigs}, "inclusion": {"i": 1},
         "revocation": {"cap": {"size": 5, "lo": la, "hi": lb}, "issuer_key": {"size": 5}}, "binding": {"b": 1}},
        # the same head (members in another order, same sig): one table entry, its new witness merged in
        {"domain": "d2", "head": {"head": {"root": "r1", "size": 3}, "sig": "s1", "cosigs": [w1_again, w2]},
         "inclusion": {"i": 2}, "revocation": {"cap": {"size": 5, "lo": lb_reordered}, "issuer_key": {"size": 6, "hi": lc}}},
        # the same head content under another sig, and another head under the same sig: separate entries
        {"domain": "d3", "head": {"head": {"size": 3, "root": "r1"}, "sig": "s2", "cosigs": []}, "inclusion": {"i": 3},
         "revocation": {"cap": {"size": 1, "lo": la}, "issuer_key": {"size": 1}}},
        {"domain": "d4", "head": {"head": {"size": 4, "root": "r1"}, "sig": "s1", "cosigs": [w2]}, "inclusion": {"i": 4},
         "revocation": {"cap": {"size": 2}, "issuer_key": {"size": 2}}},
    ]
    sig = _b64u(leaf.sign(MESH_ACTION_DOMAIN.encode("utf-8")
                          + canonical_bytes_strict({"action": action, "tip": hash_canonical(chain[-1])})))
    want = {
        "chain": chain,
        "heads": [{"head": {"size": 3, "root": "r1"}, "sig": "s1", "cosigs": [w1, w2]},
                  {"head": {"size": 3, "root": "r1"}, "sig": "s2", "cosigs": []},
                  {"head": {"size": 4, "root": "r1"}, "sig": "s1", "cosigs": [w2]}],
        "rev_leaves": [la, lb, lc],
        "hops": [
            {"domain": "d1", "head": 0, "inclusion": {"i": 1},
             "revocation": {"cap": {"size": 5, "lo": 0, "hi": 1}, "issuer_key": {"size": 5}}, "binding": {"b": 1}},
            {"domain": "d2", "head": 0, "inclusion": {"i": 2},
             "revocation": {"cap": {"size": 5, "lo": 1}, "issuer_key": {"size": 6, "hi": 2}}},
            {"domain": "d3", "head": 1, "inclusion": {"i": 3}, "revocation": {"cap": {"size": 1, "lo": 0}, "issuer_key": {"size": 1}}},
            {"domain": "d4", "head": 2, "inclusion": {"i": 4}, "revocation": {"cap": {"size": 2}, "issuer_key": {"size": 2}}},
        ],
        "action": action,
        "action_sig": sig,
    }
    assert S.assemble_mesh_proof(chain, hops, action, leaf) == want
    assert ev1_cosigs == [w1]  # the caller's cosignature list is copied, never extended
    assert S.assemble_mesh_proof(chain, hops, action, leaf, []) == want
    pins = [{"domain": "d1", "proof": {"size": 3}}]
    assert S.assemble_mesh_proof(chain, hops, action, leaf, pins) == dict(want, pin_proofs=pins)
