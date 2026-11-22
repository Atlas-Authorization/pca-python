"""Mesh trust verifier (atlas_pca/mesh.py): kill tests for the paths the shared vectors do not reach. A real signed proof is
built here (domain, witness and holder keys are deterministic seeds generated at test load); verify_chain, verify_inclusion
and verify_non_membership are replaced by recorders so a test reaches the checks after them with exact arguments."""
import os

import pytest

from atlas_pca import mesh as M
from atlas_pca.agent import KeyPair
from atlas_pca.pca import b64u, canonical_bytes_strict, cap_hash  # noqa: F401

NOW = 1_800_000_000_000
DK, WK, HK, AK = (KeyPair(os.urandom(32)) for _ in range(4))  # generated at load, never committed
D, W = DK.public, WK.public
ACTION = {"type": "read", "resource": "/x", "service_domain": "svc", "nonce": "n", "at": NOW}
V_OK = M.MeshVerdict(True, None, -1)


def _sig(k, domain, body):
    return b64u(k.sign(domain.encode() + canonical_bytes_strict(body)))


def _trust(**kw):
    t = {"humanPrincipal": "h", "witnesses": [W], "threshold": 1, "now": NOW, "allowedDomains": [D], "rootDomain": D}
    t.update(kw)
    return t


def _head(**kw):
    h = {"domain": D, "size": 1, "root": "r", "rev_root": "v", "rev_size": 0, "timestamp": NOW}
    h.update(kw)
    return {"head": h, "sig": _sig(DK, M.MESH_HEAD_DOMAIN, h), "cosigs": [{"witness": W, "sig": _sig(WK, M.MESH_COSIG_DOMAIN, h)}]}


def _hop(binding=None):
    h = {"domain": D, "head": 0, "inclusion": {"index": 0, "size": 1, "path": []},
         "revocation": {"cap": {"size": 0}, "issuer_key": {"size": 0}}}
    if binding is not None:
        h["binding"] = binding
    return h


def _proof(caps, hops, heads=None, action=ACTION, **extra):
    p = {"chain": caps, "hops": hops, "heads": [_head()] if heads is None else heads, "rev_leaves": [],
         "action": action, "action_sig": _sig(HK, M.MESH_ACTION_DOMAIN, {"action": action, "tip": cap_hash(caps[-1])})}
    p.update(extra)
    return p


CAP0 = {"id": "c0", "issuer": "root", "holder": HK.public, "caveats": []}


@pytest.fixture
def calls(monkeypatch):
    rec = {"chain": [], "nm": []}

    def vc(*a):
        rec["chain"].append(a)
        return True, None

    def nm(_root, _c, ident):
        rec["nm"].append(ident)
        return True

    monkeypatch.setattr(M, "verify_chain", vc)
    monkeypatch.setattr(M, "verify_inclusion", lambda *a: True)
    monkeypatch.setattr(M, "verify_non_membership", nm)
    return rec


def test_a_signed_single_hop_proof_is_accepted(calls):
    assert M.verify_mesh_proof(_proof([CAP0], [_hop()]), _trust()) == V_OK
    assert calls["nm"] == ["c0", "key:root"]


def test_a_capability_without_id_or_issuer_uses_empty_strings(calls):
    bare = {"holder": HK.public, "caveats": []}
    assert M.verify_mesh_proof(_proof([bare], [_hop()]), _trust()) == V_OK
    assert calls["nm"] == ["", "key:"]


def test_non_dict_proof_and_missing_tables_are_malformed(calls):
    for p in (5, None, "x", []):
        assert M.verify_mesh_proof(p, _trust()) == M.MeshVerdict(False, "malformed proof", -1), p
    assert M.verify_mesh_proof({}, _trust()) == M.MeshVerdict(False, "malformed proof", -1)
    assert M.verify_mesh_proof({"chain": [], "hops": [], "heads": [], "rev_leaves": "x"}, _trust()) == M.MeshVerdict(False, "malformed proof", -1)


def test_an_exception_inside_verification_is_a_malformed_proof(calls):
    class Boom(dict):
        def get(self, *a, **k):
            raise ValueError("boom")

    assert M.verify_mesh_proof(Boom(), _trust()) == M.MeshVerdict(False, "malformed proof", -1)


def test_pin_proofs_bound_is_inclusive(calls):
    entry = {"domain": "d", "proof": {"oldSize": 0, "newSize": 1, "path": []}}
    base = {"chain": [], "hops": [], "heads": [], "rev_leaves": [], "action": ACTION, "action_sig": "s"}
    assert M.verify_mesh_proof(dict(base, pin_proofs=[entry] * 256), _trust()) == M.MeshVerdict(False, "chain length out of bounds", -1)
    assert M.verify_mesh_proof(dict(base, pin_proofs=[entry] * 257), _trust()) == M.MeshVerdict(False, "malformed pin proofs", -1)


def test_evidence_tables_are_bounded_by_the_chain(calls):
    base = {"chain": [{}], "hops": [], "heads": [], "rev_leaves": [], "action": ACTION, "action_sig": "s"}
    assert M.verify_mesh_proof(dict(base, rev_leaves=[{}] * 3), _trust()) == M.MeshVerdict(False, "evidence tables exceed chain size", -1)
    assert M.verify_mesh_proof(dict(base, rev_leaves=[{}] * 2), _trust()) == M.MeshVerdict(False, "hop evidence count does not match chain length", -1)
    assert M.verify_mesh_proof(dict(base, heads=[{}, {}]), _trust()) == M.MeshVerdict(False, "evidence tables exceed chain size", -1)


def test_chain_verifier_gets_the_human_and_the_pins_and_its_reason_is_prefixed(monkeypatch):
    seen = []

    def vc(*a):
        seen.append(a)
        return False, "why"

    monkeypatch.setattr(M, "verify_chain", vc)
    chain = [CAP0]
    got = M.verify_mesh_proof(_proof(chain, [_hop()]), _trust(pqPins={"k": "v", "x": 5}))
    assert got == M.MeshVerdict(False, "chain: why", -1)
    assert seen == [(chain, "h", None, {"k": "v"}, None)]


def test_a_non_dict_head_entry_is_a_malformed_proof(calls):
    p = _proof([CAP0], [_hop()], heads=[5])
    assert M.verify_mesh_proof(p, _trust()) == M.MeshVerdict(False, "malformed proof", -1)
    assert M._verify(p, _trust()) == M.MeshVerdict(False, "malformed proof", -1)  # an explicit verdict, not an exception
    p = _proof([CAP0], [_hop()], heads=[{}])
    assert M._verify(p, _trust()) == M.MeshVerdict(False, "malformed proof", -1)


def _two_hops(child_caveats, parent_caveats):
    c0 = dict(CAP0, caveats=parent_caveats)
    c1 = {"id": "c1", "issuer": AK.public, "holder": HK.public, "caveats": child_caveats}
    bind = {"agent": AK.public, "domain": D, "role": "r"}
    bind["sig"] = _sig(DK, M.MESH_BINDING_DOMAIN, {"agent": AK.public, "domain": D, "role": "r"})
    return _proof([c0, c1], [_hop(), _hop(bind)])


def test_a_hop_that_widens_authority_is_refused_at_its_index(calls):
    wide = _two_hops([{"type": "scope", "actions": ["read", "delete"]}], [{"type": "scope", "actions": ["read"]}])
    assert M.verify_mesh_proof(wide, _trust()) == M.MeshVerdict(False, "hop widens authority", 1)
    ok = _two_hops([{"type": "scope", "actions": ["read"]}], [{"type": "scope", "actions": ["read", "write"]}])
    assert M.verify_mesh_proof(ok, _trust()) == V_OK


def test_cosignature_list_bound_is_inclusive(calls):
    one = _head()
    full = dict(one, cosigs=one["cosigs"] + [None] * 255)
    assert M.verify_mesh_proof(_proof([CAP0], [_hop()], heads=[full]), _trust()) == V_OK
    over = dict(one, cosigs=one["cosigs"] + [None] * 256)
    assert M.verify_mesh_proof(_proof([CAP0], [_hop()], heads=[over]), _trust()) == M.MeshVerdict(False, "source-domain anchor: malformed head", 0)


def test_trust_configuration_defaults_and_pq_pin_filter():
    c = M._valid_trust(_trust())
    assert c["issuer_domains"] is None and c["pinned"] is None and c["pq_pins"] is None
    c = M._valid_trust(_trust(issuerDomains={}, pinnedHeads={}, pqPins={"k": "v", "x": 5}))
    assert c["issuer_domains"] == {} and c["pinned"] == {} and c["pq_pins"] == {"k": "v"}


def test_path_bounds_are_inclusive():
    assert M._valid_consistency({"oldSize": 1, "newSize": 2, "path": ["a"] * 128}) is not None
    assert M._valid_consistency({"oldSize": 1, "newSize": 2, "path": ["a"] * 129}) is None
    assert M._valid_inclusion({"index": 0, "size": 1, "path": ["a"] * 128}) is not None
    assert M._valid_inclusion({"index": 0, "size": 1, "path": ["a"] * 129}) is None


def test_audience_is_sorted_by_utf8_order_not_code_point_order():
    # a lone surrogate encodes as U+FFFD (EF BF BD), after U+E000 (EE 80 80); plain code-point order puts it first
    assert M._intersect(False, None, ["\ud800", "", "\ud800"]) == ["", "\ud800"]


def _eff(**kw):
    e = {"actions": None, "prefixes": [], "max_amount": None, "expires_at": None, "audience": None, "max_hops": None}
    e.update(kw)
    return e


def test_narrowing_rules():
    for k in ("actions", "audience"):
        assert M._narrows(_eff(**{k: None}), _eff(**{k: ["a"]})) is False   # child unbounded under a bounded parent
        assert M._narrows(_eff(**{k: ["b"]}), _eff(**{k: ["a"]})) is False  # child member outside the parent
        assert M._narrows(_eff(**{k: ["a"]}), _eff(**{k: ["a", "b"]})) is True
        assert M._narrows(_eff(**{k: ["a"]}), _eff(**{k: None})) is True
    for k in ("max_amount", "expires_at", "max_hops"):
        assert M._narrows(_eff(**{k: None}), _eff(**{k: 5})) is False
        assert M._narrows(_eff(**{k: 6}), _eff(**{k: 5})) is False
        assert M._narrows(_eff(**{k: 5}), _eff(**{k: 5})) is True
        assert M._narrows(_eff(**{k: 4}), _eff(**{k: 5})) is True
        assert M._narrows(_eff(**{k: 4}), _eff(**{k: None})) is True


def test_verify_returns_the_malformed_verdict_itself(calls):
    bad = M.MeshVerdict(False, "malformed proof", -1)
    for p in (5, None, "x", []):
        assert M._verify(p, _trust()) == bad, p
    assert M._verify({}, _trust()) == bad
    assert M._verify({"chain": [], "hops": [], "heads": [], "rev_leaves": "x"}, _trust()) == bad
