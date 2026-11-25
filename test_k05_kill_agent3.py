"""Mutation-kill tests for the agent side (atlas_pca.agent) and its OpenSSL signing binding (atlas_pca.pq_backends): the default
signer opt-in, ML-DSA signing through dilithium-py, the envelope members' validation order (envelope.ts mintGrant), the
default agent binding, the PCA-Provenance header cap (adapters.ts PROV_HEADER_MAX, inclusive), Ed25519 sub-agents and the
OpenSSL capability probe. Nothing here runs at import: every key is made inside a test."""
import ctypes
import sys

import pytest

from atlas_pca import agent as G
from atlas_pca import pq_backends as PB
from atlas_pca.pca import b64u, canonical_bytes_strict, unb64u


def _kp(n):
    return G.keypair_from_seed(bytes([n]) * 32)


def _env(**extra):
    env = {"predicates": [], "caveats": [], "risk_policy": G.DEFAULT_RISK_POLICY}
    env.update(extra)
    return env


# ---- keys -------------------------------------------------------------------------------------------------------------------

def test_generate_keypair_refuses_the_builtin_signer_by_default(monkeypatch):
    assert G.generate_keypair()._allow_insecure is False
    assert G.generate_keypair(allow_insecure_signer=True)._allow_insecure is True
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric.ed25519", None)
    monkeypatch.setattr(G._ed, "_ALLOW_INSECURE", False)
    with pytest.raises(RuntimeError) as e:
        G.generate_keypair().sign(b"m")
    assert str(e.value) == G._ed.INSECURE_SIGNER_REFUSED


class _Mldsa:
    """dilithium-py's ML_DSA_* surface: sign(sk, m, ctx=b"", deterministic=False), key_derive(seed) -> (pk, sk)."""

    def __init__(self):
        self.calls = []

    def sign(self, sk, m, ctx=b"", deterministic=False):
        self.calls.append((sk, m, ctx, deterministic))
        return b"SIG"

    def key_derive(self, seed):
        return b"PK" + seed[:1], b"SK"


def test_pq_keypair_signs_deterministically_with_its_own_secret(monkeypatch):
    impl = _Mldsa()
    monkeypatch.setitem(G._ML_DSA, "ML-DSA-65", impl)
    kp = G.PqKeyPair("ML-DSA-65", b"PK", b"SK")
    assert kp.sign(b"msg") == b"SIG"
    # FIPS 204 deterministic variant (rnd = 0^32), pure mode, empty context: as the TypeScript reference signs
    assert impl.calls == [(b"SK", b"msg", b"", True)] and impl.calls[0][3] is True


def test_dilithium_fallback_key_carries_its_family(monkeypatch):
    impl = _Mldsa()
    monkeypatch.setattr(PB, "openssl_available", lambda f: False)
    monkeypatch.setitem(G._ML_DSA, "ML-DSA-87", impl)
    k = G.generate_pq_keypair("ML-DSA-87", seed=b"\x01" * 32)
    assert type(k) is G.PqKeyPair and k.family == "ML-DSA-87" and k.public_bytes == b"PK\x01" and k.secret == b"SK"
    assert k.sign(b"m") == b"SIG" and impl.calls == [(b"SK", b"m", b"", True)]


# ---- mint_grant: optional envelope members ----------------------------------------------------------------------------------

@pytest.mark.parametrize("members,err", [
    ({"units": 5}, "units must be an object"),
    ({"tighten": [5]}, "tighten[0] must be an object"),
    ({"tighten": None}, "tighten must be an array"),  # present and null is checked (JSON null is not absent)
    ({"template_ref": 5}, "template_ref must be an object"),
    ({"actions": 5}, "actions must be an object"),
    ({"provenance": 5}, "provenance must be an object"),
    # the reference's order (envelope.ts mintGrant): units, tighten, template_ref, actions, provenance
    ({"units": 5, "tighten": [5]}, "units must be an object"),
    ({"tighten": [5], "template_ref": 5}, "tighten[0] must be an object"),
    ({"template_ref": 5, "actions": 5}, "template_ref must be an object"),
    ({"actions": 5, "provenance": 5}, "actions must be an object"),
    ({}, None),
    ({"units": {}, "tighten": []}, None),
])
def test_envelope_members_are_checked_in_reference_order(members, err):
    assert G._envelope_member_error(members) == err
    if err is None:
        return
    with pytest.raises(ValueError) as e:
        G.mint_grant(_kp(91), "H", _env(**members), "goal", salt="s")
    assert str(e.value) == "mint_grant: " + err


def test_mint_grant_agent_binding_defaults_to_an_empty_object():
    p = _kp(91)
    for env in (_env(), _env(agent_binding=None)):  # `agent_binding ?? {}`
        assert G.mint_grant(p, "H", env, "goal", salt="s")["grant"]["caveats"][0]["agent_binding"] == {}
    got = G.mint_grant(p, "H", _env(agent_binding={"k": "v"}), "goal", salt="s")["grant"]["caveats"][0]["agent_binding"]
    assert got == {"k": "v"}


# ---- PCA-Provenance header ----------------------------------------------------------------------------------------------------

def test_provenance_header_is_the_strict_canonical_bundle_up_to_8192_characters():
    small = {"a": "b"}
    h = G.pca_headers({"v": 1}, provenance=small)
    assert unb64u(h["PCA-Provenance"]) == b'{"a":"b"}'
    fits = {"a": "x" * 6136}  # 6,144 canonical bytes encode to exactly 8,192 base64url characters
    raw = canonical_bytes_strict(fits)
    assert len(raw) == 6144
    h = G.pca_headers({"v": 1}, provenance=fits)
    assert h["PCA-Provenance"] == b64u(raw) and len(h["PCA-Provenance"]) == G.PROV_HEADER_MAX == 8192
    assert "PCA-Provenance" not in G.pca_headers({"v": 1}, provenance={"a": "x" * 6137})  # 8,194 characters: body only


# ---- Agent.delegate (Ed25519) -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("alg", [None, "ed25519"])
def test_ed25519_sub_agent_appends_one_hop_and_keeps_the_settings(alg):
    principal, agent, sub = _kp(91), _kp(93), _kp(94)
    grant = G.mint_grant(principal, agent.public, _env(), "goal", salt="s")["grant"]

    def clock():
        return 1000
    parent = G.Agent(agent, grant, "https://api.example", clock=clock, ttl_ms=12345, alg=alg)
    child = parent.delegate(sub, [{"type": "c"}])
    cap = child.chain[-1]
    assert len(child.chain) == 2 and child.chain[0] is grant
    assert cap == G.delegate(grant, agent, sub.public, [{"type": "c"}])
    assert cap["holder"] == sub.public and cap["caveats"] == grant["caveats"] + [{"type": "c"}]
    assert "alg" not in cap and "pq_pk" not in cap
    assert child.key is sub and child.grant is grant and child.aud == "https://api.example"
    assert child.ttl_ms == 12345 and child.clock is clock and child.counter == 0 and child.alg is None and child.pq is None


# ---- pq_backends ------------------------------------------------------------------------------------------------------------

def test_openssl_available_never_offers_less_or_an_unknown_type(monkeypatch):
    monkeypatch.setattr(PB, "_openssl_available", lambda kt: True)
    assert PB.openssl_available("LESS-cat1") is False  # LESS is never an OpenSSL key type, whatever the probe says
    assert PB.openssl_available("nope") is False
    assert PB.openssl_available("ML-DSA-65") is True and PB.openssl_available("SLH-DSA-SHA2-256s") is True
    monkeypatch.setattr(PB, "_openssl_available", lambda kt: False)
    assert PB.openssl_available("ML-DSA-65") is False


class _Fn:
    restype = argtypes = "unset"


class _ProtoLib:
    def __getattr__(self, name):
        if not name.startswith("EVP_"):
            raise AttributeError(name)
        f = _Fn()
        self.__dict__[name] = f
        return f


def test_bind_sign_declares_the_set_params_prototype():
    lib = _ProtoLib()
    assert PB._bind_sign(lib) is lib
    assert lib.EVP_PKEY_CTX_set_params.restype is ctypes.c_int
    assert lib.EVP_PKEY_CTX_set_params.argtypes == [ctypes.c_void_p, ctypes.c_void_p]
