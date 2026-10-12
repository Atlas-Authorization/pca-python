"""Mutation kills (batch B): verification logic of atlas_pca/pca.py -- wire v2, verify_pcactn_core, verify_chain, threshold
shares / signer set, the PQ-key choke point, suites, inclusion, caveats. Self-contained: PCActns, capability hops and
threshold shares are minted here with a tiny RFC 8032 signer over the verifier's own curve arithmetic (and dilithium-py for
ML-DSA-65, skipped when absent), so every assertion is an exact verdict / check map / reason / return value."""
import copy
import hashlib
import time

import pytest

from atlas_pca import ed25519 as E
from atlas_pca import mldsa
from atlas_pca import pca
from atlas_pca.pca import (
    CAP_DOMAIN, EMPTY_PARAMS_DIGEST, PCACTN_VERSION, _PinnedPq, _plan_leaf, _resolve_pq_key, b64u,
    canonical_bytes_strict, caveat_limit_exceeded, conditions_digest, hash_canonical, holder_pq_commitment,
    merkle_root, pq_binding_error, sha256, share_suite_tag, signer_set_hash, threshold_message, unb64u,
    validate_wire_v2, verify_artifact_suite, verify_chain, verify_inclusion, verify_leaf_suite, verify_pcactn_core,
    verify_threshold_share,
)

ML = mldsa._ML_DSA_65
needs_mldsa = pytest.mark.skipif(ML is None, reason="dilithium-py (ML-DSA-65) not installed")


# ---- minting helpers (tests only) -----------------------------------------------------------------------------------

def _enc(P):
    zi = E._inv(P[2])
    x, y = P[0] * zi % E._p, P[1] * zi % E._p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _keys(label):
    h = hashlib.sha512(hashlib.sha256(label.encode()).digest()).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], _enc(E._mul(a, E._G))


def _sign(k, msg):
    a, prefix, A = k
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % E._q
    R = _enc(E._mul(r, E._G))
    h = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % E._q
    return R + ((r + h * a) % E._q).to_bytes(32, "little")


def _pub(k):
    return b64u(k[2])


PRINCIPAL, AGENT, GUARDIAN, OTHER = _keys("kb-principal"), _keys("kb-agent"), _keys("kb-guardian"), _keys("kb-other")
CAVEATS = [{"type": "max_spend", "usd": 100}]
AUD = "aud-kill-b"
NOW = 1_700_000_000_000


def _cap(issuer_k, holder_pub, caveats, parent=None, pq=None):
    """A capability hop. `pq` = (pk_bytes, sk) makes it a pure ml-dsa-65 hop (alg + pq_pk bound into the body)."""
    body = {"issuer": _pub(issuer_k), "holder": holder_pub, "caveats": caveats, "parent": parent}
    if pq is not None:
        body["alg"], body["pq_pk"] = "ml-dsa-65", b64u(pq[0])
    d = hash_canonical(body)
    hop = {"id": d, "issuer": body["issuer"], "holder": holder_pub, "caveats": caveats, "body_digest": d}
    if parent is not None:
        hop["parent"] = parent
    msg = CAP_DOMAIN + unb64u(d)
    if pq is None:
        hop["sig"] = b64u(_sign(issuer_k, msg))
    else:
        hop["alg"], hop["pq_pk"], hop["sig"] = "ml-dsa-65", b64u(pq[0]), b64u(ML.sign(pq[1], msg))
    return hop


def _pcactn(chain, leaf_k, iat=NOW - 1000, exp=NOW + 600_000, **extra):
    action = {"verb": "read", "resource": "db/x", "params_digest": EMPTY_PARAMS_DIGEST, "reversibility_class": "reversible"}
    leaf = _plan_leaf("n1", action, conditions_digest())
    p = {
        "ver": PCACTN_VERSION, "action": action, "grant_ref": chain[0]["id"], "cap_chain": chain,
        "plan": {"root": merkle_root([leaf]), "inclusion_proof": {"index": 0, "size": 1, "path": []}, "node_id": "n1"},
        "attestation": {"epoch": 1, "quote_digest": "q", "model_id": "m", "measurement": "me", "operator": "o"},
        "provenance": {"causal_hash": "c", "taint_level": 0, "trusted_refs": []},
        "freshness": {"epoch": 1, "beacon_ref": "b", "accumulator_witness": "w"},
        "counter": 0, "risk_claim": {"r": 0, "inputs": {}}, "aud": AUD, "iat": iat, "exp": exp,
    }
    p.update(extra)
    p["sig"] = b64u(_sign(leaf_k, threshold_message(p)))
    return p


ROOT = _cap(PRINCIPAL, _pub(AGENT), CAVEATS)
P0 = _pcactn([ROOT], AGENT)
ALL_OK = {"wire": True, "version": True, "audience": True, "validity": True, "chain": True, "grant_ref_bound": True,
          "plan_inclusion": True, "leaf_signature": True, "counter": True}


class Hostile(Exception):
    pass


def _verify(p, grant=ROOT, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("audience", AUD)
    return verify_pcactn_core(p, grant, **kw)


def test_baseline_self_minted_pcactn_allows():
    v = _verify(P0)
    assert (v.allow, v.checks, v.reason) == (True, ALL_OK, None)
    assert validate_wire_v2(P0) is None
    assert verify_chain([ROOT], _pub(PRINCIPAL)) == (True, None)


# ---- verify_pcactn_core / _verify_pcactn_core_unchecked ---------------------------------------------------------------

def test_now_defaults_to_wall_clock_ms():
    t = int(time.time() * 1000)
    p = _pcactn([ROOT], AGENT, iat=t - 5000, exp=t + 600_000)
    v = verify_pcactn_core(p, ROOT, audience=AUD)  # now=None -> wall clock, in MILLISECONDS
    assert (v.allow, v.checks, v.reason) == (True, ALL_OK, None)
    stale = _pcactn([ROOT], AGENT, iat=t - 900_000, exp=t - 300_000)
    v = verify_pcactn_core(stale, ROOT, audience=AUD)
    assert v.allow is False and v.reason == "validity: the PCActn has expired"


def test_outer_totality_verdict_is_exact():
    class HostileStr(str):
        def __len__(self):
            raise Hostile()

    v = verify_pcactn_core(HostileStr("{}"), ROOT, now=NOW, audience=AUD)
    assert v.allow is False
    assert v.checks == {"wire": False}
    assert v.reason == "wire: malformed input (Hostile)"


def test_inner_malformed_reason_and_checks_exact():
    # The verifier's stored grant is out of the strict profile: hashing it raises inside the check block.
    v = _verify(P0, grant={"x": float("nan")})
    assert v.allow is False
    assert v.checks == {"wire": True, "version": True, "audience": True, "validity": True, "chain": False,
                        "plan_inclusion": False, "leaf_signature": False, "counter": False}
    assert v.reason == "malformed PCActn: canonicalize: non-finite number"
    # an earlier failure keeps its reason (first failure wins)
    v = _verify(P0, grant={"x": float("nan")}, audience="someone-else")
    assert v.reason == "audience: aud does not match this resource server / instance"
    assert v.checks["audience"] is False and v.checks["validity"] is True and v.checks["chain"] is False


def test_verify_chain_wiring(monkeypatch):
    seen = []
    real = pca.verify_chain

    def spy(chain, expected_root_issuer=None, allowed_suites=None, pq_pins=None, trusted_root=None):
        seen.append((chain, expected_root_issuer, allowed_suites, pq_pins, trusted_root))
        return real(chain, expected_root_issuer, allowed_suites, pq_pins=pq_pins, trusted_root=trusted_root)

    monkeypatch.setattr(pca, "verify_chain", spy)
    grant = copy.deepcopy(ROOT)
    v = _verify(P0, grant=grant, allowed_suites=["ed25519"])
    assert v.allow is True
    assert len(seen) == 1
    chain, iss, suites, pins, trusted = seen[0]
    assert chain is P0["cap_chain"] and iss == _pub(PRINCIPAL) and suites == ["ed25519"] and pins is None
    assert trusted is grant


@needs_mldsa
def test_pure_pq_root_grant_is_trusted_root():
    pk, sk = ML.keygen()
    root = _cap(PRINCIPAL, _pub(AGENT), CAVEATS, pq=(pk, sk))
    p = _pcactn([root], AGENT)
    v = _verify(p, grant=copy.deepcopy(root))
    assert (v.allow, v.checks, v.reason) == (True, ALL_OK, None)
    # the standalone chain verifier without the stored grant refuses the same root (R3-01)
    ok, why = verify_chain([root], _pub(PRINCIPAL))
    assert ok is False and why.startswith("hop 0: root suite 'ml-dsa-65' needs a PQ key pinned")


# ---- validate_wire_v2 --------------------------------------------------------------------------------------------------

def test_wire_pq_sig_excluded_from_strict_body():
    p = dict(P0, pq_sig=1e300)  # out-of-profile, but NOT part of the strict body: the suite check reports it
    assert validate_wire_v2(p) == "'pq_sig' must be absent for alg 'ed25519'"


def test_wire_holder_pq_must_be_32_bytes():
    for bad in ("AAAA", b64u(bytes(31)), b64u(bytes(33)), "!" * 43):
        p = copy.deepcopy(P0)
        p["cap_chain"][0]["holder_pq"] = bad
        assert validate_wire_v2(p) == "cap_chain[0].holder_pq is not canonical base64url (32 bytes)", bad
        v = _verify(p)
        assert (v.allow, v.checks, v.reason) == (False, {"wire": False},
                                                 "wire: cap_chain[0].holder_pq is not canonical base64url (32 bytes)")
    p = copy.deepcopy(P0)
    p["cap_chain"][0]["holder_pq"] = b64u(bytes(32))
    assert validate_wire_v2(p) is None


def test_wire_trusted_refs_strings_accepted():
    p = _pcactn([ROOT], AGENT, provenance={"causal_hash": "c", "taint_level": 0, "trusted_refs": ["ref-1", "ref-2"]})
    assert validate_wire_v2(p) is None
    v = _verify(p)
    assert (v.allow, v.checks) == (True, ALL_OK)
    bad = copy.deepcopy(p)
    bad["provenance"]["trusted_refs"] = ["ref-1", 5]
    assert validate_wire_v2(bad) == "'provenance' is malformed"


def test_wire_internal_fault_reason():
    class ItemsBoom(dict):
        def items(self):
            raise ValueError("boom")

    assert validate_wire_v2(ItemsBoom(P0)) == "malformed: boom"


def test_wire_pq_pk_length_is_enforced():
    base = dict(P0, alg="ml-dsa-65", sig=b64u(bytes(3309)))
    assert validate_wire_v2(dict(base, pq_pk=b64u(bytes(1952)))) is None
    for n in (32, 1951, 1953):
        assert validate_wire_v2(dict(base, pq_pk=b64u(bytes(n)))) == "'pq_pk' is not canonical base64url (1952 bytes)", n
        v = _verify(dict(base, pq_pk=b64u(bytes(n))))
        assert (v.allow, v.checks) == (False, {"wire": False})
    hop = dict(ROOT, alg="ml-dsa-65", sig=b64u(bytes(3309)), pq_pk=b64u(bytes(64)))
    assert validate_wire_v2(dict(P0, cap_chain=[hop])) == "cap_chain[0]: 'pq_pk' is not canonical base64url (1952 bytes)"


# ---- verify_chain / _verify_chain_unchecked / _check_sig / caveats -----------------------------------------------------

def test_chain_non_object_hops_are_malformed_capabilities():
    assert caveat_limit_exceeded(["x", 5, None, []]) is False
    assert verify_chain(["x"]) == (False, "hop 0: malformed capability")
    assert verify_chain([ROOT, "x"], _pub(PRINCIPAL)) == (False, "hop 1: malformed capability")
    assert verify_chain([ROOT, {}], _pub(PRINCIPAL)) == (False, "hop 1: malformed capability")


def test_chain_totality_reason_names_the_exception():
    class EvilHop(dict):
        def get(self, *a, **k):
            raise Hostile()

    assert verify_chain([EvilHop()]) == (False, "malformed capability chain: Hostile")


def test_chain_unknown_root_alg_reason():
    root = dict(ROOT, alg="bogus")
    assert verify_chain([root], _pub(PRINCIPAL)) == (False, "hop 0: unknown signature alg 'bogus'")


def test_chain_unknown_hop_alg_reason():
    hop1 = {"id": ROOT["id"], "issuer": ROOT["holder"], "holder": _pub(OTHER), "caveats": list(CAVEATS),
            "body_digest": ROOT["id"], "sig": "x", "parent": hash_canonical(ROOT), "alg": "bogus"}
    assert verify_chain([ROOT, hop1], _pub(PRINCIPAL)) == (False, "hop 1: unknown signature alg 'bogus'")
    assert pq_binding_error("bogus", None, None, "hop 1") is None
    assert pq_binding_error(None, None, None, "x") is None and pq_binding_error("ed25519", None, None, "x") is None


def test_check_sig_undecodable_digest_reason():
    class Weird(dict):  # .get() and [] disagree on body_digest: the digest check passes, decoding the [] value fails
        def __getitem__(self, k):
            return "!" if k == "body_digest" else dict.__getitem__(self, k)

    assert verify_chain([Weird(ROOT)], _pub(PRINCIPAL)) == (False, "hop 0: bad signature (not signed by expected key)")
    forged = dict(ROOT, sig=b64u(_sign(OTHER, CAP_DOMAIN + unb64u(ROOT["body_digest"]))))
    assert verify_chain([forged], _pub(PRINCIPAL)) == (False, "hop 0: bad signature (not signed by expected key)")


# ---- suites / leaf ------------------------------------------------------------------------------------------------------

def test_unknown_suite_never_verifies():
    msg = b"m"
    assert verify_leaf_suite({"alg": "bogus", "sig": "x"}, _pub(AGENT), msg) is False
    assert verify_artifact_suite({"alg": "bogus", "message": b64u(msg), "sig": "x", "ed_pub": _pub(AGENT)}) is False
    good = {"message": b64u(msg), "sig": b64u(_sign(AGENT, msg)), "ed_pub": _pub(AGENT)}
    assert verify_artifact_suite(good) is True
    assert verify_artifact_suite(dict(good, alg="bogus")) is False


def test_leaf_suite_total_on_hostile_mapping():
    class GetBoom(dict):
        def get(self, *a, **k):
            raise RuntimeError

    assert verify_leaf_suite(GetBoom(), _pub(AGENT), b"m") is False


# ---- the PQ-key choke point -------------------------------------------------------------------------------------------

def test_resolve_pq_key_sources_and_empty_key():
    k = _resolve_pq_key(None, None, trusted_pk="T")
    assert isinstance(k, _PinnedPq) and (k.key, k.source) == ("T", "trusted")
    k = _resolve_pq_key("i", "K", pq_pins={"i": "K"})
    assert (k.key, k.source) == ("K", "pin")
    assert _resolve_pq_key("i", "K", pq_pins={"i": "J"}) is None
    k = _resolve_pq_key(None, "K", holder_pq=holder_pq_commitment("K"))
    assert (k.key, k.source) == ("K", "holder-commitment")
    # an EMPTY artifact key is refused before any pin / commitment lookup
    assert _resolve_pq_key("i", "", pq_pins={"i": ""}) is None
    assert _resolve_pq_key(None, "", holder_pq=holder_pq_commitment("")) is None
    assert _resolve_pq_key(None, None) is None


# ---- inclusion ----------------------------------------------------------------------------------------------------------

def test_inclusion_sibling_must_be_32_bytes():
    leaf = {"a": 1}
    lh = sha256(b"\x00" + canonical_bytes_strict(leaf))
    for n, want in ((32, True), (16, False), (31, False), (33, False), (64, False)):
        sib = bytes(range(n))
        root = b64u(sha256(b"\x01" + lh + sib))  # a root honestly computed over the odd-length sibling
        proof = {"index": 0, "size": 2, "path": [{"side": "R", "hash": b64u(sib)}]}
        assert verify_inclusion(root, proof, leaf) is want, n


# ---- signer set / threshold shares --------------------------------------------------------------------------------------

def test_signer_set_hash_rejects_malformed_entries():
    assert signer_set_hash([{"role": "agent", "publicKey": 5}, {"role": "guardian", "publicKey": "k"}]) is None
    assert signer_set_hash([{"role": 5, "publicKey": "k"}, {"role": "guardian", "publicKey": "j"}]) is None
    assert signer_set_hash(["x"]) is None and signer_set_hash(["x", {"role": "agent", "publicKey": "k"}]) is None
    assert signer_set_hash([{"role": "agent"}]) is None and signer_set_hash([{"publicKey": "k"}]) is None
    assert signer_set_hash([{"role": "agent", "publicKey": "k"}]) is not None


def test_share_suite_tag_exact():
    assert share_suite_tag(None) == b"" and share_suite_tag("ed25519") == b"" and share_suite_tag("bogus") == b""
    assert share_suite_tag(5) == b""
    assert share_suite_tag("ml-dsa-65") == b"\x00atlas-pca/share-suite/v1\x00ml-dsa-65"
    assert share_suite_tag("hybrid-ed25519-ml-dsa-65") == b"\x00atlas-pca/share-suite/v1\x00hybrid-ed25519-ml-dsa-65"


THR = b"atlas-pca/actn/v2\x00" + bytes(range(32))


def _share_msg(role, signer_set, t, tag=b""):
    """Independent re-derivation of the v2.1 share message (no library share_message / share_suite_tag)."""
    return ("atlas-pca/share/" + role + "\x00").encode() + sha256(THR) + signer_set_hash(signer_set) + bytes([t]) + tag


def _entry(role, k, signer_set, t=1, **share_extra):
    share = {"role": role, "publicKey": _pub(k), "sig": b64u(_sign(k, _share_msg(role, signer_set, t)))}
    share.update(share_extra)
    return {"role": role, "t": t, "signer_set": signer_set, "threshold_message": b64u(THR), "share": share}


def test_explicit_ed25519_share_signs_the_untagged_message():
    ss = [{"role": "agent", "publicKey": _pub(AGENT)}]
    assert verify_threshold_share(_entry("agent", AGENT, ss)) is True
    assert verify_threshold_share(_entry("agent", AGENT, ss, alg="ed25519")) is True


def test_duplicate_signer_entry_does_not_stop_registry_validation():
    a = {"role": "agent", "publicKey": _pub(AGENT)}
    g = {"role": "guardian", "publicKey": _pub(GUARDIAN)}
    ss = [a, dict(a), g]
    assert verify_threshold_share(_entry("guardian", GUARDIAN, ss)) is True
    assert verify_threshold_share(_entry("agent", AGENT, ss)) is True
    bad = [a, dict(a), {"role": "bogus", "publicKey": _pub(GUARDIAN)}]
    assert verify_threshold_share(_entry("agent", AGENT, bad)) is False
    bad2 = [a, dict(a), {"role": "guardian", "publicKey": _pub(AGENT)}]  # one key under two roles, after a duplicate
    assert verify_threshold_share(_entry("agent", AGENT, bad2)) is False


@needs_mldsa
def test_pq_share_pq_pk_must_equal_the_registered_key():
    pk, sk = ML.keygen()
    reg = b64u(pk)
    ss = [{"role": "agent", "publicKey": _pub(AGENT), "pq_pk": reg}]
    tag = b"\x00atlas-pca/share-suite/v1\x00ml-dsa-65"
    sig = b64u(ML.sign(sk, _share_msg("agent", ss, 1, tag)))
    share = {"role": "agent", "publicKey": _pub(AGENT), "sig": sig, "alg": "ml-dsa-65"}
    entry = {"role": "agent", "t": 1, "signer_set": ss, "threshold_message": b64u(THR), "share": share}
    assert verify_threshold_share(entry) is True
    assert verify_threshold_share(dict(entry, share=dict(share, pq_pk=reg))) is True
    # a share naming a DIFFERENT pq_pk is refused even though its signature verifies under the registered key
    # (natives agree: go-pca threshold.go / rust-pca lib.rs refuse it too)
    other = b64u(bytes(1952))
    assert verify_threshold_share(dict(entry, share=dict(share, pq_pk=other))) is False
    # a role WITHOUT a registered pq_pk never accepts a PQ share
    ss_ed = [{"role": "agent", "publicKey": _pub(AGENT)}]
    sig2 = b64u(ML.sign(sk, _share_msg("agent", ss_ed, 1, tag)))
    e2 = {"role": "agent", "t": 1, "signer_set": ss_ed, "threshold_message": b64u(THR),
          "share": {"role": "agent", "publicKey": _pub(AGENT), "sig": sig2, "alg": "ml-dsa-65", "pq_pk": reg}}
    assert verify_threshold_share(e2) is False


# ---- batch B2 -----------------------------------------------------------------------------------------------------------

def test_b2_resolve_pq_key_refusals():
    assert _resolve_pq_key(None, None, trusted_pk="") is None  # an empty trusted key is no key
    assert _resolve_pq_key(None, "K", trusted_pk="") is None
    assert _resolve_pq_key(None, "K", holder_pq="not-the-commitment") is None  # a holder_pq that does not commit to K
    assert _resolve_pq_key(None, "K", holder_pq=holder_pq_commitment("J")) is None
    assert _resolve_pq_key(None, "K", holder_pq=None) is None


def test_b2_pq_suite_without_a_resolved_key_never_verifies():
    msg = b"m"
    assert verify_leaf_suite({"alg": "ml-dsa-65", "sig": b64u(bytes(3309))}, _pub(AGENT), msg) is False
    hyb = {"alg": "hybrid-ed25519-ml-dsa-65", "sig": b64u(_sign(AGENT, msg)), "pq_sig": b64u(bytes(3309))}
    assert verify_leaf_suite(hyb, _pub(AGENT), msg) is False


def test_b2_leaf_suite_message_must_be_bytes():
    msg = b"payload"
    p = {"sig": b64u(_sign(AGENT, msg))}
    assert verify_leaf_suite(p, _pub(AGENT), msg) is True and verify_leaf_suite(p, _pub(AGENT), bytearray(msg)) is True
    assert verify_leaf_suite(p, _pub(AGENT), list(msg)) is False  # bytes(list) would be the same bytes
    assert verify_leaf_suite(p, _pub(AGENT), msg.decode()) is False
    assert verify_leaf_suite([("sig", p["sig"])], _pub(AGENT), msg) is False


@needs_mldsa
def test_b2_undecodable_pinned_pq_key_is_a_bad_signature():
    issuer, holder = _pub(PRINCIPAL), _pub(AGENT)
    body = {"issuer": issuer, "holder": holder, "caveats": CAVEATS, "parent": None, "alg": "ml-dsa-65", "pq_pk": "AAAA"}
    d = hash_canonical(body)
    hop = {"id": d, "issuer": issuer, "holder": holder, "caveats": CAVEATS, "body_digest": d, "alg": "ml-dsa-65",
           "pq_pk": "AAAA", "sig": b64u(bytes(3309))}
    assert verify_chain([hop], issuer, pq_pins={issuer: "AAAA"}) == (False, "hop 0: bad signature (not signed by expected key)")


def test_b2_threshold_share_total_on_hostile_entry():
    class GetBoom(dict):
        def get(self, *a, **k):
            raise RuntimeError

    assert verify_threshold_share(GetBoom()) is False


def test_b2_wire_sig_and_threshold_excluded_from_strict_body():
    assert validate_wire_v2(dict(P0, sig="\ud800")) == "'sig' is not canonical base64url (64 bytes) for alg 'ed25519'"
    assert validate_wire_v2(dict(P0, threshold={"x": 1e300})) == "'threshold' must be {shares:[...]}"


def test_b2_wire_threshold_share_public_key_is_32_bytes():
    def thr(pk):
        return dict(P0, threshold={"shares": [{"role": "agent", "publicKey": pk, "sig": b64u(bytes(64))}]})

    assert validate_wire_v2(thr(b64u(bytes(32)))) is None
    for n in (16, 31, 33):
        assert validate_wire_v2(thr(b64u(bytes(n)))) == "threshold.shares[0].publicKey is not canonical base64url (32 bytes)", n
        v = _verify(thr(b64u(bytes(n))))
        assert (v.allow, v.checks) == (False, {"wire": False})


def test_b2_signer_set_hash_empty_and_tag_unhashable():
    assert signer_set_hash([]) is None and signer_set_hash(None) is None and signer_set_hash({}) is None
    assert share_suite_tag([]) == b"" and share_suite_tag({}) == b""


def test_b2_caveat_limit_counts_only_lists():
    f = caveat_limit_exceeded
    assert f([{"caveats": "x" * 300}]) is False and f([{"caveats": None}]) is False and f([{"caveats": {"a": 1}}]) is False
    assert f([{}] * 1025) is False
    full = {"caveats": [{"type": "x"}] * 256}
    assert f([full] * 4 + [{}]) is False and f([full] * 4 + [{"caveats": "x"}]) is False
    assert f([full] * 4 + [{"caveats": [{"type": "x"}]}]) is True
    assert f([{"caveats": [{"type": "x"}] * 257}]) is True
    assert verify_chain([dict(ROOT, caveats=None)]) == (False, "hop 0: malformed capability")
    assert verify_chain([dict(ROOT, caveats="x" * 300)]) == (False, "hop 0: malformed capability")
