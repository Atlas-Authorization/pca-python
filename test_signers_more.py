"""The extra producer-side signers: every refusal text, and round trips through this package's own verifiers. Keys are the
fixed test seeds of the producer vector file."""
import copy
import json
import os

import pytest

from atlas_pca import signers_more as S
from atlas_pca.agent import keypair_from_seed
from atlas_pca.intent_v2 import check_revocation_epoch, verify_action_schema, verify_session_root
from atlas_pca.intent_wb import (FACT_DOMAIN, OFFER_SET_DOMAIN, decide_offer_set, offer_set_ref, validate_fact_wire,
                                 validate_offer_set_wire, verify_artifact_sig, verify_labels)
from atlas_pca.pca import unb64u

FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance", "producer-vectors.json")
with open(FILE, encoding="utf-8") as f:
    DOC = json.load(f)
K = {n: keypair_from_seed(unb64u(e["seed"])) for n, e in DOC["keys"].items()}
NOW = 1_800_000_001_000


def args(name):
    return copy.deepcopy(next(c for c in DOC["cases"] if c["name"] == name)["args"])


def refuses(fn, text):
    with pytest.raises(ValueError) as e:
        fn()
    assert str(e.value) == text


def test_threshold_share_refusals():
    a = args("threshold-share-agent")
    msg = unb64u(a["message"])
    refuses(lambda: S.sign_threshold_share("agent", K["agent"], msg, a["signer_set"], 4), "sign_threshold_share: t must be 1, 2 or 3")
    refuses(lambda: S.sign_threshold_share("agent", K["agent"], msg, a["signer_set"], True), "sign_threshold_share: t must be 1, 2 or 3")
    refuses(lambda: S.sign_threshold_share("agent", K["agent"], msg, [{"role": "agent"}], 2), "sign_threshold_share: malformed signer set")


def test_pq_binding_refusals_and_pin():
    pq_pk = args("pq-binding")["pq_pk"]
    for epoch in (0, -1, True, 2 ** 53):
        refuses(lambda: S.sign_pq_binding(K["agent"], pq_pk, epoch, "rs"), "sign_pq_binding: epoch must be a positive safe integer")
    refuses(lambda: S.sign_pq_binding(K["agent"], pq_pk, 1, ""), "sign_pq_binding: aud (the instance/audience id) is required")
    b = S.sign_pq_binding(K["agent"], pq_pk, 1, "rs")
    assert S.pq_pin_for(b, "rs") is not None
    assert S.pq_pin_for(b, "other-rs") is None


def test_caution_refusals():
    body = args("caution")["body"]
    h = K["agent"]
    refuses(lambda: S.sign_caution([], h), "sign_caution: not an object")
    refuses(lambda: S.sign_caution(dict(body, action_digest=""), h), "sign_caution: action_digest required")
    refuses(lambda: S.sign_caution({k: v for k, v in body.items() if k != "holder"}, h), "sign_caution: holder required")
    for c in (1.5, -0.1, float("nan"), "0.5", True):
        refuses(lambda: S.sign_caution(dict(body, caution=c), h), "sign_caution: caution must be a finite number in [0,1]")
    refuses(lambda: S.sign_caution(dict(body, reason="has space"), h), "sign_caution: invalid reason")


def test_session_root_round_trip_and_refusals():
    body = args("session-root")["body"]
    s = S.sign_session_root(body, K["principal"])
    assert verify_session_root(s, {})["ok"]
    refuses(lambda: S.sign_session_root(body, K["agent"]), "sign_session_root: the signer is not one of the session principals")
    with pytest.raises(ValueError, match=r"^sign_session_root: "):
        S.sign_session_root(dict(body, kind="nope"), K["principal"])


def test_session_grant_refusals():
    a = args("session-grant-g0")
    kw = dict(principal=K["principal"], holder=K["agent"].public, session=a["session"], seq=0, root=a["root"],
              map_digest=a["map_digest"], predicates=a["predicates"], salt=a["salt"])
    assert S.mint_session_grant(**kw)["goal_salt"] == a["salt"]
    refuses(lambda: S.mint_session_grant(**dict(kw, map_digest="short")),
            "mint_session_grant: map_digest must be canonical base64url (32 bytes)")
    with pytest.raises(ValueError, match=r"^mint_session_grant: "):
        S.mint_session_grant(**dict(kw, seq=-1))


def test_action_schema_round_trip():
    doc = args("action-schema")["doc"]
    s = S.sign_action_schema(doc, "site-k1", K["site"])
    assert verify_action_schema(s, [S.action_schema_key_of("site-k1", K["site"])])["ok"]
    assert not verify_action_schema(s, [S.action_schema_key_of("site-k1", K["agent"])])["ok"]
    with pytest.raises(ValueError, match=r"^sign_action_schema: "):
        S.sign_action_schema(dict(doc, v=2), "site-k1", K["site"])


def test_intent_required_refusals():
    body = args("intent-required")["body"]
    site = K["site"]

    def r(mut, text):
        b = copy.deepcopy(body)
        mut(b)
        refuses(lambda: S.sign_intent_required(b, "site-k1", site), "sign_intent_required: " + text)
    r(lambda b: b.update(extra=1), "unknown member 'extra'")
    r(lambda b: b.update(v=2), "not a pca-intent-required v1")
    r(lambda b: b.update(v=True), "not a pca-intent-required v1")
    r(lambda b: b.update(session="x"), "session must be canonical base64url (32 bytes)")
    r(lambda b: b.update(cell={"verb": "refund"}), "cell must be {verb, coords}")
    r(lambda b: b["cell"].update(coords={}), "coords must be an object of 1..64 dimensions")
    r(lambda b: b["cell"].update(coords={"": ["a"]}), "a coordinate path must be 1..256 characters")
    r(lambda b: b["cell"].update(coords={"x": [5, 1]}), "coords 'x': need 0 <= lo <= hi")
    r(lambda b: b["cell"].update(coords={"x": ["a", "a"]}), "coords 'x': values must be distinct")
    r(lambda b: b["cell"].update(coords={"x": [1.5, 2]}), "coords 'x': an index range [lo, hi] or a value set")
    r(lambda b: b.update(reason="sure"), "reason must be 'uncertain'")
    r(lambda b: b.update(question_id="q 1"), "question_id must match [A-Za-z0-9_-]{1,64}")
    r(lambda b: b.update(question_id="q-1\n"), "question_id must match [A-Za-z0-9_-]{1,64}")
    r(lambda b: b.update(friction="none"), "unknown friction tier")
    r(lambda b: b.update(delivered_to="site"), "delivered_to must be 'wallet' or 'agent'")
    r(lambda b: b.update(expires_at=-1), "expires_at must be a non-negative safe integer")
    r(lambda b: b.update(sig={}), "an unsigned body must not carry sig")
    refuses(lambda: S.sign_intent_required([], "site-k1", site), "sign_intent_required: not an object")


def test_labels_fact_round_trip():
    lb = args("labels")["body"]
    s = S.sign_labels(lb, K["site"])
    assert verify_labels(s, [{"site": lb["site"], "kid": lb["kid"], "pk": K["site"].public}]) is None
    f = S.sign_fact(args("fact-integer")["body"], K["oracle"])
    assert validate_fact_wire(f) is None
    assert verify_artifact_sig(FACT_DOMAIN, f, {"pk": K["oracle"].public})
    assert not verify_artifact_sig(FACT_DOMAIN, f, {"pk": K["site"].public})


def _case(name):
    return copy.deepcopy(next(c for c in DOC["cases"] if c["name"] == name))


def test_offer_set_exact_outputs_and_refusals():
    for name in ("offer-set-complete", "offer-set-partial-page"):
        c = _case(name)
        assert S.sign_offer_set(c["args"]["body"], K["site"]) == c["expect"]
    for name in ("offer-set-refuses-unsafe-price", "offer-set-refuses-unsafe-issued-at"):
        c = _case(name)
        with pytest.raises(TypeError) as e:
            S.sign_offer_set(c["args"]["body"], K["site"])
        assert str(e.value) == c["expect"]["error"] == "canonicalize: integer outside the safe range (|n| > 2^53-1)"
    body = args("offer-set-complete")["body"]
    S.sign_offer_set(body, K["site"])
    assert "sig" not in body  # the caller's body is not mutated


def test_offer_set_verifies_and_decides():
    body = copy.deepcopy(args("offer-set-complete")["body"])
    # the vector's null attribute only tests that signing keeps it; a null is not a wire scalar (the reference refuses it too)
    assert validate_offer_set_wire(S.sign_offer_set(body, K["site"])) == "offer 2: attribute 'note' must be a scalar"
    del body["offers"][2]["note"]
    os_ = S.sign_offer_set(body, K["site"])
    assert validate_offer_set_wire(os_) is None
    assert verify_artifact_sig(OFFER_SET_DOMAIN, os_, {"pk": K["site"].public})
    assert not verify_artifact_sig(OFFER_SET_DOMAIN, os_, {"pk": K["oracle"].public})
    policy = {"name": "excess", "site_keys": [{"kid": "site-k1", "pk": K["site"].public}], "max_age_ms": 60_000,
              "offer_param": "action.params.offer", "filter": {"query": dict(os_["query"]), "offer": {"stops": 0}}}
    d = decide_offer_set(policy, offer_set_ref(os_), os_, {"offer": "o-3"}, os_["site"], os_["session"], os_["issued_at"] + 1000, 0)
    assert d == {"ok": True, "excess": 52000 - 41200, "chosen_price": 52000, "min_price": 41200}


def test_template_tighten_refusals():
    with pytest.raises(ValueError, match=r"^sign_template: "):
        S.sign_template({"v": 1}, K["principal"])
    with pytest.raises(ValueError, match=r"^sign_tighten: "):
        S.sign_tighten({"v": 1}, K["principal"])


def test_revocation_epoch_round_trip():
    ep = args("revocation-epoch")["body"]
    s = S.sign_revocation_epoch(K["guardian"], ep)
    assert check_revocation_epoch(s, K["guardian"].public, NOW)["ok"]
    assert not check_revocation_epoch(s, K["agent"].public, NOW)["ok"]
