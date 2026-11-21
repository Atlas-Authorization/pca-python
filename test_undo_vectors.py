"""Undo windows (pure layer): replays conformance/undo-vectors.json (made by the TypeScript reference; a missing file FAILS,
it never skips). Every section: compensation digests, the signed token (re-signed byte for byte from the seed, encoded, digest,
every check), receipts (re-signed byte for byte, digests, chains), transitions, window clamps and the undo_window obligation."""
import copy
import hashlib
import json
import os

import pytest

from atlas_pca.agent import KeyPair
from atlas_pca.obligations import obligations_error
from atlas_pca.undo import (compensation_digest, decode_undo_token, encode_undo_token, resolve_undo_window, sign_undo_receipt,
                            sign_undo_token, undo_receipt_chain_error, undo_receipt_digest, undo_token_check, undo_token_digest,
                            undo_transition, verify_undo_receipt)

_HERE = os.path.dirname(os.path.abspath(__file__))
_P = next((p for p in (os.path.join(_HERE, "conformance", "undo-vectors.json"),
                       os.path.join(_HERE, "conformance", "undo-vectors.json"))
           if os.path.exists(p)), None)
assert _P is not None, "undo-vectors.json is missing (a missing vector file fails, never skips)"
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)
SEED = hashlib.sha256(DOC["signer"]["seed_label"].encode("utf-8")).digest()
SIGNER = DOC["signer"]["public"]


def _ids(xs):
    return [x["name"] for x in xs]


def test_undo_format_and_signer():
    assert (DOC["format"], DOC["ver"]) == ("pca-undo-vectors", 1)
    assert KeyPair(SEED).public == SIGNER and DOC["signer"]["other_public"] != SIGNER
    assert [len(DOC[k]) for k in ("compensation", "transitions", "window", "obligation")] == [3, 33, 9, 6]


@pytest.mark.parametrize("c", DOC["compensation"], ids=_ids(DOC["compensation"]))
def test_undo_compensation(c):
    assert compensation_digest(c["compensation"]) == c["digest"]


def test_undo_token_sign_encode_digest():
    t = DOC["token"]
    assert sign_undo_token(t["record"], SEED) == t["token"]
    assert encode_undo_token(t["token"]) == t["encoded"]
    assert decode_undo_token(t["encoded"]) == t["token"]
    assert undo_token_digest(t["token"]) == t["digest"]


@pytest.mark.parametrize("c", DOC["token"]["checks"], ids=_ids(DOC["token"]["checks"]))
def test_undo_token_check(c):
    assert undo_token_check(c["token"], c["signer"], c["record"], c["now"]) == c["expect"]


@pytest.mark.parametrize("i", range(len(DOC["receipts"]["list"])))
def test_undo_receipt(i):
    e = DOC["receipts"]["list"][i]
    r = e["receipt"]
    assert undo_receipt_digest(r) == e["digest"]
    assert sign_undo_receipt({k: r[k] for k in ("record", "event", "state", "at", "compensation_digest", "prev", "note")}, SEED) == r
    assert verify_undo_receipt(r, SIGNER) is True
    assert verify_undo_receipt(r, DOC["signer"]["other_public"]) is False


@pytest.mark.parametrize("c", DOC["receipts"]["chains"], ids=_ids(DOC["receipts"]["chains"]))
def test_undo_receipt_chain(c):
    err = undo_receipt_chain_error(dict(c["record"], receipts=c["receipts"]), c["signer"])
    assert (err is None) is c["expect"]["ok"], err


@pytest.mark.parametrize("c", DOC["transitions"], ids=_ids(DOC["transitions"]))
def test_undo_transition(c):
    before = copy.deepcopy(c["record"])
    r, e = undo_transition(c["record"], c["event"], c["now"]), c["expect"]
    assert r["outcome"] == e["outcome"]
    if e["outcome"] == "refused":
        assert r["code"] == e["code"]
    elif e["outcome"] == "applied":
        assert (r["record"]["state"], r["record"]["ver"]) == (e["state"], e["ver"])
        if "attempt" in e:
            assert r["record"]["attempt"] == e["attempt"]
    assert c["record"] == before  # pure: the input record is never modified


@pytest.mark.parametrize("c", DOC["window"], ids=_ids(DOC["window"]))
def test_undo_window(c):
    assert resolve_undo_window(c["requested"], c["policy"]) == c["expect"]


@pytest.mark.parametrize("c", DOC["obligation"], ids=_ids(DOC["obligation"]))
def test_undo_obligation(c):
    assert (obligations_error([c["obligation"]]) is None) is c["expect"]["ok"]
