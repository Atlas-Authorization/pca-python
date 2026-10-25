"""Kill tests: the signed revocation epoch check (check_revocation_epoch: signer / suite, shape, signature, grant binding,
expiry and issue-time boundaries, rollback, PCActn freshness) on a real signed epoch from the shared session-revocation
oracle, and compare_utf8 (UTF-8 byte order, ties broken by UTF-16 code units; exact -1 / 0 / 1)."""
import json
import os

import pytest

from atlas_pca.intent_v2 import check_revocation_epoch, compare_utf8

with open(os.path.join(os.path.dirname(__file__), "testdata", "k042-sessrevoc-cases.json"), encoding="utf-8") as fh:
    _OK = next(c for c in json.load(fh)["rev"] if c["name"] == "ok")

EP = json.loads(_OK["ev"])["epoch"]
GUARDIAN = json.loads(_OK["authority"])
GRANT = EP["grant_ref"]
NOW = _OK["now"]


def run(ep=None, **kw):
    a = dict(guardian_public=GUARDIAN, now=NOW, grant_ref=GRANT)
    a.update(kw)
    return check_revocation_epoch(EP if ep is None else ep, a.pop("guardian_public"), a.pop("now"), **a)


def bad(r, reason):
    assert r == {"ok": False, "reason": reason}


def test_valid_epoch_and_boundaries():
    assert run() == {"ok": True}
    assert run(grant_ref=EP["grant_ref"])["ok"] is True
    assert run(now=EP["not_after"])["ok"] is True  # now == not_after is still fresh
    bad(run(now=EP["not_after"] + 1), "revocation epoch expired (stale revocation root)")
    assert run(now=EP["issued_at"] - 60_000)["ok"] is True  # issued exactly 60 s ahead
    bad(run(now=EP["issued_at"] - 60_001), "revocation epoch issued in the future")


def test_signer_and_suite():
    msg = "revocation epoch not signed by the pinned guardian"
    bad(run(guardian_public="x" * 43), msg)
    bad(run(guardian_public=None), msg)
    bad(run(ep=[EP]), msg)
    bad(run(ep="x"), msg)
    bad(run(ep=dict(EP, guardian=5)), msg)
    bad(run(ep=dict(EP, alg="not-a-suite")), msg)
    bad(run(ep=dict(EP, alg=7)), msg)
    no_alg = {k: v for k, v in EP.items() if k != "alg"}
    assert run(ep=no_alg)["ok"] is True  # an absent alg is the default suite
    assert run(ep=dict(EP, alg="ed25519"))["ok"] is True


@pytest.mark.parametrize("field,value", [
    ("epoch", -1), ("epoch", 1.5), ("epoch", None), ("epoch", "2"), ("epoch", True),
    ("set_size", -1), ("set_size", 0.5), ("set_size", None), ("set_size", "2"),
    ("issued_at", 1.5), ("issued_at", None), ("issued_at", "1"), ("issued_at", 2 ** 53),
    ("not_after", 1.5), ("not_after", None), ("not_after", "1"), ("not_after", 2 ** 53),
])
def test_malformed(field, value):
    bad(run(ep=dict(EP, **{field: value})), "malformed revocation epoch")


@pytest.mark.parametrize("field", ["epoch", "set_size", "issued_at", "not_after"])
def test_missing_member_is_malformed(field):
    bad(run(ep={k: v for k, v in EP.items() if k != field}), "malformed revocation epoch")


def test_signature_and_binding():
    bad(run(ep=dict(EP, sig="A" * 86)), "revocation epoch signature invalid")
    bad(run(ep=dict(EP, root="A" * 43)), "revocation epoch signature invalid")
    bad(run(ep={k: v for k, v in EP.items() if k != "sig"}), "revocation epoch signature invalid")
    bad(run(grant_ref="pca-intent-session:other"), "revocation epoch is for a different grant")
    assert run(grant_ref=EP["grant_ref"] + "")["ok"] is True


def test_rollback_and_freshness():
    e = EP["epoch"]
    assert run(last_accepted_epoch=e)["ok"] is True  # equal is not a rollback
    assert run(last_accepted_epoch=e - 1)["ok"] is True
    bad(run(last_accepted_epoch=e + 1), "revocation epoch %d is older than the last accepted %d (rollback)" % (e, e + 1))
    assert run(pcactn_epoch=e)["ok"] is True  # freshness.epoch >= epoch
    assert run(pcactn_epoch=e + 1)["ok"] is True
    bad(run(pcactn_epoch=e - 1), "PCActn freshness.epoch %d predates the revocation epoch %d" % (e - 1, e))


@pytest.mark.parametrize("a,b,want", [
    ("a", "a", 0), ("", "", 0), ("a", "b", -1), ("b", "a", 1), ("a", "ab", -1), ("ab", "a", 1), ("", "a", -1),
    ("Z", "a", -1), ("a", "Z", 1), ("é", "z", 1), ("z", "é", -1),
    ("\U0001F600", "￿", 1),  # UTF-8 order puts an astral char after U+FFFF (UTF-16 order would not)
    ("￿", "\U0001F600", -1),
    ("\ud800", "�", -1),  # a lone surrogate encodes as U+FFFD: bytes tie, broken by UTF-16 code units
    ("�", "\ud800", 1),
    ("\ud800", "\udc00", -1), ("\udc00", "\ud800", 1),
    ("a\ud800", "a�", -1), ("a�", "a\ud800", 1),
])
def test_compare_utf8(a, b, want):
    assert compare_utf8(a, b) == want
