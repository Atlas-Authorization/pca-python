"""Kill tests for atlas_pca.fastapi: intent_policy and intent_v2 reach the guard unchanged."""
import pytest

pytest.importorskip("fastapi")

import atlas_pca.fastapi as fa  # noqa: E402


def test_intent_arguments_are_forwarded(monkeypatch):
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return lambda headers, body: None

    monkeypatch.setattr(fa, "require_pca", fake)
    res = lambda *a: None
    fa.RequirePCA(audience="aud", resolve_grant=res, signature_only=True)
    assert seen == {"audience": "aud", "resolve_grant": res, "now": None, "intent_policy": None, "intent_v2": None, "fresh_at": None,
                    "signature_only": True}
    fa.RequirePCA(audience="aud", resolve_grant=res)
    assert seen["signature_only"] is False  # the default is the full authorize pipeline
    pol, v2 = {"p": 1}, {"v": 2}
    fa.RequirePCA(audience="aud", resolve_grant=res, now=5, intent_policy=pol, intent_v2=v2, signature_only=True)
    assert seen["now"] == 5 and seen["intent_policy"] is pol and seen["intent_v2"] is v2


def test_fresh_at_is_forwarded(monkeypatch):
    seen = {}
    monkeypatch.setattr(fa, "require_pca", lambda **kw: seen.update(kw) or (lambda headers, body: None))
    pol = {"signer": "s"}
    fa.RequirePCA(audience="aud", resolve_grant=lambda *a: None, fresh_at=pol, signature_only=True)
    assert seen["fresh_at"] is pol
