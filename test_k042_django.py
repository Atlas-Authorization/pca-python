"""Kill tests for atlas_pca.django: PCA_INTENT_V2 (dict, callable, dotted path, wrong type) and PCA_INTENT_POLICY reach the
guard unchanged."""
import pytest

import test_server_exact as X

pytest.importorskip("django")


def _settings():
    s = X._django()
    for name in ("PCA_SIGNATURE_ONLY", "PCA_AUDIENCE", "PCA_RESOLVE_GRANT", "PCA_NOW", "PCA_INTENT_V2", "PCA_INTENT_POLICY"):
        if hasattr(s, name):
            delattr(s, name)
    s.PCA_AUDIENCE = X.AUD
    s.PCA_SIGNATURE_ONLY = True
    s.PCA_RESOLVE_GRANT = X.resolve_for_dotted
    return s


@pytest.fixture(autouse=True)
def _clean_settings():
    yield
    from django.conf import settings

    for name in ("PCA_INTENT_V2", "PCA_INTENT_POLICY", "PCA_SIGNATURE_ONLY", "PCA_AUDIENCE", "PCA_RESOLVE_GRANT", "PCA_NOW"):
        if settings.configured and hasattr(settings, name):
            delattr(settings, name)


def _capture(monkeypatch):
    import atlas_pca.django as dj

    seen = {}

    def fake(**kw):
        seen.update(kw)
        return lambda headers, body: None

    monkeypatch.setattr(dj, "require_pca", fake)
    return dj, seen


def test_intent_settings_reach_the_guard(monkeypatch):
    s = _settings()
    dj, seen = _capture(monkeypatch)
    dj.PCAMiddleware(lambda r: None)
    assert seen["intent_v2"] is None and seen["intent_policy"] is None and seen["audience"] == X.AUD
    d = {"schema": {}}
    s.PCA_INTENT_V2 = d
    s.PCA_INTENT_POLICY = {"k": 1}
    dj.PCAMiddleware(lambda r: None)
    assert seen["intent_v2"] is d and seen["intent_policy"] == {"k": 1}
    f = lambda *a: None
    s.PCA_INTENT_V2 = f
    dj.PCAMiddleware(lambda r: None)
    assert seen["intent_v2"] is f
    s.PCA_INTENT_V2 = "test_server_exact.resolve_for_dotted"
    dj.PCAMiddleware(lambda r: None)
    assert seen["intent_v2"] is X.resolve_for_dotted


def test_intent_v2_of_the_wrong_type_is_refused(monkeypatch):
    from django.core.exceptions import ImproperlyConfigured

    s = _settings()
    dj, seen = _capture(monkeypatch)
    for bad in (5, ["x"], True):
        s.PCA_INTENT_V2 = bad
        with pytest.raises(ImproperlyConfigured,
                           match=r"^settings\.PCA_INTENT_V2 must be a dict, a callable or a dotted path to a callable$"):
            dj.PCAMiddleware(lambda r: None)


def test_fresh_at_setting_reaches_the_guard(monkeypatch):
    s = _settings()
    dj, seen = _capture(monkeypatch)
    dj.PCAMiddleware(lambda r: None)
    assert seen["fresh_at"] is None
    s.PCA_FRESH_AT = {"signer": "s"}
    dj.PCAMiddleware(lambda r: None)
    assert seen["fresh_at"] == {"signer": "s"}
    s.PCA_FRESH_AT = "test_server_exact.resolve_for_dotted"
    dj.PCAMiddleware(lambda r: None)
    assert seen["fresh_at"] is X.resolve_for_dotted
