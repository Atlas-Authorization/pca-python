"""RULE22_ENGINE (the trait engine of rule 22) over every shared `rule22` / `rule22_schema` vector: integrity through
schema_error, decision through decide, exactly the verdict the reference engine gives."""
import pytest

from atlas_pca import actions_registry as R
from test_actions_vectors import _cases

VECS = [v for v in _cases() if v["kind"] in ("rule22", "rule22_schema")]


def test_vectors_are_present():
    assert sum(v["kind"] == "rule22" for v in VECS) >= 8 and sum(v["kind"] == "rule22_schema" for v in VECS) >= 8


@pytest.mark.parametrize("v", VECS, ids=lambda v: v["id"])
def test_engine_matches_the_vector(v):
    i = v["input"]
    e = R.RULE22_ENGINE.schema_error(i["doc"], i.get("pins"))
    if v["kind"] == "rule22_schema":
        assert (e is None) == v["expect"].get("ok", False)
        return
    if e is not None:
        assert v["expect"]["integrity"] != "ok" and v["expect"]["decision"] == "deny"
        return
    assert v["expect"]["integrity"] == "ok"
    assert R.RULE22_ENGINE.decide(i["doc"], i["verb"], i["grant"], i["context"]) == v["expect"]["decision"]


def test_decide_is_fail_closed():
    assert R.RULE22_ENGINE.decide({"verbs": []}, "a.b", {"caveats": [], "max_esc": 3, "preauth_esc": 0}, []) == "deny"
    assert R.RULE22_ENGINE.decide(None, "a.b", {}, []) == "deny"
