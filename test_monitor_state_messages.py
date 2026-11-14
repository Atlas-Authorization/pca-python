"""The structural refusal of a monitor state names exactly what is wrong."""
import pytest

from atlas_pca.prohibitions import canonical_state, state_problem


@pytest.mark.parametrize("state", [None, [], {"now": 1, "ledger": {}}, {"now": float("inf"), "ledger": {}, "latched": {}, "seq": 0}])
def test_a_state_without_its_shape_is_reported_as_malformed(state):
    assert state_problem(state) == "malformed monitor state"
    with pytest.raises(TypeError) as e:
        canonical_state(state)
    assert str(e.value) == "malformed monitor state"


@pytest.mark.parametrize("where", ["ledger", "latched"])
def test_a_state_whose_check_itself_fails_is_reported_as_malformed(where):
    # a non-text key makes the length check raise: the refusal is the plain one, not an exception
    state = {"now": 10, "ledger": {}, "latched": {}, "seq": 0, "parent": None}
    state[where] = {7: [] if where == "ledger" else 1}
    assert state_problem(state) == "malformed monitor state"
