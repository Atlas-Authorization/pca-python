"""parse_event reads its input with the strict canonical JSON profile, as the reference does: nothing the loose parser forgave is accepted."""
import pytest

from atlas_pca import events as E

GOOD = E.serialize_event(E.build_step_up_event("step_up.created", {"at": 1700000000000, "grant_ref": "g1", "action": {"verb": "v", "resource": "r"}, "tier": 2}))


def test_a_well_formed_event_round_trips():
    assert E.parse_event(GOOD)["grant_ref"] == "g1"


@pytest.mark.parametrize("mutate", [
    lambda s: s.replace('"tier":2', '"tier":2,"tier":3'),        # a duplicate member (the loose parser kept the last)
    lambda s: s.replace('"tier":2', '"tier":2e0'),               # an exponent
    lambda s: s.replace('"tier":2', '"tier":2.0'),               # a trailing-zero fraction
    lambda s: s.replace('"grant_ref":"g1"', '"grant_ref":"g\\ud800"'),  # a lone surrogate
    lambda s: s.replace('"tier":2', '"tier":-0'),                # a negative zero
])
def test_what_the_strict_profile_refuses_is_refused(mutate):
    text = mutate(GOOD)
    assert text != GOOD
    with pytest.raises(ValueError, match="strict JSON"):
        E.parse_event(text)


def test_a_non_string_is_refused():
    for bad in (None, 5, b"{}", [], {}):
        with pytest.raises(ValueError, match="strict JSON"):
            E.parse_event(bad)
