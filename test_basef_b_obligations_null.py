"""A JSON null `obligations` is not an absent one: `obligations must be an array` (reference obligations.ts). Absent is the `ABSENT` marker."""
from atlas_pca import obligations as OB

LOG = {"kind": "log"}


def test_validate_null_vs_absent():
    assert OB.obligations_error(None) == "obligations must be an array"
    assert OB.obligations_error(OB.ABSENT) is None
    assert OB.obligations_error([]) is None
    assert OB.obligations_error("x") == "obligations must be an array"


def test_gate_null_denies_and_absent_allows():
    assert OB.pep_obligation_gate("allow", False, None, ["log"]) == {
        "decision": "deny", "perform": [], "unsupported": [], "reason": "malformed obligations: obligations must be an array"}
    assert OB.pep_obligation_gate("allow", False, OB.ABSENT, ["log"]) == {"decision": "allow", "perform": [], "unsupported": []}
    assert OB.pep_obligation_gate("allow", False, [LOG], ["log"]) == {"decision": "allow", "perform": [LOG], "unsupported": []}


def test_non_allow_decisions_do_not_look_at_obligations():
    assert OB.pep_obligation_gate("deny", False, None, []) == {"decision": "deny", "perform": [], "unsupported": []}


def test_merge_null_is_refused_and_absent_is_skipped():
    assert OB.merge_obligations([LOG], None) == {"ok": False, "reason": "obligations must be an array"}
    assert OB.merge_obligations([LOG], OB.ABSENT, []) == {"ok": True, "obligations": [LOG]}


def test_outcome_null_obligations_are_unmet_and_absent_is_ok():
    assert OB.obligation_outcome(None, [], 1) == {"outcome": "escalate", "overdue": [], "status": "obligation_unmet"}
    assert OB.obligation_outcome(OB.ABSENT, [], 1) == {"outcome": "ok", "overdue": []}


def test_the_marker_is_a_singleton_and_prints_as_absent():
    assert repr(OB.ABSENT) == "ABSENT" and OB.ABSENT is OB.ABSENT
