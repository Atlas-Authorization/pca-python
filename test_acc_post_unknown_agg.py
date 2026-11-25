"""acc_post refuses an agg outside sum / count / max / distinct FIRST, selected or not, keyed or not (reference TS 80ad8c7ff,
packages/pca/src/mutation-kill-r13-g2-history.test.ts "refuses an agg outside ..."); a known agg still combines."""
import pytest

from atlas_pca.intent_history import HistoryError, acc_post

T = 1_000_000
SUM = {"id": "spend", "agg": "sum", "val": "action.params.total", "sel": {"verbs": ["pay"]}, "win": {"kind": "task"}, "key": None,
       "holder": {"kind": "site_local"}}
H = [{"id": "e1", "verb": "pay", "resource": "r", "params": {"total": 10, "k": "x", "to": "p"}, "t": T, "status": "committed"}]
_MISSING = object()


@pytest.mark.parametrize("agg", ["SUM", "tVm", "", "avg", None, 1, _MISSING, ["sum"]])
def test_unknown_agg_is_refused_first(agg):
    bad = {k: v for k, v in SUM.items() if k != "agg"}
    if agg is not _MISSING:
        bad["agg"] = agg
    for verb in ("pay", "look"):
        with pytest.raises(HistoryError, match="^accPost: unknown agg$"):
            acc_post(bad, H, verb, {"total": 5}, T)
    # keyed, and the key parameter missing (the empty pre-state branch): still the agg refusal, before any key work
    with pytest.raises(HistoryError, match="^accPost: unknown agg$"):
        acc_post(dict(bad, key="action.params.k"), H, "pay", {"total": 5}, T)


def test_known_agg_still_combines():
    assert acc_post(SUM, H, "pay", {"total": 5}, T) == 15
    assert acc_post(SUM, H, "look", {"total": 5}, T) == 10
