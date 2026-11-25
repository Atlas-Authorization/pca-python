"""A clock reading that is not a finite number prunes no lease revocation (NaN made every `revoked_at + ceiling >= now` false, so every
revocation was dropped and the lease it covered read as live again)."""
import json
import math
import os

import pytest

from atlas_pca import lease as L
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.plan_lifecycle import PlanRegistry

DOC = json.load(open(os.path.join(os.path.dirname(__file__), "conformance", "lease-vectors.json"), encoding="utf-8"))
REV = DOC["revocations"][0]  # target "lease", value "L1"


def _held(clock):
    reg = L.LeaseRegistry({"authorities": [DOC["authority"]], "maxTtlCeiling": 100}, MemoryAtomicKv(), clock=lambda: clock)
    assert reg.revoke(REV)["ok"] is True
    return reg.shard_revocations(L.shard_of(REV["value"], reg.shard_count))


def test_a_finite_clock_past_the_ceiling_prunes_the_revocation():
    assert _held(REV["revoked_at"] + 1000) == []


def test_a_finite_clock_inside_the_ceiling_keeps_it():
    assert [r["sig"] for r in _held(REV["revoked_at"] + 50)] == [REV["sig"]]


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_a_non_finite_clock_keeps_the_revocation(bad):
    assert [r["sig"] for r in _held(bad)] == [REV["sig"]]


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_a_plan_with_an_approval_expiry_is_not_executable_on_a_non_finite_clock(bad):
    clock = {"t": 1000}
    reg = PlanRegistry(now=lambda: clock["t"])
    nodes = [{"id": "n1", "verb": "orders.read", "resource": "/orders/1"}]
    root = reg.draft("g", nodes)["record"]["root"]
    assert reg.validate("g", root)["ok"] and reg.commit("g", root)["ok"]
    assert reg.authorize("g", root, {"by": "p", "expiresAt": 5000})["ok"]
    assert reg.status("g", root)["executable"] is True  # a finite clock before the expiry
    clock["t"] = bad
    assert reg.status("g", root)["executable"] is False  # -Infinity passed `now < exp`
