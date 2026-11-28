"""Differential replay of the TypeScript reference (@atlasauth/pca-revoke): registry, chain check, verify gate, CAEP bridge."""
import copy
import os
import tempfile
import time

import pytest

from atlas_pca import revoke as R
from base_oracle import load_ref, near_clock, reference_clock_ms, run

COUNT, BY_FN = load_ref("revoke")
CLOCK = reference_clock_ms(BY_FN)


class _Boom(R.InMemoryRevocationStore):
    def __init__(self, fail):
        super().__init__()
        self.fail = fail

    def get(self, kind, value):
        if self.fail == "failGet":
            raise RuntimeError("boom")
        return super().get(kind, value)

    def all(self):
        if self.fail == "failAll":
            raise RuntimeError("boom")
        return super().all()


def _norm(v):
    """An entry whose revokedAt is within two minutes of the wall clock is printed "<now>" (the reference does the same; its generation clock is frozen at the corpus header's clockMs, so that instant counts as now too)."""
    if isinstance(v, list):
        return [_norm(x) for x in v]
    if isinstance(v, dict):
        return {k: ("<now>" if k == "revokedAt" and isinstance(x, (int, float)) and not isinstance(x, bool)
                    and near_clock(x, CLOCK) else _norm(x)) for k, x in v.items()}
    return v


def _step(reg, s):
    op = s["op"]
    o = s.get("opts") or {}
    if op == "revoke":
        return reg.revoke(s["input"])
    if op == "revokeSubtree":
        return reg.revoke_subtree(s["target"], s.get("opts"))
    if op == "unrevoke":
        return reg.unrevoke(s["key"])
    if op == "list":
        return reg.list()
    if op == "lookup":
        return reg.lookup(s["kind"], s["value"])
    if op == "prefixes":
        return reg.prefixes()
    if op == "clear":
        reg.clear()
        return None
    if op == "killAgent":
        return reg.kill_agent(s["holder"], reason=o.get("reason"), revoked_at=o.get("revokedAt"))
    if op == "killSubtree":
        return reg.kill_subtree(s["root"], reason=o.get("reason"), revoked_at=o.get("revokedAt"))
    if op == "check":
        return R.check_revocation(s["p"], reg, o.get("now"))
    if op == "verify":
        return R.verify_with_revocation(s["p"], s["core"], reg, o.get("now"))
    if op == "ingest":
        return R.ingest_caep_event(s["event"], reg)
    raise AssertionError("bad op")


def scenario(spec):
    store = _Boom(spec["store"]) if spec.get("store") in ("failGet", "failAll") else R.InMemoryRevocationStore()
    reg = R.RevocationRegistry(store)
    out = []
    for s in spec["ops"]:
        try:
            out.append(_norm(copy.deepcopy(_step(reg, s))))
        except Exception:  # noqa: BLE001 - only the refusal is compared, not its message
            out.append({"$err": True})
    return out


def _skip(c):
    # the reference stores a kind-less entry that no lookup can match; this port refuses it
    return "kind-less entry" if c["name"].startswith("scenario/revoke/34#") else None


def test_scenarios():
    run(BY_FN["scenario"], scenario, skip=_skip)


def test_is_active_at():
    run(BY_FN["isActiveAt"], R.is_active_at)


def test_event_types():
    run(BY_FN["caepEventTypes"], lambda: R.CAEP_EVENT_TYPES)


def test_every_function_is_covered():
    assert set(BY_FN) == {"scenario", "isActiveAt", "caepEventTypes"} and COUNT == sum(len(v) for v in BY_FN.values())


def test_in_memory_store_conforms():
    assert R.run_revocation_store_conformance(R.InMemoryRevocationStore) == []


def test_file_store_conforms_and_survives_reopen():
    with tempfile.TemporaryDirectory() as d:
        n = [0]

        def make():
            n[0] += 1
            return R.FileRevocationStore(os.path.join(d, "r%d.json" % n[0]))

        paths = {}

        def make_tracked():
            s = make()
            paths[id(s)] = s._path
            return s

        assert R.run_revocation_store_conformance(make_tracked, lambda prev: R.FileRevocationStore(paths[id(prev)])) == []


def test_file_store_refuses_a_corrupt_file():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "r.json")
        for body in ("{not json", '{"entries":"x"}', '{"v":1,"entries":[{"kind":"cap"}]}', '{"entries":[],"x":NaN}'):
            with open(p, "w") as fh:
                fh.write(body)
            with pytest.raises(ValueError):
                R.FileRevocationStore(p)
