"""Differential replay of the testing kit (acceptance constants and route mapping, fake verifier, tamper, in-memory state store)
against the TypeScript reference."""
import pytest

from atlas_pca import testing as T
from base_oracle import load_ref, run

COUNT, CASES = load_ref("testing")


def _apply(rec, m):
    if m["op"] == "none":
        return
    cur = rec
    for k in m["path"][:-1]:
        cur = cur[k]
    if m["op"] == "set":
        cur[m["path"][-1]] = m["value"]
    else:
        cur.pop(m["path"][-1], None)


def _session(ops):
    s = T.memory_state_store()
    out = []
    for op, key, *st in ops:
        if op == "put":
            s.put(key, st[0])
        else:
            out.append(s.get(key))
    return out


MAP = {
    "consts": lambda: {"aud": T.ADAPTER_ACCEPTANCE_AUDIENCE, "expected": T.ADAPTER_ACCEPTANCE_EXPECTED},
    "acceptanceOperation": T.acceptance_operation,
    "fakeVerifyAllow": lambda p, o: T.fake_verify(p, **o).allow,
    "expectVerifies": lambda p, o: T.expect_verifies(p, **o).allow,
    "expectDenied": lambda p, o: T.expect_denied(p, **o).allow,
    "tamper": lambda e, m: T.tamper(e, lambda rec: _apply(rec, m)),
    "memorySession": _session,
}


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
