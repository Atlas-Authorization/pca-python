"""verify_ledger_consistency refuses any node that is not 32 bytes (the TS reference fix 80dfe7a25). With oldSize 1 the old
root is the starting hash, so a 31/33-byte old root (or path element) plus a new root built over it used to verify."""
import hashlib

import pytest

from atlas_pca.ledger import verify_ledger_consistency
from atlas_pca.pca import b64u

C = bytes(range(32))


def _node(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


@pytest.mark.parametrize("n", [31, 33])
def test_short_or_long_old_root_is_refused(n):
    bad = b"\x07" * n
    assert not verify_ledger_consistency(b64u(bad), b64u(_node(bad, C)), {"oldSize": 1, "newSize": 2, "path": [b64u(C)]})


@pytest.mark.parametrize("n", [31, 33])
def test_short_or_long_path_node_is_refused(n):
    bad = b"\x07" * n
    assert not verify_ledger_consistency(b64u(C), b64u(_node(C, bad)), {"oldSize": 1, "newSize": 2, "path": [b64u(bad)]})


def test_32_byte_control_verifies():
    old = b"\x07" * 32
    assert verify_ledger_consistency(b64u(old), b64u(_node(old, C)), {"oldSize": 1, "newSize": 2, "path": [b64u(C)]})
