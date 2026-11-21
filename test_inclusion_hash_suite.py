"""verify_inclusion reads the proof's self-describing hash suite: absent or sha256 verifies, anything else refuses."""
from atlas_pca.pca import merkle_root, verify_inclusion

LEAF = {"i": 1}


def test_hash_suite_member():
    root, proof = merkle_root([LEAF]), {"index": 0, "size": 1, "path": []}
    assert verify_inclusion(root, proof, LEAF)
    assert verify_inclusion(root, {**proof, "hash_suite": "sha256"}, LEAF)
    for suite in ("sha384", "SHA256", "", None, 1):
        assert not verify_inclusion(root, {**proof, "hash_suite": suite}, LEAF)
