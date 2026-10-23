"""Kill tests for atlas_pca.intent_map: the disclosure entry shape (every path element is a canonical 32-byte digest)."""
from atlas_pca import intent_map as M
from atlas_pca.pca import b64u

SALT = b64u(bytes(32))


def _entry(path):
    return {"index": 0, "salt": SALT, "leaf": {}, "path": path}


def _disclosure(path):
    e = _entry(path)
    return {"size": 4, "header": e, "cell": _entry([]), "metrics": _entry([])}


def test_entry_path_elements_must_be_32_byte_digests():
    msg = "disclosure.header.path must be an array of 32-byte digests"
    assert M.map_disclosure_error(_disclosure([b64u(bytes(32))] * 2)) != msg
    for bad in (b64u(bytes(31)), b64u(bytes(33)), b64u(b""), "!!", 5, None):
        assert M.map_disclosure_error(_disclosure([b64u(bytes(32)), bad])) == msg, bad
    assert M.map_disclosure_error(_disclosure("x")) == msg
    assert M.map_disclosure_error(_disclosure([b64u(bytes(32))] * 65)) == msg
