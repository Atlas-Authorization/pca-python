"""Private state is owner-only. POSIX: mode 0600 for a file and 0700 for a directory. Windows: the descriptor read back is exactly
``D:P(A;;FA;;;<current user SID>)``, a protected DACL with one entry for the current user (no inheritance), set when the path is created."""
import os

import pytest

from atlas_pca import private_fs as P


def _is_owner_only(path, directory=False):
    got = P.describe_restriction(path)
    if os.name == "nt":
        # exactly one entry (for the current user), protected (the P flag: no inherited entries); the failure shows what Windows reported
        assert got == P.normalized_owner_sddl() and got.startswith("D:P(") and got.count("(") == 1, got
        return True
    assert got == ("0o700" if directory else "0o600"), got
    return True


def test_open_private_creates_an_owner_only_file_and_keeps_exclusive_create(tmp_path):
    p = str(tmp_path / "f")
    fd = P.open_private(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    os.write(fd, b"x")
    os.close(fd)
    assert _is_owner_only(p)
    with pytest.raises(FileExistsError):
        P.open_private(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    fd = P.open_private(p, os.O_WRONLY | os.O_APPEND)
    os.write(fd, b"y")
    os.close(fd)
    assert open(p, "rb").read() == b"xy"


def test_directories_this_module_creates_are_owner_only(tmp_path):
    d = str(tmp_path / "a" / "b" / "c")
    P.makedirs_private(d)
    for x in (d, os.path.dirname(d), os.path.dirname(os.path.dirname(d))):
        assert _is_owner_only(x, directory=True)
    t = P.mkdtemp_private("pcatest-", str(tmp_path))
    assert _is_owner_only(t, directory=True)
    with pytest.raises(FileExistsError):
        P.mkdir_private(t)


def test_directory_kv_state_is_owner_only(tmp_path):
    from atlas_pca.ciba_store import create_directory_kv
    d = str(tmp_path / "kv")
    kv = create_directory_kv(d)
    assert kv.put_if_equals("k", None, "v") is True
    assert _is_owner_only(d, directory=True)
    files = [os.path.join(d, n) for n in os.listdir(d)]
    assert files and all(_is_owner_only(f) for f in files)


def test_file_approval_store_and_secret_store_are_owner_only(tmp_path):
    from atlas_pca.ciba_store import create_file_approval_store
    from atlas_pca.stepup import FileSecretStore
    p = str(tmp_path / "approvals.json")
    assert create_file_approval_store(p).cas("k", 0, {"a": 1}) is True
    assert _is_owner_only(p)
    s = str(tmp_path / "seed")
    FileSecretStore(s).save(b"\x01" * 32)
    assert _is_owner_only(s)


def test_revocation_and_witness_state_files_are_owner_only(tmp_path):
    from atlas_pca.mesh_witness import FileMeshWitnessStore
    from atlas_pca.revoke import FileRevocationStore, RevocationRegistry
    r = str(tmp_path / "rev.json")
    RevocationRegistry(FileRevocationStore(r)).revoke({"kind": "cap", "value": "c1", "reason": "r", "revokedAt": 1})
    assert _is_owner_only(r)
    w = str(tmp_path / "witness.json")
    store = FileMeshWitnessStore(w)
    store.save({"epoch": 1})
    assert store.load() == {"epoch": 1} and _is_owner_only(w)


def test_durable_state_directory_and_files_are_owner_only(tmp_path):
    from atlas_pca.durable_state import open_durable_state
    d = str(tmp_path / "ds")
    h = open_durable_state(dir=d)
    h.set("k", "v")
    assert _is_owner_only(d, directory=True)
    files = [os.path.join(d, n) for n in os.listdir(d) if os.path.isfile(os.path.join(d, n))]
    assert files and all(_is_owner_only(f) for f in files)


def test_scitt_log_file_is_owner_only(tmp_path):
    from atlas_pca.scitt_log import FileScittLogStore
    p = str(tmp_path / "log.bin")
    s = FileScittLogStore.open(p)
    try:
        assert _is_owner_only(p)
    finally:
        s.close()
