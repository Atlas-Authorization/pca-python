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


# ---- the portable branch, pinned on every platform (the Windows mutation job forces it with _WIN off) --------------------------------

def _spy(monkeypatch, name):
    calls, real = [], getattr(os, name)

    def spy(*a):
        calls.append(a)
        return real(*a)
    monkeypatch.setattr(os, name, spy)
    return calls


def test_portable_branch_creates_with_owner_only_modes(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "_WIN", False)
    p = str(tmp_path / "f")
    opened = _spy(monkeypatch, "open")
    fd = P.open_private(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    assert isinstance(fd, int) and os.write(fd, b"ab") == 2
    os.close(fd)
    assert opened == [(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)]
    d = str(tmp_path / "d")
    made = _spy(monkeypatch, "mkdir")
    P.mkdir_private(d)
    assert os.path.isdir(d) and made == [(d, 0o700)]
    os.chmod(p, 0o444)  # the one mode Windows and POSIX both report the same way
    try:
        assert P.describe_restriction(p) == "0o444"
    finally:
        os.chmod(p, 0o644)
    assert P.normalized_owner_sddl() == "0o600"


# ---- Windows: what the file system really holds, read independently of the module ------------------------------------------------

win = pytest.mark.skipif(os.name != "nt", reason="Windows security descriptors and CreateFileW semantics")


def _icacls_aces(path):
    """The ACEs icacls lists for `path` (inherited ones carry `(I)`, inheritance flags `(OI)`/`(CI)`)."""
    import subprocess
    out = subprocess.run(["icacls", path], capture_output=True, text=True, check=True).stdout.splitlines()
    first, rest = out[0], out[1:]
    assert first.lower().startswith(path.lower()), out
    aces = [first[len(path):].strip()]
    for line in rest:
        if not line.strip():
            break
        aces.append(line.strip())
    return [a.lower() for a in aces]


def _me():
    import subprocess
    return subprocess.run(["whoami"], capture_output=True, text=True, check=True).stdout.strip().lower()  # same account lookup icacls uses


@win
def test_windows_dacl_is_one_full_control_entry_for_the_user_and_nothing_inherited(tmp_path):
    f, d = str(tmp_path / "f"), str(tmp_path / "d")
    os.close(P.open_private(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL))
    P.mkdir_private(d)
    for x in (f, d):
        # exactly one entry: full control (FA, the whole file access mask), the current user, no (I) inherited entry and no (OI)/(CI) flags
        assert _icacls_aces(x) == [_me() + ":(f)"], (x, _icacls_aces(x))
        assert _is_owner_only(x, directory=x == d)


@win
def test_windows_security_attributes_are_owner_only_and_not_inheritable():
    import ctypes
    from ctypes import wintypes
    with P._Sa() as sa:
        assert sa.nLength == ctypes.sizeof(P._SECURITY_ATTRIBUTES)
        assert sa.bInheritHandle == 0  # a child process never inherits a handle to private state
        s = wintypes.LPWSTR()
        assert P._adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sa.lpSecurityDescriptor, 1, 4, ctypes.byref(s), None)
        try:
            assert s.value == P.normalized_owner_sddl()
        finally:
            P._k32.LocalFree(ctypes.cast(s, wintypes.HLOCAL))
    assert P._current_sid().startswith("S-1-5-")


@win
def test_windows_open_modes_grant_exactly_the_requested_access(tmp_path):
    p = str(tmp_path / "f")
    with open(p, "wb") as fh:
        fh.write(b"hello")
    fd = P.open_private(p, os.O_RDONLY)  # GENERIC_READ only
    try:
        assert os.read(fd, 5) == b"hello"
        with pytest.raises(OSError):
            os.write(fd, b"x")
        with open(p, "rb") as other:  # shared for read while open
            assert other.read() == b"hello"
    finally:
        os.close(fd)
    fd = P.open_private(p, os.O_WRONLY)  # GENERIC_WRITE only, no read right
    try:
        with pytest.raises(OSError):
            os.read(fd, 1)
        assert os.write(fd, b"J") == 1
    finally:
        os.close(fd)
    fd = P.open_private(p, os.O_RDWR)
    try:
        assert os.read(fd, 5) == b"Jello"
    finally:
        os.close(fd)
    fd = P.open_private(p, os.O_WRONLY | os.O_APPEND)  # FILE_APPEND_DATA only: no read, writes land at the end
    try:
        with pytest.raises(OSError):
            os.read(fd, 1)
        os.write(fd, b"!")
    finally:
        os.close(fd)
    assert open(p, "rb").read() == b"Jello!"
    fd = P.open_private(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)  # CREATE_ALWAYS over an existing file empties it
    os.write(fd, b"z")
    os.close(fd)
    assert open(p, "rb").read() == b"z"
    fd = P.open_private(p, os.O_WRONLY | os.O_TRUNC)  # TRUNCATE_EXISTING
    os.close(fd)
    assert open(p, "rb").read() == b""


@win
def test_windows_missing_paths_fail_without_creating_anything(tmp_path):
    import ctypes
    m = str(tmp_path / "missing")
    for flags in (os.O_RDONLY, os.O_WRONLY | os.O_TRUNC):  # OPEN_EXISTING / TRUNCATE_EXISTING never create
        with pytest.raises(FileNotFoundError):
            P.open_private(m, flags)
    assert not os.path.exists(m)
    fd = P.open_private(m, os.O_WRONLY | os.O_CREAT)  # OPEN_ALWAYS creates
    os.close(fd)
    assert os.path.isfile(m)
    with pytest.raises(FileNotFoundError):
        P.mkdir_private(str(tmp_path / "no" / "child"))  # ERROR_PATH_NOT_FOUND surfaces as its Windows error
    ctypes.set_last_error(0)  # the error must come from the failing advapi32 call itself, not a stale value
    with pytest.raises(FileNotFoundError) as e:
        P.describe_restriction(str(tmp_path / "gone"))
    assert e.value.winerror == 2
