"""The directory key-value store's platform rules, pinned on every OS by giving the module a stand-in `os` whose name is "nt" or
"posix": Windows refuses an open or a rename for the instant another handle is renaming over the file (PermissionError), so there
the store retries (200 attempts, then the error surfaces); on POSIX a PermissionError is a real denial and surfaces at once."""
import os
import time

import pytest

from atlas_pca import ciba_store as S


class _Os:
    def __init__(self, name, **over):
        self.name = name
        self.__dict__.update(over)

    def __getattr__(self, a):
        return getattr(os, a)


class _Time:
    time = staticmethod(time.time)

    @staticmethod
    def sleep(_s):
        pass  # the retry count is what is pinned, not the wall clock


def _kv(tmp_path, monkeypatch, name, lock_timeout_ms=5000, **over):
    monkeypatch.setattr(S, "os", _Os(name, **over))
    monkeypatch.setattr(S, "time", _Time)
    return S.create_directory_kv(str(tmp_path / "kv"), lock_timeout_ms)


def _denied(fails):
    """(calls, fn): fn raises PermissionError for its first `fails` calls (-1: always), then runs `real`."""
    calls = []

    def wrap(real):
        def fn(*a, **k):
            calls.append(a[0])
            if fails < 0 or len(calls) <= fails:
                raise PermissionError(13, "in use by another handle", a[0])
            return real(*a, **k)
        return fn
    return calls, wrap


def test_windows_read_retries_a_transient_denial_and_reads_the_value(tmp_path, monkeypatch):
    kv = _kv(tmp_path, monkeypatch, "nt")
    assert kv.put_if_equals("k", None, "v1") is True
    calls, wrap = _denied(3)
    monkeypatch.setattr(S, "open", wrap(open), raising=False)
    assert kv.get("k") == "v1"
    assert len(calls) == 4


def test_windows_read_gives_up_after_200_attempts_with_the_error(tmp_path, monkeypatch):
    kv = _kv(tmp_path, monkeypatch, "nt")
    assert kv.put_if_equals("k", None, "v1") is True
    calls, wrap = _denied(-1)
    monkeypatch.setattr(S, "open", wrap(open), raising=False)
    with pytest.raises(PermissionError):
        kv.get("k")
    assert len(calls) == 200


def test_posix_read_denial_surfaces_at_once(tmp_path, monkeypatch):
    kv = _kv(tmp_path, monkeypatch, "posix")
    assert kv.put_if_equals("k", None, "v1") is True
    calls, wrap = _denied(1)
    monkeypatch.setattr(S, "open", wrap(open), raising=False)
    with pytest.raises(PermissionError):
        kv.get("k")
    assert len(calls) == 1


def test_windows_rename_retries_a_transient_denial_and_publishes(tmp_path, monkeypatch):
    calls, wrap = _denied(3)
    kv = _kv(tmp_path, monkeypatch, "nt", replace=wrap(os.replace))
    assert kv.put_if_equals("k", None, "v1") is True
    assert len(calls) == 4
    assert kv.get("k") == "v1"


def test_windows_rename_gives_up_after_200_attempts_with_the_error(tmp_path, monkeypatch):
    calls, wrap = _denied(-1)
    kv = _kv(tmp_path, monkeypatch, "nt", replace=wrap(os.replace))
    with pytest.raises(PermissionError):
        kv.put_if_equals("k", None, "v1")
    assert len(calls) == 200
    assert kv.get("k") is None
    assert not [n for n in os.listdir(str(tmp_path / "kv")) if n.endswith(".lock")]  # the lock is released on the error


def test_posix_rename_denial_surfaces_at_once(tmp_path, monkeypatch):
    calls, wrap = _denied(-1)
    kv = _kv(tmp_path, monkeypatch, "posix", replace=wrap(os.replace))
    with pytest.raises(PermissionError):
        kv.put_if_equals("k", None, "v1")
    assert len(calls) == 1


def test_lock_denial_is_a_pending_delete_on_windows_and_a_real_denial_on_posix(tmp_path, monkeypatch):
    real = S.open_private
    calls = []

    def lock_denied(path, flags, *a):
        if path.endswith(".lock"):
            calls.append(path)
            raise PermissionError(13, "lock file pending deletion", path)
        return real(path, flags, *a)
    monkeypatch.setattr(S, "open_private", lock_denied)
    kv = _kv(tmp_path, monkeypatch, "posix", lock_timeout_ms=50)
    with pytest.raises(PermissionError):
        kv.put_if_equals("k", None, "v1")
    assert len(calls) == 1
    kv = _kv(tmp_path, monkeypatch, "nt", lock_timeout_ms=50)
    with pytest.raises(S.ApprovalStoreError) as e:
        kv.put_if_equals("k", None, "v1")
    assert e.value.code == "lock_timeout" and len(calls) > 2
