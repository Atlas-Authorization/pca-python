"""Durable state's Windows rules, pinned on every OS by giving the module a stand-in `os` named "nt" or "posix" (and on Windows also
against the real kernel): the liveness probe of a lock holder is OpenProcess + GetExitCodeProcess there, never os.kill(pid, 0) (which
is CTRL_C_EVENT on Windows), and the state directory is chmod 0700 only where a mode means something."""
import ctypes
import os
import subprocess
import sys

import pytest

from atlas_pca import durable_state as D


class _Os:
    def __init__(self, name, **over):
        self.name = name
        self.__dict__.update(over)

    def __getattr__(self, a):
        return getattr(os, a)


class _Fn:
    def __init__(self, impl):
        self.impl, self.calls, self.restype = impl, [], None

    def __call__(self, *a):
        self.calls.append(a)
        return self.impl(*a)


class _K32:
    """kernel32 as _pid_alive uses it: OpenProcess gives `handle` (None = NULL with last error `err`), GetExitCodeProcess reports `code`."""

    def __init__(self, handle, err=0, code=259, ok=1):
        self.err = err

        def open_process(*_a):
            return handle

        def exit_code(_h, ref):
            ref._obj.value = code
            return ok
        self.OpenProcess, self.GetExitCodeProcess, self.CloseHandle = _Fn(open_process), _Fn(exit_code), _Fn(lambda _h: 1)


def _alive(monkeypatch, k32, pid=4321):
    made = []

    def windll(name, **kw):
        made.append((name, kw))
        return k32
    monkeypatch.setattr(ctypes, "WinDLL", windll, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: k32.err, raising=False)  # what OpenProcess left (Windows-only in ctypes)
    monkeypatch.setattr(D, "os", _Os("nt", kill=lambda *_a: pytest.fail("os.kill is Ctrl-C on Windows, never a probe")))
    return D._pid_alive(pid), made


def test_windows_probe_opens_the_process_for_limited_query_and_reads_still_active(monkeypatch):
    k32 = _K32(0x1234)
    got, made = _alive(monkeypatch, k32)
    assert got is True
    assert made == [("kernel32", {"use_last_error": True})]
    assert k32.OpenProcess.restype is ctypes.c_void_p  # a 64-bit handle is not truncated to a C int
    assert k32.OpenProcess.calls == [(0x1000, False, 4321)]  # PROCESS_QUERY_LIMITED_INFORMATION, not inheritable
    assert [c[0].value for c in k32.GetExitCodeProcess.calls] == [0x1234]
    assert [c[0].value for c in k32.CloseHandle.calls] == [0x1234]  # the handle is never leaked


@pytest.mark.parametrize("code,ok", [(0, 1), (260, 1), (259, 0)])
def test_windows_probe_an_exited_process_or_an_unreadable_exit_code_is_dead(monkeypatch, code, ok):
    k32 = _K32(0x1234, code=code, ok=ok)
    assert _alive(monkeypatch, k32)[0] is False
    assert len(k32.CloseHandle.calls) == 1


@pytest.mark.parametrize("err,want", [(5, True), (87, False), (6, False)])
def test_windows_probe_access_denied_means_it_exists(monkeypatch, err, want):
    k32 = _K32(None, err=err)
    assert _alive(monkeypatch, k32)[0] is want
    assert k32.GetExitCodeProcess.calls == [] and k32.CloseHandle.calls == []


def test_windows_probe_that_cannot_load_kernel32_says_dead(monkeypatch):
    def windll(*_a, **_k):
        raise OSError("no kernel32")
    monkeypatch.setattr(ctypes, "WinDLL", windll, raising=False)
    monkeypatch.setattr(D, "os", _Os("nt"))
    assert D._pid_alive(4321) is False


class _Stop(Exception):
    pass


def test_state_directory_is_chmod_0700_on_posix_and_left_to_the_descriptor_on_windows(tmp_path, monkeypatch):
    calls = []

    def chmod(*a):
        calls.append(a)
        raise _Stop()  # stop right after the call: the rest of opening is not what this pins
    d = str(tmp_path / "ds")
    monkeypatch.setattr(D, "os", _Os("posix", chmod=chmod))
    with pytest.raises(_Stop):
        D.open_durable_state(dir=d)
    assert calls == [(d, 0o700)]
    monkeypatch.setattr(D, "os", _Os("nt", chmod=chmod))
    D.open_durable_state(dir=str(tmp_path / "ds2")).set("k", "v")
    assert calls == [(d, 0o700)]


@pytest.mark.skipif(os.name != "nt", reason="the real Windows kernel")
def test_windows_probe_against_real_processes():
    assert D._pid_alive(os.getpid()) is True
    child = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(260)"])
    assert child.wait(60) == 260
    assert D._pid_alive(child.pid) is False  # the Popen handle keeps the exited process object (and its pid) from reuse
