"""The platform branches of atlas_pca/_sodium_path.py (win32 dll, darwin dylib + Homebrew fallback) run on every OS by patching sys.platform,
so the Linux mutation job decides their mutants too (no macOS or Windows runner needed for pure string / path logic)."""
import ctypes.util
import os
import sys
import types

import pytest

from atlas_pca import _sodium_path as S


def _native(tmp_path, monkeypatch, plat, name):
    d = tmp_path / "_native"
    d.mkdir()
    (d / name).write_bytes(b"x")
    monkeypatch.setattr(S, "__file__", str(tmp_path / "m.py"))
    monkeypatch.setattr(sys, "platform", plat)


@pytest.mark.parametrize("plat,name", [("win32", "libsodium.dll"), ("darwin", "libsodium.dylib"), ("linux", "libsodium.so"), ("freebsd13", "libsodium.so")])
def test_bundled_picks_the_platforms_library_name(tmp_path, monkeypatch, plat, name):
    _native(tmp_path, monkeypatch, plat, name)
    assert S.bundled() == str(tmp_path / "_native" / name)


@pytest.mark.parametrize("plat,present,absent", [("win32", "libsodium.so", "libsodium.dll"), ("darwin", "libsodium.so", "libsodium.dylib"), ("linux", "libsodium.dll", "libsodium.so")])
def test_bundled_ignores_another_platforms_library_and_is_none_without_its_own(tmp_path, monkeypatch, plat, present, absent):
    _native(tmp_path, monkeypatch, plat, present)
    assert S.bundled() is None


def test_system_fallback_is_darwin_only_and_only_without_a_standard_lookup(monkeypatch):
    brew = S._BREW
    assert brew == ("/opt/homebrew/lib/libsodium.dylib", "/usr/local/lib/libsodium.dylib")
    present = {brew[1]}
    monkeypatch.setattr(S, "os", types.SimpleNamespace(path=types.SimpleNamespace(isfile=lambda p: p in present)))
    monkeypatch.setattr(ctypes.util, "find_library", lambda n: None)
    monkeypatch.setattr(sys, "platform", "linux")
    assert S._system_fallback() is None
    monkeypatch.setattr(sys, "platform", "darwin")
    assert S._system_fallback() == brew[1]  # the first existing one
    present.add(brew[0])
    assert S._system_fallback() == brew[0]  # Apple-silicon Homebrew wins when both exist
    present.clear()
    assert S._system_fallback() is None
    present.add(brew[0])
    monkeypatch.setattr(ctypes.util, "find_library", lambda n: "libsodium.dylib")
    assert S._system_fallback() is None  # the standard lookup found one: no fallback


def test_prefer_bundled_redirects_only_sodium_lookups_and_restores(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "bundled", lambda: "/b/libsodium.x")
    orig = lambda n: "orig:" + n
    monkeypatch.setattr(ctypes.util, "find_library", orig)
    with S.prefer_bundled():
        assert ctypes.util.find_library("sodium") == "/b/libsodium.x"
        assert ctypes.util.find_library("libsodium") == "/b/libsodium.x"
        assert ctypes.util.find_library("c") == "orig:c"
    assert ctypes.util.find_library is orig
    monkeypatch.setattr(S, "bundled", lambda: None)
    monkeypatch.setattr(S, "_system_fallback", lambda: None)
    with S.prefer_bundled():
        assert ctypes.util.find_library is orig
