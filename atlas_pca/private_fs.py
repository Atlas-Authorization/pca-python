"""Owner-only files and directories, one helper for every writer of private state (approval and replay stores, durable state, key
material, witness and revocation state, conformance harness files).

POSIX: mode 0600 for a file, 0700 for a directory, given at creation. Windows: a mode does nothing there, so the file or directory is
created through CreateFileW / CreateDirectoryW with a SECURITY_ATTRIBUTES whose descriptor is ``D:P(A;;FA;;;<current user SID>)``: a
protected DACL (no inherited entries) with exactly one entry, for the current user, applied atomically AT CREATION (restricting a file
afterwards leaves a window in which another process can open it and keep the handle). No dependency: ctypes only.

A directory that already exists is left as it is (an existing path cannot be restricted atomically); every directory this module creates is
private."""
from __future__ import annotations

import os
import secrets
from typing import List, Optional

_WIN = os.name == "nt"
_SID_CACHE: List[str] = []

if _WIN:  # pragma: no cover - exercised by the Windows job
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _adv = ctypes.WinDLL("advapi32", use_last_error=True)

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID), ("bInheritHandle", wintypes.BOOL)]

    class _SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID)]  # TOKEN_USER.User: only the SID pointer at offset 0 is read, never the attributes after it

    _PP = ctypes.POINTER
    # one table, one loop: a 64-bit handle or pointer passed without its prototype is truncated to a C int, so every function is declared
    for _lib, _name, _res, _args in (
        (_k32, "GetCurrentProcess", wintypes.HANDLE, []),
        (_k32, "CloseHandle", wintypes.BOOL, [wintypes.HANDLE]),
        (_k32, "LocalFree", wintypes.HLOCAL, [wintypes.HLOCAL]),
        (_k32, "CreateFileW", wintypes.HANDLE, [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, _PP(_SECURITY_ATTRIBUTES), wintypes.DWORD,
                                                wintypes.DWORD, wintypes.HANDLE]),
        (_k32, "CreateDirectoryW", wintypes.BOOL, [wintypes.LPCWSTR, _PP(_SECURITY_ATTRIBUTES)]),
        (_adv, "OpenProcessToken", wintypes.BOOL, [wintypes.HANDLE, wintypes.DWORD, _PP(wintypes.HANDLE)]),
        (_adv, "GetTokenInformation", wintypes.BOOL, [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, _PP(wintypes.DWORD)]),
        (_adv, "ConvertSidToStringSidW", wintypes.BOOL, [wintypes.LPVOID, _PP(wintypes.LPWSTR)]),
        (_adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW", wintypes.BOOL, [wintypes.LPCWSTR, wintypes.DWORD, _PP(wintypes.LPVOID),
                                                                                         _PP(wintypes.DWORD)]),
        (_adv, "ConvertSecurityDescriptorToStringSecurityDescriptorW", wintypes.BOOL, [wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                                                                         _PP(wintypes.LPWSTR), _PP(wintypes.DWORD)]),
        (_adv, "GetFileSecurityW", wintypes.BOOL, [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, _PP(wintypes.DWORD)]),
    ):
        getattr(_lib, _name).restype = _res
        getattr(_lib, _name).argtypes = _args

    # single-bit rights are written as shifts: a +1 on 0x80000000 or 0x0008 would add a right the call already implies (an equivalent change)
    _TOKEN_QUERY, _TOKEN_USER = 1 << 3, 1
    _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION = 1, 4
    _GENERIC_READ, _GENERIC_WRITE = 1 << 31, 1 << 30
    _FILE_APPEND_DATA = 0x0004
    _SHARE_ALL = 7  # read 1 | write 2 | delete 4: what the C runtime's own open gives, so a rename over the file still works
    _CREATE_NEW, _CREATE_ALWAYS, _OPEN_EXISTING, _OPEN_ALWAYS, _TRUNCATE_EXISTING = 1, 2, 3, 4, 5
    _FILE_ATTRIBUTE_NORMAL = 0x80
    _INVALID = wintypes.HANDLE(-1).value


def _err(what: str) -> OSError:
    e = ctypes.get_last_error()  # type: ignore[name-defined]
    return ctypes.WinError(e) if e else OSError(what)  # type: ignore[name-defined]


def _current_sid() -> str:
    """The string SID of the user this process runs as (token user)."""
    if _SID_CACHE:
        return _SID_CACHE[0]
    tok = wintypes.HANDLE()  # type: ignore[name-defined]
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(tok)):  # type: ignore[name-defined]
        raise _err("OpenProcessToken")
    try:
        need = wintypes.DWORD()  # type: ignore[name-defined]
        _adv.GetTokenInformation(tok, _TOKEN_USER, None, 0, ctypes.byref(need))  # type: ignore[name-defined]
        buf = ctypes.create_string_buffer(need.value)  # type: ignore[name-defined]
        if not _adv.GetTokenInformation(tok, _TOKEN_USER, buf, need, ctypes.byref(need)):  # type: ignore[name-defined]
            raise _err("GetTokenInformation")
        tu = ctypes.cast(buf, ctypes.POINTER(_SID_AND_ATTRIBUTES)).contents  # type: ignore[name-defined]
        s = wintypes.LPWSTR()  # type: ignore[name-defined]
        if not _adv.ConvertSidToStringSidW(tu.Sid, ctypes.byref(s)):  # type: ignore[name-defined]
            raise _err("ConvertSidToStringSidW")
        try:
            _SID_CACHE.append(s.value or "")
        finally:
            _k32.LocalFree(ctypes.cast(s, wintypes.HLOCAL))  # type: ignore[name-defined]
    finally:
        _k32.CloseHandle(tok)
    return _SID_CACHE[0]


def owner_sddl() -> str:
    """The descriptor every private path gets on Windows: protected DACL, one entry, full access for the current user."""
    return "D:P(A;;FA;;;%s)" % _current_sid()


class _Sa:
    """A SECURITY_ATTRIBUTES over the owner-only descriptor (the descriptor memory is released on close)."""

    def __enter__(self):  # pragma: no cover - Windows
        sd = wintypes.LPVOID()  # type: ignore[name-defined]
        if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(owner_sddl(), _SDDL_REVISION_1, ctypes.byref(sd), None):  # type: ignore[name-defined]
            raise _err("ConvertStringSecurityDescriptorToSecurityDescriptorW")
        self._sd = sd
        self.sa = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), sd, False)  # type: ignore[name-defined]
        return self.sa

    def __exit__(self, *_a):  # pragma: no cover - Windows
        _k32.LocalFree(self._sd)  # type: ignore[name-defined]


def open_private(path: str, flags: int, binary: bool = True) -> int:
    """``os.open(path, flags, 0o600)`` whose file is owner-only from its first instant on Windows too. Honours O_CREAT, O_EXCL (CREATE_NEW),
    O_TRUNC, O_APPEND and the access mode. Returns a C runtime file descriptor."""
    if not _WIN:
        return os.open(path, flags, 0o600)
    import msvcrt  # pragma: no cover - Windows
    acc = flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)  # pragma: no cover
    access = {os.O_RDONLY: _GENERIC_READ, os.O_WRONLY: _GENERIC_WRITE, os.O_RDWR: _GENERIC_READ | _GENERIC_WRITE}[acc]
    if flags & os.O_APPEND:
        access = (access & ~_GENERIC_WRITE) | _FILE_APPEND_DATA
    if flags & os.O_CREAT and flags & os.O_EXCL:
        disp = _CREATE_NEW
    elif flags & os.O_CREAT and flags & os.O_TRUNC:
        disp = _CREATE_ALWAYS
    elif flags & os.O_CREAT:
        disp = _OPEN_ALWAYS
    elif flags & os.O_TRUNC:
        disp = _TRUNCATE_EXISTING
    else:
        disp = _OPEN_EXISTING
    with _Sa() as sa:
        h = _k32.CreateFileW(os.fspath(path), access, _SHARE_ALL, ctypes.byref(sa), disp, _FILE_ATTRIBUTE_NORMAL, None)
    if h in (None, _INVALID):
        raise _err("CreateFileW")
    osf = (os.O_APPEND if flags & os.O_APPEND else 0) | (os.O_RDONLY if acc == os.O_RDONLY else 0) | (os.O_BINARY if binary else os.O_TEXT)
    try:
        return msvcrt.open_osfhandle(h, osf)
    except OSError:
        _k32.CloseHandle(h)
        raise


def mkdir_private(path: str) -> None:
    """Create one directory owner-only (0700 on POSIX; the protected one-entry descriptor on Windows, at creation). Raises FileExistsError."""
    if not _WIN:
        os.mkdir(path, 0o700)
        return
    with _Sa() as sa:  # pragma: no cover - Windows
        if not _k32.CreateDirectoryW(os.fspath(path), ctypes.byref(sa)):
            e = ctypes.get_last_error()
            if e in (80, 183):  # ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS
                raise FileExistsError(path)
            raise ctypes.WinError(e)


def makedirs_private(path: str) -> None:
    """``os.makedirs(path, 0o700, exist_ok=True)`` where every directory it creates is owner-only; an existing one is left as it is."""
    path = os.path.abspath(path)
    if os.path.isdir(path):
        return
    parent = os.path.dirname(path)
    if parent and parent != path:
        makedirs_private(parent)
    try:
        mkdir_private(path)
    except FileExistsError:
        if not os.path.isdir(path):
            raise


def mkdtemp_private(prefix: str = "tmp", dir: Optional[str] = None) -> str:
    """``tempfile.mkdtemp`` whose directory is owner-only from creation on every platform."""
    import tempfile
    base = dir or tempfile.gettempdir()
    for _ in range(100):
        p = os.path.join(base, prefix + secrets.token_hex(6))
        try:
            mkdir_private(p)
            return p
        except FileExistsError:
            continue
    raise FileExistsError("no free temporary directory name under %s" % base)


def describe_restriction(path: str) -> str:
    """What the owner-only restriction of `path` reads back as: POSIX ``0o600`` style permission bits; Windows the DACL as an SDDL string."""
    if not _WIN:
        return oct(os.stat(path).st_mode & 0o777)
    need = wintypes.DWORD()  # type: ignore[name-defined]  # pragma: no cover - Windows
    _adv.GetFileSecurityW(path, _DACL_SECURITY_INFORMATION, None, 0, ctypes.byref(need))  # type: ignore[name-defined]
    buf = ctypes.create_string_buffer(need.value)  # type: ignore[name-defined]
    if not _adv.GetFileSecurityW(path, _DACL_SECURITY_INFORMATION, buf, need, ctypes.byref(need)):  # type: ignore[name-defined]
        raise _err("GetFileSecurityW")
    s = wintypes.LPWSTR()  # type: ignore[name-defined]
    if not _adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(buf, _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION, ctypes.byref(s), None):  # type: ignore[name-defined]
        raise _err("ConvertSecurityDescriptorToStringSecurityDescriptorW")
    try:
        return s.value or ""
    finally:
        _k32.LocalFree(ctypes.cast(s, wintypes.HLOCAL))  # type: ignore[name-defined]


def normalized_owner_sddl() -> str:
    """The owner-only descriptor as Windows itself prints it back: SDDL writes a well-known account as its alias (the built-in administrator is
    ``LA``), so the descriptor is round-tripped through the same conversion that read-backs use before it is compared."""
    if not _WIN:
        return "0o600"
    sd = wintypes.LPVOID()  # type: ignore[name-defined]  # pragma: no cover - Windows
    if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(owner_sddl(), _SDDL_REVISION_1, ctypes.byref(sd), None):  # type: ignore[name-defined]
        raise _err("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        s = wintypes.LPWSTR()  # type: ignore[name-defined]
        if not _adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION, ctypes.byref(s), None):  # type: ignore[name-defined]
            raise _err("ConvertSecurityDescriptorToStringSecurityDescriptorW")
        try:
            return s.value or ""
        finally:
            _k32.LocalFree(ctypes.cast(s, wintypes.HLOCAL))  # type: ignore[name-defined]
    finally:
        _k32.LocalFree(sd)  # type: ignore[name-defined]
