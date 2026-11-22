"""The libsodium that ships inside the platform wheels (atlas_pca/_native), made visible to pysodium without touching the system.

pysodium finds its library with ctypes.util.find_library at import; ``prefer_bundled`` points that lookup at the bundled copy for the
duration of the import only. Without a bundled copy (the pure wheel, an sdist, an unsupported platform) the system libsodium is used."""
import contextlib
import ctypes.util
import os
import sys

_FILES = {"win32": "libsodium.dll", "darwin": "libsodium.dylib"}


def bundled():
    """The bundled libsodium's path, or None when this install carries none."""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_native", _FILES.get(sys.platform, "libsodium.so"))
    return p if os.path.isfile(p) else None


_BREW = ("/opt/homebrew/lib/libsodium.dylib", "/usr/local/lib/libsodium.dylib")  # Homebrew: ctypes' macOS lookup does not search them


def _system_fallback():
    """A Homebrew libsodium on macOS when the standard lookup finds none, else None."""
    if sys.platform != "darwin" or ctypes.util.find_library("sodium"):
        return None
    return next((p for p in _BREW if os.path.isfile(p)), None)


@contextlib.contextmanager
def prefer_bundled():
    path = bundled() or _system_fallback()
    if path is None:
        yield
        return
    original = ctypes.util.find_library
    ctypes.util.find_library = lambda name: path if name in ("sodium", "libsodium") else original(name)
    try:
        yield
    finally:
        ctypes.util.find_library = original
