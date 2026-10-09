"""Make the sibling ``atlas_pca`` (sdks/python-pca) importable when running the tests in-tree.

In a real install ``atlas-pca`` is a declared dependency and is already on the path; this shim only
helps the test run find the reference verifier without an install, mirroring how sdks/python-pca runs
its own tests from its directory.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PYTHON_PCA = os.path.normpath(os.path.join(_HERE, "..", ".."))
if _PYTHON_PCA not in sys.path:
    sys.path.insert(0, _PYTHON_PCA)


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _duck_typed_unless_real(request, monkeypatch):
    """The in-tree unit tests exercise the duck-typed ``GuardedFunction`` even when agent-framework
    happens to be installed (they block its import); the ``test_real_*`` modules run against the real
    framework. (The middleware base class is bound at import time, so it is unaffected here.)"""
    if request.module.__name__.startswith("test_real"):
        return
    import sys

    monkeypatch.setitem(sys.modules, "agent_framework", None)  # makes ``import agent_framework`` raise ImportError
