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
