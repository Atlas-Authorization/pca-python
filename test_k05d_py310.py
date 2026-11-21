"""Kill tests for the mutants that drop the byteorder argument of int.from_bytes / int.to_bytes.

CPython 3.11 gave both a default byteorder of "big", so on the 3.12 the mutation job runs, `to_bytes(4, )` is the same call.
The package supports Python >= 3.9, where the mutant raises TypeError. These mutants are therefore killed on a supported
interpreter: while a mutant is under test, the existing known-answer tests that reach each call are re-run under the Python 3.10
interpreter the job provides (PCA_PY310: the package's optional dependencies, the test dependencies and mutmut, whose trampoline the mutated modules import), in the mutated tree.

The in-process calls come first on purpose: mutmut runs a mutant only against the tests that called its function in the stats
run, and a call in a subprocess is not traced."""
import os
import re
import subprocess
import sys

import pytest

from atlas_pca import attest_cert, attest_common, intent_map, sigstore_bundle

# existing tests that pin the exact bytes / the accepting path of each call (they pass on 3.9 .. 3.13)
_NODEIDS = [
    "test_attest_units.py::Common::test_binding_known_answer_and_refusals",   # _lp (attest_common:33), attestation_binding (:62)
    "test_k05_attest_common_kill.py::test_ec_point_and_raw_ecdsa",            # ecdsa_verify_raw (:441, both halves)
    "test_k05_kill_intel_ocsp_cert.py::test_pss_params_values_and_defaults",  # _pss_params (attest_cert:388, :390)
    "test_k05_kill_stores_sigstore.py::test_tlv",                             # sigstore_bundle._tlv (:238)
    "test_k05_kill_stores_sigstore.py::test_sct_signed_bytes_are_the_rfc6962_structure",  # _verify_sct (:485)
    "test_k042_map_units.py::test_encodings",                                 # intent_map._u64be
    "test_k042_map_units.py::test_hash_domains_and_errors",
]


def _touch(fn, *args):
    try:
        fn(*args)
    except Exception as e:  # noqa: BLE001 - only the call (the stats trace) matters here
        if type(e).__name__.startswith("Mutmut"):  # mutmut's own "fail" probe must reach its runner
            raise


def test_the_byteorder_calls_are_killed_on_a_supported_python_below_3_11():
    _touch(attest_common._lp, "a")
    _touch(attest_common.attestation_binding, {})
    _touch(attest_common.ecdsa_verify_raw, None, b"", b"", "sha256")
    _touch(attest_cert._pss_params, b"", None)
    _touch(sigstore_bundle._tlv, b"\x30\x00", 0)
    _touch(sigstore_bundle._verify_sct, None, None, None)
    _touch(intent_map._u64be, 0)
    if sys.version_info < (3, 11):
        return  # this interpreter already is the supported old one: every ordinary test kills these mutants
    old = os.environ.get("PCA_PY310")
    if "__mutmut_" not in os.environ.get("MUTANT_UNDER_TEST", ""):
        if old is None:
            pytest.skip("no Python 3.10 interpreter (PCA_PY310) and no mutant under test")
    assert old, "the mutation job must provide PCA_PY310 (a Python 3.10 with pytest + cryptography)"
    ver = subprocess.run([old, "-c", "import sys; print(sys.version_info[:2])"], capture_output=True, text=True, timeout=60)
    assert ver.stdout.strip() == "(3, 10)", "PCA_PY310 is not a Python 3.10 interpreter: " + (ver.stdout + ver.stderr)[-300:]
    # the unmutated clean run goes through here too: a missing import in that interpreter fails it (and the whole shard) loudly
    # instead of "killing" every mutant of these functions for the wrong reason. The summary line proves every test really ran.
    r = subprocess.run([old, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *_NODEIDS],
                       cwd=os.getcwd(), capture_output=True, text=True, timeout=600)
    assert r.returncode == 0 and re.search(r"\b%d passed\b" % len(_NODEIDS), r.stdout) and "error" not in r.stdout.lower().split("passed")[-1], \
        (r.stdout[-1500:] + r.stderr[-500:])
