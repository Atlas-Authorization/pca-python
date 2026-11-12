"""At most 8 RFC 3161 timestamps per Sigstore bundle (each one is a full CMS + chain + signature verification): the ninth is refused
before any of them is verified, with stage `tsa` and `too many RFC 3161 timestamps (<n>, at most 8)`."""
import copy
import json
import os

import pytest

pytest.importorskip("cryptography")

from atlas_pca.sigstore_bundle import parse_trusted_root, verify_sigstore_bundle_core

_HERE = os.path.dirname(os.path.abspath(__file__))
_P = next(p for p in (os.path.join(_HERE, "conformance", "sigstore-vectors.json"),
                      os.path.join(_HERE, "conformance", "sigstore-vectors.json")) if os.path.exists(p))
with open(_P, encoding="utf-8") as f:
    DOC = json.load(f)
CASE = next(c for c in DOC["cases"] if c["name"] == "npm/sigstore-5.0.0")
ROOT = parse_trusted_root(DOC["roots"][CASE["roots"]])


def with_timestamps(n):
    b = copy.deepcopy(CASE["bundle"])
    b["verificationMaterial"]["timestampVerificationData"] = {"rfc3161Timestamps": [{"signedTimestamp": "AAAA"} for _ in range(n)]}
    return verify_sigstore_bundle_core(b, ROOT)


def test_the_baseline_bundle_verifies():
    assert verify_sigstore_bundle_core(CASE["bundle"], ROOT)["ok"] is True


@pytest.mark.parametrize("n", [9, 10, 100])
def test_more_than_eight_timestamps_are_refused_before_any_is_verified(n):
    r = with_timestamps(n)
    assert r["ok"] is False and r["code"] == "tsa"
    assert r["detail"] == "too many RFC 3161 timestamps (%d, at most 8)" % n


def test_eight_timestamps_reach_the_verification():
    r = with_timestamps(8)
    assert r["ok"] is False and r["code"] == "tsa"
    assert "too many" not in r["detail"]
