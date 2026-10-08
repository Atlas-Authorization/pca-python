"""Shared known-good PCActn fixtures for the tests.

Loaded from the shared conformance vectors (the same source sdks/python-pca/test_server.py uses), so
the signed bytes are known-good and nothing here mints or re-signs — no network, no crewai needed.
"""
import copy
import json
import os
from typing import Any, Dict, Optional

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "conformance")


def _valid_vector() -> Dict[str, Any]:
    with open(os.path.join(_DIR, "vectors.json"), encoding="utf-8") as f:
        doc = json.load(f)
    return next(v for v in doc["vectors"] if v["name"] == "valid-in-plan-action")


_VEC = _valid_vector()

PCACTN: Dict[str, Any] = _VEC["pcactn"]
GRANT: Dict[str, Any] = _VEC["grant"]
NOW: int = _VEC["context"]["now"]
AUD: str = _VEC["context"]["aud"]
VERB: str = PCACTN["action"]["verb"]
RESOURCE: str = PCACTN["action"]["resource"]
REQUIRE: str = "%s:%s" % (VERB, RESOURCE)


def resolver(grant_ref: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return the fixture grant only for its own grant_ref; everything else is unknown."""
    return GRANT if grant_ref == PCACTN["grant_ref"] else None


def tampered_pcactn() -> Dict[str, Any]:
    """A deep copy of the valid PCActn with one leaf-signature byte flipped.

    Still well-formed on the wire (canonical 64-byte base64url sig), so it reaches the crypto check and
    fails there: a classic invalid proof.
    """
    bad = copy.deepcopy(PCACTN)
    sig = bad["sig"]
    swap = "B" if sig[0] != "B" else "C"
    bad["sig"] = swap + sig[1:]
    return bad
