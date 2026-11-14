"""The built-in action catalog is the reference's catalog, entry for entry."""
import json
import os
import re

import pytest

from atlas_pca.facade import BUILTIN_ACTIONS

KEYS = ("connector", "action", "verb", "reversibility", "blastRadius", "amountField", "description", "aliases", "traits")
TS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "packages", "pca", "src", "catalog-builtin.generated.ts")


def test_shape():
    verbs = [a["verb"] for a in BUILTIN_ACTIONS]
    assert len(verbs) == len(set(verbs)) > 0
    for a in BUILTIN_ACTIONS:
        assert isinstance(a["reversibility"], str) and a["reversibility"]
        assert 0 <= a["blastRadius"] <= 1


@pytest.mark.skipif(not os.path.exists(TS), reason="reference source not present (standalone package)")
def test_matches_reference():
    src = open(TS, encoding="utf-8").read()
    m = re.search(r"=\s*(\[.*\]);\s*$", src, re.S)
    assert m, "catalog array not found"
    # the generated file is one object literal per line with bare keys: quote the known keys, drop the trailing comma
    text = re.sub(r"([{,] )(%s): " % "|".join(KEYS), r'\1"\2": ', m.group(1))
    ref = json.loads(re.sub(r",\s*\]$", "]", text))
    assert BUILTIN_ACTIONS == ref
