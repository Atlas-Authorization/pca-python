"""idna_host: with Ada installed the host mapping is UTS 46 non-transitional (the reference); the corpus cases of ciba / vc run it too."""
import pytest

from atlas_pca import idna_host

CASES = {"Straße": "xn--strae-oqa", "münchen.de": "xn--mnchen-3ya.de", "MÜNCHEN.de": "xn--mnchen-3ya.de", "a.bé": "a.xn--b-bga", "faß.de": "xn--fa-hia.de"}


def test_ada_matches_uts46_nontransitional():
    pytest.importorskip("ada_url")
    assert idna_host._ada is not None
    for src, want in CASES.items():
        assert idna_host.domain_to_ascii(src) == want


def test_approximation_handles_plain_names():
    assert idna_host._approx("münchen.de") == "xn--mnchen-3ya.de"
    assert idna_host._approx("a.bé") == "a.xn--b-bga"
