"""The post-quantum (endemic LWE) base OT plugged into the OT-extension channel and the no-dealer offline phase: no reference vectors, the
correctness relations (the receiver gets the chosen message; shares of a product sum to the product). Needs liblweot (ATLAS_PCA_LIBLWEOT),
libsodium through pysodium and the cryptography package."""
import pytest

pytest.importorskip("pysodium")
pytest.importorskip("cryptography")

from atlas_pca import mpc as M  # noqa: E402
from atlas_pca import mpc_lwe_ot as E  # noqa: E402
from atlas_pca import mpc_mascot as MA  # noqa: E402
from atlas_pca.mpc_ot import Ot, OtChannel  # noqa: E402

if not E.available():
    pytest.skip("liblweot not available", allow_module_level=True)


def test_channel_over_the_endemic_base_ot():
    ch = OtChannel(Ot.ot_random(Ot.split_mix64(11)), E.with_endemic_base_ot())
    bits = [0, 1, 1, 0, 1]
    m0 = [3, 5, 7, 9, 11]
    m1 = [4, 6, 8, 10, 12]
    got = ch.extend_ot(bits, m0, m1).received
    assert got == [m1[i] if b else m0[i] for i, b in enumerate(bits)]
    assert ch.base_transcript is None  # the endemic base OT keeps no EC transcript


def test_no_dealer_multiplication_over_the_endemic_base_ot():
    off = MA.make_no_dealer_offline(2, 7, MA.NoDealerOptions(base_ot_fn=E.with_endemic_base_ot()))
    x, y = [5, 9], [11, 13]
    z = off.ot_share_multiply(x, y)
    assert (z[0] + z[1]) % M.PRIME == ((x[0] + x[1]) * (y[0] + y[1])) % M.PRIME
