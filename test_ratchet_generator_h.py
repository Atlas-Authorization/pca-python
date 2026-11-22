"""The Pedersen generator H is RistrettoPoint.hashToCurve(sha512(label)) exactly as the reference derives it (RFC 9496 map)."""
from atlas_pca import ratchet_group as R


def test_generator_h_matches_the_reference():
    assert R.H.hex() == "b610f395494953a558726b2cc614029452d9e19ba1e83e31e27c0718f8932618"
