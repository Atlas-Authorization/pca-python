"""OID content / arc caps: the decimal conversion of one arc is quadratic in its length and runs on attacker DER before any trust
check, so an OID past 256 content bytes or an arc past 64 base-128 groups is refused first (`extension OID is too long`,
`extension OID has an oversized arc`); the reference's x509 reader and every hardened native use the same limits."""
import time

import pytest

from atlas_pca import attest_der as D
from atlas_pca import sigstore_bundle as S


def oid_tlv(content):
    n = len(content)
    if n < 0x80:
        h = bytes([6, n])
    elif n < 0x100:
        h = bytes([6, 0x81, n])
    elif n < 0x10000:
        h = bytes([6, 0x82, n >> 8, n & 255])
    else:
        h = bytes([6, 0x83, n >> 16, (n >> 8) & 255, n & 255])
    return h + bytes(content)


def der_oid(content):
    b = oid_tlv(content)
    return D._oid_to_dotted(b, D.read_tlv(b, 0))


def sig_oid(content):
    b = oid_tlv(content)
    return S._oid(b, S._tlv(b, 0))


def arc(groups):
    return [0x2A] + [0x81] * (groups - 1) + [0x01]


FUNCS = [(der_oid, D.DerError, "extension OID is too long", "extension OID has an oversized arc"),
         (sig_oid, S._Fail, "OID is too long", "OID has an oversized arc")]


@pytest.mark.parametrize("fn,exc,too_long,oversized", FUNCS)
def test_ordinary_oids_decode(fn, exc, too_long, oversized):
    assert fn([0x55, 0x1D, 0x13]) == "2.5.29.19"
    # 2.25.<128-bit UUID arc>: 19 base-128 groups
    uuid = [0x69] + [0x83] + [0xFF] * 17 + [0x7F]
    assert fn(uuid).startswith("2.25.") and fn(uuid) == "2.25." + str(2 ** 128 - 1)


@pytest.mark.parametrize("fn,exc,too_long,oversized", FUNCS)
def test_content_of_exactly_256_bytes_is_accepted_and_257_is_too_long(fn, exc, too_long, oversized):
    ok = [0x2A] * 256  # 256 single-group arcs
    assert fn(ok).count(".") == 256
    with pytest.raises(exc) as e:
        fn(ok + [0x2A])
    assert str(e.value) == too_long
    with pytest.raises(exc) as e:
        fn([0x81] * 299 + [0x01])
    assert str(e.value) == too_long


@pytest.mark.parametrize("fn,exc,too_long,oversized", FUNCS)
def test_an_arc_of_exactly_64_groups_is_accepted_and_65_is_oversized(fn, exc, too_long, oversized):
    assert fn(arc(64)).startswith("1.")
    with pytest.raises(exc) as e:
        fn(arc(65))
    assert str(e.value) == oversized
    # the group counter restarts per arc: two 64-group arcs are fine
    assert fn([0x2A] + [0x81] * 63 + [0x01] + [0x81] * 63 + [0x01]).count(".") >= 2
    # the first arc (the head) counts too
    with pytest.raises(exc) as e:
        fn([0x81] * 64 + [0x01])
    assert str(e.value) == oversized


@pytest.mark.parametrize("fn,exc,too_long,oversized", FUNCS)
def test_a_huge_single_arc_is_refused_fast(fn, exc, too_long, oversized):
    t0 = time.perf_counter()
    with pytest.raises(exc) as e:
        fn([0xFF] * 100_000 + [0x7F])
    assert str(e.value) == too_long
    assert time.perf_counter() - t0 < 1.0


def test_the_existing_refusals_are_unchanged():
    with pytest.raises(D.DerError) as e:
        der_oid([0x80, 0x01])
    assert str(e.value) == "extension OID has a non-minimal arc"
    with pytest.raises(D.DerError) as e:
        der_oid([0x55, 0x81])
    assert str(e.value) == "extension OID is truncated"
