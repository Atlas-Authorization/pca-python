"""Point validation is fail-closed whatever libsodium build answers is_valid_point: a mixed-order point B + T (T of order 2)
passes 1.0.20's X-only subgroup test, so the group law has to refuse it."""
import unittest

from atlas_pca import ed25519 as ed
from atlas_pca import frost

BASE = bytes([0x58]) + bytes([0x66]) * 31
T2 = bytes([0xEC]) + bytes([0xFF]) * 30 + bytes([0x7F])  # (0, -1), order 2
IDENT = bytes([1]) + bytes(31)
NONCANON = bytes([0xEE]) + bytes([0xFF]) * 30 + bytes([0x7F])  # y = p + 1
NEG_BASE = BASE[:31] + bytes([BASE[31] | 0x80])


class MixedOrderPoints(unittest.TestCase):
    def test_group_law_check(self):
        mixed = ed._encode(ed._add(ed._decode(BASE), ed._decode(T2)))
        self.assertTrue(ed.is_safe_point_bytes(BASE))
        self.assertTrue(ed.is_safe_point_bytes(NEG_BASE))
        for bad in (mixed, T2, IDENT, bytes(32), NONCANON, BASE[:31]):
            self.assertFalse(ed.is_safe_point_bytes(bad))

    def test_decode_safe_point(self):
        mixed = ed._encode(ed._add(ed._decode(BASE), ed._decode(T2)))
        self.assertEqual(frost.decode_safe_point(BASE), BASE)
        self.assertEqual(frost.decode_safe_point(NEG_BASE), NEG_BASE)
        for bad in (mixed, T2, IDENT, bytes(32), NONCANON):
            with self.assertRaises(ValueError):
                frost.decode_safe_point(bad)


if __name__ == "__main__":
    unittest.main()
