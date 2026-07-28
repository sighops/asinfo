from unittest import TestCase

from ipasn.mrt import is_asn_invalid


class TestIsAsnInvalid(TestCase):

    def test_real_world_asns_are_valid(self):
        for asn in (15169, 1128, 3320, 64495, 999_999):
            self.assertFalse(is_asn_invalid(asn), f"AS{asn} should not be invalid")

    def test_zero_and_negative_are_invalid(self):
        self.assertTrue(is_asn_invalid(0))
        self.assertTrue(is_asn_invalid(-1))

    def test_reserved_16bit_range_is_invalid(self):
        self.assertTrue(is_asn_invalid(64496))
        self.assertTrue(is_asn_invalid(131071))
        self.assertFalse(is_asn_invalid(64495))
        self.assertFalse(is_asn_invalid(131072))

    def test_reserved_32bit_private_use_is_invalid(self):
        # No clean "just below the floor" case to assert as valid here:
        # everything near 4.2 billion is already caught by the unallocated
        # heuristic (>= 1,000,000) regardless of this specific range.
        self.assertTrue(is_asn_invalid(4_200_000_000))

    def test_unallocated_heuristic_range_is_invalid(self):
        self.assertTrue(is_asn_invalid(1_000_000))
        self.assertFalse(is_asn_invalid(999_999))
