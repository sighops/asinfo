import pytest

from ipasn.mrt import is_asn_invalid


@pytest.mark.parametrize("asn", [15169, 1128, 3320, 64495, 999_999])
def test_real_world_asns_are_valid(asn):
    assert not is_asn_invalid(asn)


@pytest.mark.parametrize("asn", [0, -1])
def test_zero_and_negative_are_invalid(asn):
    assert is_asn_invalid(asn)


def test_reserved_16bit_range_is_invalid():
    assert is_asn_invalid(64496)
    assert is_asn_invalid(131071)
    assert not is_asn_invalid(64495)
    assert not is_asn_invalid(131072)


def test_reserved_32bit_private_use_is_invalid():
    # No clean "just below the floor" case to assert as valid here:
    # everything near 4.2 billion is already caught by the unallocated
    # heuristic (>= 1,000,000) regardless of this specific range.
    assert is_asn_invalid(4_200_000_000)


def test_unallocated_heuristic_range_is_invalid():
    assert is_asn_invalid(1_000_000)
    assert not is_asn_invalid(999_999)
