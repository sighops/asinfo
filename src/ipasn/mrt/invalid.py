"""ASN "invalid" (private-use / reserved / unallocated) range checks.

Used when picking a route's origin AS out of an AS_PATH: an AS in one of
these ranges is never a legitimate origin, so parsing falls back to an
earlier AS_PATH entry (or, for AS_SET segments, excludes it from the
candidate set) rather than reporting it.

References:
    IANA AS number registry: https://www.iana.org/assignments/as-numbers/
    RFC 1930, RFC 5398, RFC 6996, RFC 7300
"""

from __future__ import annotations

# RFC 5398 (documentation/sample use) + RFC 6996 (private use) 16-bit range.
_RESERVED_16BIT_LOW = 64496
_RESERVED_16BIT_HIGH = 131071

# RFC 6996: top of the 32-bit space reserved for private use.
_RESERVED_32BIT_PRIVATE_USE_FLOOR = 4_200_000_000

# Heuristic: IANA has not allocated anywhere near this high as of this
# writing, so a "real" origin AS above it is far more likely to be
# corrupt/misparsed data than a genuine allocation. Revisit against the IANA
# registry (linked above) as allocations progress - this is deliberately a
# loose heuristic, not a spec-defined boundary.
_UNALLOCATED_32BIT_FLOOR = 1_000_000


def is_asn_invalid(asn: int) -> bool:
    """Returns True if `asn` is not a plausible real-world route origin."""
    if asn <= 0:
        return True
    if asn >= _RESERVED_32BIT_PRIVATE_USE_FLOOR:
        return True
    if _RESERVED_16BIT_LOW <= asn <= _RESERVED_16BIT_HIGH:
        return True
    if asn >= _UNALLOCATED_32BIT_FLOOR:
        return True
    return False
