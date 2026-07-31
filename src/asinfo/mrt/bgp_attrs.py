"""BGP path-attribute parsing (RFC 4271 §4.3, RFC 6793 for 4-octet ASNs),
scoped to exactly what's needed to determine a route's origin AS: decoding
AS_PATH and, for legacy 2-octet-ASN table dumps, AS4_PATH segments.

Other path attributes (ORIGIN, NEXT_HOP, MED, COMMUNITIES, ...) are skipped
over by their declared length without being decoded - nothing here needs them.
"""

from __future__ import annotations

from dataclasses import dataclass

from .invalid import is_asn_invalid
from .reader import ByteReader, MrtFormatError

ATTR_TYPE_AS_PATH = 2
ATTR_TYPE_AS4_PATH = 17

SEG_TYPE_AS_SET = 1
SEG_TYPE_AS_SEQUENCE = 2
SEG_TYPE_AS_CONFED_SEQUENCE = 3  # RFC 5065 - confederation-internal, legacy
SEG_TYPE_AS_CONFED_SET = 4

_EXTENDED_LENGTH_FLAG = 0x10


@dataclass(frozen=True, slots=True)
class PathSegment:
    seg_type: int
    asns: tuple[int, ...]


def _read_attr_header(reader: ByteReader) -> tuple[int, int]:
    """Reads one path-attribute's (type_code, value_length), leaving the
    cursor positioned at the start of its value."""
    flags = reader.read_u8()
    type_code = reader.read_u8()
    length = reader.read_u16() if flags & _EXTENDED_LENGTH_FLAG else reader.read_u8()
    return type_code, length


def _parse_path_segments(data: bytes, asn_width: int) -> list[PathSegment]:
    reader = ByteReader(data)
    segments = []
    while len(reader):
        seg_type = reader.read_u8()
        count = reader.read_u8()
        asns = tuple(
            reader.read_u32() if asn_width == 4 else reader.read_u16() for _ in range(count)
        )
        segments.append(PathSegment(seg_type, asns))
    return segments


def _origin_from_segments(segments: list[PathSegment]) -> int | set[int] | None:
    """The origin AS is the AS that first announced the route: the last
    (right-most, oldest) entry of the last AS_SEQUENCE segment - each AS
    along the way prepends itself to the *left* of the path as it
    propagates, so the origin ends up at the right-hand end.

    If the final segment is an AS_SET (formed by route aggregation), the
    true origin is inherently ambiguous, so all valid candidates are
    returned as a set and it's left to the caller to pick one.
    """
    for segment in reversed(segments):
        if segment.seg_type == SEG_TYPE_AS_SEQUENCE:
            for asn in reversed(segment.asns):
                if not is_asn_invalid(asn):
                    return asn
            continue  # every ASN here was invalid - fall back to the segment before it
        if segment.seg_type == SEG_TYPE_AS_SET:
            candidates = {asn for asn in segment.asns if not is_asn_invalid(asn)}
            if candidates:
                return candidates
            continue
        raise MrtFormatError(
            f"unexpected AS_PATH segment type {segment.seg_type}: AS_CONFED "
            "segments should have been stripped before external advertisement"
        )
    return None


def extract_origin_as(attr_data: bytes, asn_width: int) -> int | set[int]:
    """Scans one RIB entry's raw path-attribute block and returns its origin AS.

    `asn_width` is 4 for TABLE_DUMP_V2 entries (always native 4-octet ASNs)
    and 2 for TABLE_DUMP (v1) entries. For the 4-octet case, AS_PATH already
    carries real ASNs throughout, so parsing stops as soon as it's found -
    the common case, and the fast path.

    For 2-octet entries, routers without 4-octet-ASN support replace
    out-of-range ASNs in AS_PATH with the placeholder AS_TRANS (23456);
    AS4_PATH (RFC 6793), when present, carries the true values for the tail
    of the path - exactly where the origin lives - so its origin takes
    precedence over AS_PATH's when both are present.
    """
    reader = ByteReader(attr_data)
    as_path_segments: list[PathSegment] | None = None
    as4_path_segments: list[PathSegment] | None = None
    want_as4 = asn_width == 2

    while len(reader):
        type_code, length = _read_attr_header(reader)
        value = reader.read(length)
        if type_code == ATTR_TYPE_AS_PATH:
            as_path_segments = _parse_path_segments(value, asn_width)
        elif want_as4 and type_code == ATTR_TYPE_AS4_PATH:
            as4_path_segments = _parse_path_segments(value, 4)

        have_as_path = as_path_segments is not None
        have_as4_if_wanted = not want_as4 or as4_path_segments is not None
        if have_as_path and have_as4_if_wanted:
            break

    origin = None
    if as4_path_segments:
        origin = _origin_from_segments(as4_path_segments)
    if origin is None and as_path_segments:
        origin = _origin_from_segments(as_path_segments)
    if origin is None:
        raise MrtFormatError("no usable AS_PATH/AS4_PATH origin in path attributes")
    return origin
