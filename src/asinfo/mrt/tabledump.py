"""TABLE_DUMP (RFC 6396 §4.1) and TABLE_DUMP_V2 (§4.3) record parsing.

Reads directly from a file-like object, one MRT record at a time - the only
thing ever fully materialized in memory is a single record's body (a few
bytes to a few KB), never the whole archive.

Each TABLE_DUMP record and each RIB entry within a TABLE_DUMP_V2 record
becomes a RawTableEntry: a prefix plus its still-undecoded BGP path-attribute
bytes. Decoding those attributes into an origin AS is bgp_attrs.py's job -
this module only knows MRT/RIB framing, not BGP attribute internals.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from typing import BinaryIO

from .headers import MrtHeader, MrtType, TableDumpSubtype, TableDumpV2Subtype, read_header
from .reader import ByteReader, MrtFormatError


@dataclass(frozen=True, slots=True)
class RawTableEntry:
    header: MrtHeader
    prefix: str
    attr_data: bytes
    asn_width: int  # 2 for TABLE_DUMP (v1), 4 for TABLE_DUMP_V2


@dataclass(frozen=True, slots=True)
class SkippedRecord:
    header: MrtHeader
    reason: str


Record = RawTableEntry | SkippedRecord

_MULTICAST_AND_GENERIC_SUBTYPES = {
    TableDumpV2Subtype.RIB_IPV4_MULTICAST,
    TableDumpV2Subtype.RIB_IPV6_MULTICAST,
    TableDumpV2Subtype.RIB_GENERIC,
}


def iter_records(stream: BinaryIO, *, check_all_peers: bool = False) -> Iterator[Record]:
    """Yields one Record per MRT record (TABLE_DUMP_V2 RIB records, which can
    bundle one RIB entry per peer for the same prefix, yield multiple
    RawTableEntry in a row - all sharing that prefix).

    `check_all_peers` controls how many of a TABLE_DUMP_V2 record's peer
    entries are yielded: by default only the first - real RIBs can have
    dozens of peers per prefix, and decoding all of them multiplies the
    AS_PATH-parsing work several times over for no benefit beyond
    MOAS-conflict detection. Pass True to yield every peer entry instead,
    at that cost.

    A mid-stream decompression EOFError (raised by bz2/gzip when the
    underlying archive is truncated - e.g. a download that got cut short) is
    treated the same as a clean end-of-file: parsing stops with whatever was
    successfully read rather than aborting the whole conversion.
    """
    while True:
        try:
            header = read_header(stream)
        except EOFError:
            return
        if header is None:
            return

        try:
            raw_body = stream.read(header.length)
        except EOFError:
            return
        if len(raw_body) < header.length:
            raise MrtFormatError(
                f"truncated MRT record body: got {len(raw_body)} of {header.length} declared bytes"
            )
        body = ByteReader(raw_body)

        if header.type == MrtType.TABLE_DUMP:
            yield _parse_table_dump_v1(header, body)
        elif header.type == MrtType.TABLE_DUMP_V2:
            yield from _iter_table_dump_v2(header, body, check_all_peers=check_all_peers)
        else:
            yield SkippedRecord(header, f"unsupported MRT record type {header.type}")


def _format_prefix(addr_bytes: bytes, prefix_len: int) -> str:
    addr_int = int.from_bytes(addr_bytes, "big")
    network_cls = IPv4Network if len(addr_bytes) == 4 else IPv6Network
    return str(network_cls((addr_int, prefix_len), strict=False))


def _parse_table_dump_v1(header: MrtHeader, body: ByteReader) -> RawTableEntry:
    if header.subtype not in (TableDumpSubtype.AFI_IPV4, TableDumpSubtype.AFI_IPV6):
        raise MrtFormatError(f"unsupported TABLE_DUMP subtype {header.subtype}")
    addr_octets = 4 if header.subtype == TableDumpSubtype.AFI_IPV4 else 16

    body.read_u16()  # view number - unused (multi-RIB-view support, rarely non-zero)
    body.read_u16()  # sequence number - informational only
    prefix_bytes = body.read(addr_octets)
    prefix_len = body.read_u8()
    status = body.read_u8()
    if status != 1:
        raise MrtFormatError(f"TABLE_DUMP status octet must be 1, got {status}")
    body.read_u32()  # originated time - unused
    body.read(addr_octets)  # peer IP - unused for origin extraction
    body.read_u16()  # peer AS - unused (the real path is in the attributes)
    attr_len = body.read_u16()
    attr_data = body.read(attr_len)

    prefix = _format_prefix(prefix_bytes, prefix_len)
    return RawTableEntry(header=header, prefix=prefix, attr_data=attr_data, asn_width=2)


def _iter_table_dump_v2(
    header: MrtHeader, body: ByteReader, *, check_all_peers: bool = False
) -> Iterator[Record]:
    if header.subtype == TableDumpV2Subtype.PEER_INDEX_TABLE:
        # Maps peer-index -> peer IP/AS for the RIB records that follow; not
        # needed to extract a prefix's origin AS from its own attributes.
        yield SkippedRecord(header, "PEER_INDEX_TABLE")
        return

    if header.subtype in _MULTICAST_AND_GENERIC_SUBTYPES:
        yield SkippedRecord(header, f"TABLE_DUMP_V2 subtype {header.subtype} not supported")
        return

    if header.subtype not in (
        TableDumpV2Subtype.RIB_IPV4_UNICAST,
        TableDumpV2Subtype.RIB_IPV6_UNICAST,
    ):
        yield SkippedRecord(header, f"unknown TABLE_DUMP_V2 subtype {header.subtype}")
        return

    addr_octets = 4 if header.subtype == TableDumpV2Subtype.RIB_IPV4_UNICAST else 16

    body.read_u32()  # sequence number - unused
    prefix_len = body.read_u8()
    prefix_octets = (prefix_len + 7) // 8
    prefix_bytes = body.read(prefix_octets) + bytes(addr_octets - prefix_octets)
    prefix = _format_prefix(prefix_bytes, prefix_len)

    entry_count = body.read_u16()
    for _ in range(entry_count):
        body.read_u16()  # peer index - unused
        body.read_u32()  # originated time - unused
        attr_len = body.read_u16()
        attr_data = body.read(attr_len)
        yield RawTableEntry(header=header, prefix=prefix, attr_data=attr_data, asn_width=4)
        if not check_all_peers:
            break  # remaining peer entries are never read - only the first, by far the common case
