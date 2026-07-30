"""RFC 6396 §3 - the MRT common header, and the record/subrecord type codes
this parser understands.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import BinaryIO

from .reader import MrtFormatError

HEADER_LEN = 12  # timestamp(4) + type(2) + subtype(2) + length(4)
_HEADER_STRUCT = struct.Struct(">IHHI")


class MrtType(IntEnum):
    TABLE_DUMP = 12
    TABLE_DUMP_V2 = 13


class TableDumpSubtype(IntEnum):
    AFI_IPV4 = 1
    AFI_IPV6 = 2


class TableDumpV2Subtype(IntEnum):
    PEER_INDEX_TABLE = 1
    RIB_IPV4_UNICAST = 2
    RIB_IPV4_MULTICAST = 3
    RIB_IPV6_UNICAST = 4
    RIB_IPV6_MULTICAST = 5
    RIB_GENERIC = 6


@dataclass(frozen=True, slots=True)
class MrtHeader:
    timestamp: int
    type: int
    subtype: int
    length: int


def read_header(stream: BinaryIO) -> MrtHeader | None:
    """Reads one MRT common header directly from `stream`.

    Returns None on a clean EOF (no bytes left to read). Raises
    MrtFormatError if the stream ends partway through a header.
    """
    raw = stream.read(HEADER_LEN)
    if not raw:
        return None
    if len(raw) < HEADER_LEN:
        raise MrtFormatError(
            f"truncated MRT header: got {len(raw)} of {HEADER_LEN} bytes"
        )
    timestamp, type_, subtype, length = _HEADER_STRUCT.unpack(raw)
    return MrtHeader(timestamp, type_, subtype, length)
