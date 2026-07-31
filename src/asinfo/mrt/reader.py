"""Minimal big-endian byte cursor over an in-memory buffer.

Deliberately has no MRT/BGP-specific knowledge - it exists so the format
modules (headers.py, tabledump.py, bgp_attrs.py) can be written declaratively
against RFC field layouts (read_u8, read_u16, read(n)) instead of manual
slice/unpack arithmetic.
"""

from __future__ import annotations


class MrtFormatError(ValueError):
    """Raised when MRT/BGP binary data doesn't match its expected structure."""


class ByteReader:
    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes, offset: int = 0) -> None:
        self._data = data
        self._offset = offset

    def __len__(self) -> int:
        """Bytes remaining to be read."""
        return len(self._data) - self._offset

    @property
    def offset(self) -> int:
        return self._offset

    def read(self, n: int) -> bytes:
        if n < 0 or self._offset + n > len(self._data):
            raise MrtFormatError(
                f"unexpected end of data: wanted {n} byte(s), {len(self)} remaining"
            )
        chunk = self._data[self._offset : self._offset + n]
        self._offset += n
        return chunk

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_u16(self) -> int:
        return int.from_bytes(self.read(2), "big")

    def read_u32(self) -> int:
        return int.from_bytes(self.read(4), "big")
