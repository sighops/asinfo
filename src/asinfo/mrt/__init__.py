"""asinfo.mrt - MRT/RIB BGP table-dump parsing (RFC 6396) and IP-ASN database export.


Public API:
    parse_mrt_file(mrt_file, on_progress=None, skip_record_on_error=False)
        -> {"prefix/len": origin_asn_or_set_of_asns}
    write_prefixes_to_file(prefixes, output_file_name, source_description="")
    write_prefixes_to_debug_file(prefixes, output_file_name, source_description="")
    open_archive(path) -> an open bz2/gzip file object
"""

from __future__ import annotations

from bz2 import BZ2File
from collections.abc import Callable
from gzip import GzipFile
from time import perf_counter
from typing import BinaryIO, cast

from .bgp_attrs import extract_origin_as
from .headers import MrtType
from .invalid import is_asn_invalid
from .reader import MrtFormatError
from .tabledump import RawTableEntry, SkippedRecord, iter_records

__all__ = [
    "MrtFormatError",
    "is_asn_invalid",
    "open_archive",
    "parse_mrt_file",
    "write_prefixes_to_file",
    "write_prefixes_to_debug_file",
]

ProgressCallback = Callable[[str], None]
_PROGRESS_INTERVAL = 100_000
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"\x42\x5a\x68"


def open_archive(path: str) -> BinaryIO:
    """Opens a bz2 or gzip MRT/RIB archive for reading, detected by magic number."""
    with open(path, "rb") as fh:
        magic = fh.read(max(len(_GZIP_MAGIC), len(_BZ2_MAGIC)))
    if magic.startswith(_BZ2_MAGIC):
        # BZ2File/GzipFile are structurally BinaryIO-compatible (read/seek/etc in
        # binary mode) but typeshed doesn't declare them as such nominally.
        return cast(BinaryIO, BZ2File(path, "rb"))
    if magic.startswith(_GZIP_MAGIC):
        return cast(BinaryIO, GzipFile(path, "rb"))
    raise MrtFormatError(f"cannot determine archive type of {path!r} (not bz2 or gzip)")


def parse_mrt_file(
    mrt_file: str | BinaryIO,
    *,
    on_progress: ProgressCallback | None = None,
    skip_record_on_error: bool = False,
    check_all_peers: bool = False,
) -> dict[str, int | set]:
    """Parses an MRT/RIB BGP table dump into {"prefix/len": origin_asn_or_set}.

    `mrt_file` may be a path to a .bz2/.gz archive, or an already-open binary
    file object. Both TABLE_DUMP (v1) and TABLE_DUMP_V2 are supported, IPv4
    and IPv6, 16- and 32-bit ASNs.

    If `skip_record_on_error` is True, a RIB entry whose path attributes
    don't yield a usable origin AS is skipped (with a warning via
    `on_progress`, if given) instead of aborting the whole parse.

    `check_all_peers` controls how many BGP peers' views of each prefix are
    decoded in TABLE_DUMP_V2 records. Default False only decodes the first
    peer entry per prefix - a real RIB can have dozens of peers per prefix,
    and decoding every one of them multiplies the AS_PATH-parsing work
    several times over. Pass True to decode every peer entry instead, which
    is needed for the MOAS-conflict count below to reflect true peer
    disagreement rather than just disagreement between separate MRT records
    for the same prefix.
    """
    if isinstance(mrt_file, str):
        mrt_file = open_archive(mrt_file)

    prefixes: dict[str, int | set] = {}
    started = perf_counter()
    n_entries = n_skipped = n_errors = n_moas_conflicts = 0

    for record in iter_records(mrt_file, check_all_peers=check_all_peers):
        if isinstance(record, SkippedRecord):
            n_skipped += 1
            if on_progress:
                on_progress(f"skipped {record.reason}")
            continue

        assert isinstance(record, RawTableEntry)
        try:
            origin = extract_origin_as(record.attr_data, record.asn_width)
        except MrtFormatError as exc:
            n_errors += 1
            if not skip_record_on_error:
                raise
            if on_progress:
                on_progress(f"WARNING: skipping {record.prefix}: {exc}")
            continue

        existing = prefixes.get(record.prefix)
        if existing is None:
            prefixes[record.prefix] = origin
        elif existing != origin:
            # TABLE_DUMP (v1) legitimately repeats a prefix once per peer that
            # announced it - that's normal, and we keep whichever was seen
            # first. TABLE_DUMP_V2 records a prefix once per MRT record with
            # one sub-entry per peer, so a disagreement there (MOAS - multiple
            # origin AS) is tallied and reported as a single summary count
            # rather than one line per conflict, since a full RIB dump can
            # legitimately have thousands of these.
            if record.header.type == MrtType.TABLE_DUMP_V2:
                n_moas_conflicts += 1

        n_entries += 1
        if on_progress and n_entries % _PROGRESS_INTERVAL == 0:
            on_progress(f"{n_entries} entries processed @{perf_counter() - started:.1f}s")

    prefixes.pop("0.0.0.0/0", None)  # default route - not meaningful in an ASN lookup table
    prefixes.pop("::/0", None)

    if on_progress:
        on_progress(
            f"done: {n_entries} entries, {n_skipped} skipped, {n_errors} errors, "
            f"{n_moas_conflicts} MOAS conflicts (repeated prefix, different origins - "
            f"first seen kept), {perf_counter() - started:.1f}s"
        )
    return prefixes


def write_prefixes_to_file(
    prefixes: dict,
    output_file_name: str,
    source_description: str = "",
) -> None:
    """Writes a {prefix: origin} mapping out in the IP-ASN32-DAT text format, which seems to
    be the most commonly used format by others.

    Ambiguous (AS_SET-derived) origins are collapsed to a single arbitrary
    member, since the format has no way to represent multiple ASNs for one
    prefix - see `write_prefixes_to_debug_file` if you need to inspect the
    full candidate set instead.
    """
    _write_prefixes(
        prefixes, output_file_name, source_description, preserve_ambiguous_origins=False
    )


def write_prefixes_to_debug_file(
    prefixes: dict,
    output_file_name: str,
    source_description: str = "",
) -> None:
    """Writes a {prefix: origin} mapping for inspection, preserving ambiguous
    (AS_SET-derived) origins as their full candidate set instead of
    collapsing them to one arbitrary member.

    The result is NOT valid IP-ASN32-DAT format - a line for an ambiguous
    prefix looks like "1.2.3.0/24\t{40179, 50923}", which `ASInfo` (and
    anything else expecting one ASN per line) can't parse. Use
    `write_prefixes_to_file` to produce a loadable database.
    """
    _write_prefixes(prefixes, output_file_name, source_description, preserve_ambiguous_origins=True)


def _write_prefixes(
    prefixes: dict,
    output_file_name: str,
    source_description: str,
    preserve_ambiguous_origins: bool,
) -> None:
    n_v6 = sum(1 for prefix in prefixes if ":" in prefix)
    n_v4 = len(prefixes) - n_v6
    with open(output_file_name, "w", encoding="ascii") as fh:
        fh.write("; IP-ASN32-DAT file\n")
        fh.write(f"; Original source: {source_description}\n")
        fh.write(f"; Prefixes-v4   : {n_v4}\n; Prefixes-v6   : {n_v6}\n;\n")
        for prefix, origin in prefixes.items():
            if isinstance(origin, set) and not preserve_ambiguous_origins:
                origin = next(iter(origin))  # ambiguous aggregate - any member is a legal choice
            fh.write(f"{prefix}\t{origin}\n")
