"""ipasn.mrt - MRT/RIB BGP table-dump parsing (RFC 6396) and IP-ASN database export.


Public API:
    parse_mrt_file(mrt_file, on_progress=None, skip_record_on_error=False)
        -> {"prefix/len": origin_asn_or_set_of_asns}
    dump_prefixes_to_file(prefixes, ipasn_file_name, source_description="", debug_write_sets=False)
    open_archive(path) -> an open bz2/gzip file object
"""

from __future__ import annotations

from bz2 import BZ2File
from gzip import GzipFile
from time import perf_counter
from typing import BinaryIO, Callable, Union

from .bgp_attrs import extract_origin_as
from .invalid import is_asn_invalid
from .headers import MrtType
from .reader import MrtFormatError
from .tabledump import RawTableEntry, SkippedRecord, iter_records

__all__ = [
    "MrtFormatError",
    "is_asn_invalid",
    "open_archive",
    "parse_mrt_file",
    "dump_prefixes_to_file",
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
        return BZ2File(path, "rb")
    if magic.startswith(_GZIP_MAGIC):
        return GzipFile(path, "rb")
    raise MrtFormatError(f"cannot determine archive type of {path!r} (not bz2 or gzip)")


def parse_mrt_file(
    mrt_file: str | BinaryIO,
    *,
    on_progress: ProgressCallback | None = None,
    skip_record_on_error: bool = False,
    check_all_peers: bool = False,
) -> dict[str, Union[int, set]]:
    """Parses an MRT/RIB BGP table dump into {"prefix/len": origin_asn_or_set}.

    `mrt_file` may be a path to a .bz2/.gz archive, or an already-open binary
    file object. Both TABLE_DUMP (v1) and TABLE_DUMP_V2 are supported, IPv4
    and IPv6, 16- and 32-bit ASNs.

    If `skip_record_on_error` is True, a RIB entry whose path attributes
    don't yield a usable origin AS is skipped (with a warning via
    `on_progress`, if given) instead of aborting the whole parse.

    `check_all_peers` controls how many BGP peers' views of each prefix are
    decoded in TABLE_DUMP_V2 records. Default False only decodes the first
    peer entry per prefix (matching pyasn's default and its speed - a real
    RIB can have dozens of peers per prefix, and decoding every one of them
    multiplies the AS_PATH-parsing work several times over). Pass True to
    decode every peer entry instead, which is needed for the MOAS-conflict
    count below to reflect true peer disagreement rather than just
    disagreement between separate MRT records for the same prefix.
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


def dump_prefixes_to_file(
    prefixes: dict,
    ipasn_file_name: str,
    source_description: str = "",
    debug_write_sets: bool = False,
) -> None:
    """Writes a {prefix: origin} mapping out in the IP-ASN32-DAT text format."""
    n_v6 = sum(1 for prefix in prefixes if ":" in prefix)
    n_v4 = len(prefixes) - n_v6
    with open(ipasn_file_name, "w", encoding="ascii") as fh:
        fh.write("; IP-ASN32-DAT file\n")
        fh.write(f"; Original source: {source_description}\n")
        fh.write(f"; Prefixes-v4   : {n_v4}\n; Prefixes-v6   : {n_v6}\n;\n")
        for prefix, origin in prefixes.items():
            if isinstance(origin, set) and not debug_write_sets:
                origin = next(iter(origin))  # ambiguous aggregate - any member is a legal choice
            fh.write(f"{prefix}\t{origin}\n")
