from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from importlib.metadata import PackageNotFoundError, version
from ipaddress import IPv4Network, IPv6Network, collapse_addresses
from typing import TypedDict

import pytricia

try:
    __version__ = version("asinfo")
except PackageNotFoundError:
    __version__ = "unknown"


class PrefixSummary(TypedDict):
    announced: list[str] | None
    collapsed: list[str] | None


class ASSummary(TypedDict):
    asn: int
    as_name: str | None
    description: str | None
    as_country: str | None
    count_addresses: int | None
    prefixes: PrefixSummary


class ASInfo:
    """IPv4/IPv6 to ASN lookup table, built from a BGP MRT/RIB-derived IP-ASN database."""

    def __init__(
        self,
        db_file: str | None = None,
        as_names_file: str | None = None,
        db_string: str | None = None,
    ) -> None:
        """
        Loads an IP-ASN database and prepares it for lookups.

        Provide exactly one data source: `db_file` (a path to a database
        file, optionally gzip-compressed) or `db_string` (the database
        contents already in memory). Format is a text file with lines of
        "NETWORK/BITS<tab>ASN".  See the `asinfo` CLI for building one
        from a BGP MRT/RIB dump.

        `as_names_file`, if given, additionally loads AS names (ASN -> name)
        from a JSON file for use with get_as_name().
        """
        self.records: pytricia.PyTricia = pytricia.PyTricia()
        self.as_prefixes: dict[int, set[str]] = {}
        self.db_file = db_file
        self.asnames_file = as_names_file
        self.asnames: dict[int, str] | None = None

        if db_file is not None:
            opener = gzip.open if db_file.endswith(".gz") else open
            with opener(db_file, "rt") as f:
                for line in f:
                    self._parse_and_index_line(line)
        elif db_string is not None:
            for line in db_string.splitlines():
                self._parse_and_index_line(line)
        else:
            raise ValueError("No data given: pass either db_file or db_string.")

        self.asnames = self.load_asnames() if as_names_file else None

        # pytricia requires the trie be frozen against further modification
        # before it can be pickled.
        self.records.freeze()

    def _parse_and_index_line(self, line: str) -> None:
        line = line.strip()
        if not line or line[0] in ("#", ";"):
            return
        prefix, asn_str = line.split()
        asn = int(asn_str)
        self.records[prefix] = asn
        self.as_prefixes.setdefault(asn, set()).add(prefix)

    def load_asnames(self) -> dict[int, str]:
        """Loads {ASN: name} from `self.asnames_file` (JSON, optionally gzip-compressed)."""
        assert self.asnames_file is not None  # only called when as_names_file was given
        if self.asnames_file.endswith(".gz"):
            with gzip.open(self.asnames_file, "rt") as f:
                names = json.load(f)
        else:
            with open(self.asnames_file, encoding="utf-8") as f:
                names = json.load(f)

        try:
            return {int(asn): name for asn, name in names.items()}
        except ValueError:
            raise ValueError("AS names file contains a non-numeric ASN") from None

    def get_asn_prefix_from_ip(self, ip: str) -> tuple[int, str] | tuple[None, None]:
        """
        Returns the AS number and best-matching prefix for the given IP address.

        :param ip: string representation of an IPv4 or IPv6 address, e.g. "8.8.8.8".
        :raises ValueError: if `ip` isn't a valid IP address.
        :return: (asn, prefix) - the 32-bit origin AS number and the best-matching
            BGP prefix for `ip`, or (None, None) if `ip` isn't covered by any
            prefix in this database.
        """
        try:
            asn = self.records[ip]
            prefix = self.records.get_key(ip)
            return asn, prefix
        except KeyError:
            return None, None

    def get_as_prefixes(self, asn: int | str) -> set[str] | None:
        """Returns the set of prefixes originated by `asn` in this database,
        or None if the ASN isn't present."""
        return self.as_prefixes.get(int(asn))

    def get_as_prefixes_collapsed(self, asn: int | str) -> list[str] | None:
        """
        Returns the effective address space of the given ASN by removing all
        overlaps among its prefixes, or None if the ASN isn't present.
        """
        prefixes = self.get_as_prefixes(asn)
        if not prefixes:
            return None
        non_overlapping_4 = collapse_addresses([IPv4Network(p) for p in prefixes if ":" not in p])
        non_overlapping_6 = collapse_addresses([IPv6Network(p) for p in prefixes if ":" in p])
        return [p.compressed for p in non_overlapping_4] + [p.compressed for p in non_overlapping_6]

    def _get_as_size(self, asn: int | str, bits: int, is_v6: bool) -> int:
        prefixes = self.get_as_prefixes_collapsed(asn)
        if not prefixes:
            return 0
        return sum(
            2 ** (bits - int(prefix.split("/")[1]))
            for prefix in prefixes
            if (":" in prefix) == is_v6
        )

    def get_as_size(self, asn: int | str) -> int:
        """Returns the total count of unique IPv4 addresses routed by `asn`."""
        return self._get_as_size(asn, 32, is_v6=False)

    def get_as_size_v6(self, asn: int | str) -> int:
        """Returns the total count of unique IPv6 addresses routed by `asn`."""
        return self._get_as_size(asn, 128, is_v6=True)

    def get_as_name(self, asn: int) -> str | None:
        """Returns the AS name for `asn`, or None if unknown.

        :raises RuntimeError: if this ASInfo was created without as_names_file.
        """
        if not self.asnames:
            raise RuntimeError("AS names were not loaded (pass as_names_file to __init__)")
        return self.asnames.get(asn, None)

    def find_asns_by_name(self, name_query: str) -> list[tuple[int, str]]:
        """Returns [(asn, name), ...] for every AS name containing
        `name_query` (case-insensitive substring match).

        :raises RuntimeError: if this ASInfo was created without as_names_file.
        """
        if not self.asnames:
            raise RuntimeError("AS names were not loaded (pass as_names_file to __init__)")
        query = name_query.lower()
        return [(asn, name) for asn, name in self.asnames.items() if query in name.lower()]

    @staticmethod
    def _parse_as_name(raw_name: str) -> tuple[str, str | None, str | None]:
        """Splits a raw AS-name string ("<as-name> - <description>, <CC>")
        into (as_name, description, country).

        `as_name` is the short RPSL-style handle (RFC 2622/4012's `as-name`
        attribute syntax) - everything up to the *first* " - ". This must be
        a first-occurrence split, not last: ~1.5% of real entries contain
        " - " more than once (e.g. "NORTHROP-AS - Northrop Grumman
        Corporation - Automation Sciences Laboratory, US"), and the extra
        occurrences are part of the description, not additional structure.
        `country` is the segment after the *last* comma (verified against
        every entry in a real AS-names dataset: always present when there's
        a comma at all, and always exactly 2 characters).

        Any part not present in `raw_name` (e.g. this project's own
        synthetic test fixtures, which have neither a " - " nor a country)
        comes back None - except `as_name`, which falls back to the whole
        (trimmed) string when there's nothing to split on.
        """
        name_and_description = raw_name
        country = None
        if "," in raw_name:
            name_and_description, country = raw_name.rsplit(",", 1)
            name_and_description = name_and_description.strip()
            country = country.strip()

        if " - " in name_and_description:
            as_name, description = name_and_description.split(" - ", 1)
            return as_name.strip(), description.strip(), country
        return name_and_description, None, country

    def get_as_summary(self, asn: int | str) -> ASSummary:
        """Returns a structured summary of everything known about `asn`:
        name/country (if AS names were loaded and this ASN has one), address
        count, and both the full and collapsed prefix lists.

        An ASN known via only one data source (e.g. it has a registered name
        but currently announces no prefixes, or vice versa) isn't an error -
        the fields with no data come back None rather than 0/empty.

        :raises ValueError: if `asn` has neither announced prefixes nor a
            name entry - i.e. this database has no data on it at all.
        """
        asn = int(asn)
        prefixes = self.get_as_prefixes(asn)
        has_name_entry = self.asnames is not None and asn in self.asnames

        if prefixes is None and not has_name_entry:
            raise ValueError(f"AS{asn} is not present in this database")

        as_name = description = as_country = None
        if self.asnames is not None:
            raw_name = self.asnames.get(asn)
            if raw_name is not None:
                as_name, description, as_country = self._parse_as_name(raw_name)

        if prefixes is None:
            count_addresses = None
            announced = None
            collapsed = None
        else:
            count_addresses = self.get_as_size(asn)
            announced = sorted(prefixes)
            collapsed = self.get_as_prefixes_collapsed(asn)

        return {
            "asn": asn,
            "as_name": as_name,
            "description": description,
            "as_country": as_country,
            "count_addresses": count_addresses,
            "prefixes": {"announced": announced, "collapsed": collapsed},
        }

    def __repr__(self) -> str:
        return f"ASInfo({self.db_file!r}, {self.asnames_file!r})"

    def __iter__(self) -> Iterator[tuple[str, int]]:
        for prefix in self.records:
            yield prefix, self.records[prefix]
