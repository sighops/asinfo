import gzip
import json
from importlib.metadata import PackageNotFoundError, version
from ipaddress import collapse_addresses, ip_network

import pytricia

try:
    __version__ = version("asinfo")
except PackageNotFoundError:
    __version__ = "unknown"


class ASInfo:
    """IPv4/IPv6 to ASN lookup table, built from a BGP MRT/RIB-derived IP-ASN database."""

    def __init__(self, db_file=None, as_names_file=None, db_string=None):
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
        self.records = pytricia.PyTricia()
        self.as_prefixes = {}
        self.db_file = db_file
        self.asnames_file = as_names_file
        self.asnames = None

        if db_file is not None:
            opener = gzip.open if db_file.endswith(".gz") else open
            with opener(db_file, "rt") as f:
                for line in f:
                    self.process_load_line(line)
        elif db_string is not None:
            for line in db_string.splitlines():
                self.process_load_line(line)
        else:
            raise ValueError("No data given: pass either db_file or db_string.")

        self.asnames = self.load_asnames() if as_names_file else None

        # pytricia requires the trie be frozen against further modification
        # before it can be pickled.
        self.records.freeze()

    def process_load_line(self, line):
        line = line.strip()
        if not line or line[0] in ("#", ";"):
            return
        prefix, asn = line.split()
        asn = int(asn)
        self.records[prefix] = asn
        self.as_prefixes.setdefault(asn, set()).add(prefix)

    def load_asnames(self):
        """Loads {ASN: name} from `self.asnames_file` (JSON, optionally gzip-compressed)."""
        if self.asnames_file.endswith(".gz"):
            with gzip.open(self.asnames_file, "rt") as f:
                names = json.load(f)
        else:
            with open(self.asnames_file, "r", encoding="utf-8") as f:
                names = json.load(f)

        try:
            return {int(asn): name for asn, name in names.items()}
        except ValueError:
            raise ValueError("AS names file contains a non-numeric ASN") from None

    def lookup(self, ip):
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

    def get_as_prefixes(self, asn):
        """Returns the set of prefixes originated by `asn` in this database,
        or None if the ASN isn't present."""
        return self.as_prefixes.get(int(asn))

    def get_as_prefixes_collapsed(self, asn):
        """
        Returns the effective address space of the given ASN by removing all
        overlaps among its prefixes, or None if the ASN isn't present.
        """
        prefixes = self.get_as_prefixes(asn)
        if not prefixes:
            return None
        non_overlapping_4 = collapse_addresses([ip_network(p) for p in prefixes if ":" not in p])
        non_overlapping_6 = collapse_addresses([ip_network(p) for p in prefixes if ":" in p])
        return [p.compressed for p in non_overlapping_4] + [p.compressed for p in non_overlapping_6]

    def _get_as_size(self, asn, bits, is_v6):
        prefixes = self.get_as_prefixes_collapsed(asn)
        if not prefixes:
            return 0
        return sum(
            2 ** (bits - int(prefix.split("/")[1]))
            for prefix in prefixes
            if (":" in prefix) == is_v6
        )

    def get_as_size(self, asn):
        """Returns the total count of unique IPv4 addresses routed by `asn`."""
        return self._get_as_size(asn, 32, is_v6=False)

    def get_as_size_v6(self, asn):
        """Returns the total count of unique IPv6 addresses routed by `asn`."""
        return self._get_as_size(asn, 128, is_v6=True)

    def get_as_name(self, asn):
        """Returns the AS name for `asn`, or None if unknown.

        :raises RuntimeError: if this ASInfo was created without as_names_file.
        """
        if not self.asnames:
            raise RuntimeError("AS names were not loaded (pass as_names_file to __init__)")
        return self.asnames.get(asn, None)

    def find_asns_by_name(self, name_query):
        """Returns [(asn, name), ...] for every AS name containing
        `name_query` (case-insensitive substring match).

        :raises RuntimeError: if this ASInfo was created without as_names_file.
        """
        if not self.asnames:
            raise RuntimeError("AS names were not loaded (pass as_names_file to __init__)")
        query = name_query.lower()
        return [(asn, name) for asn, name in self.asnames.items() if query in name.lower()]

    def __repr__(self):
        return f"ASInfo({self.db_file!r}, {self.asnames_file!r})"

    def __iter__(self):
        for prefix in self.records:
            yield prefix, self.records[prefix]
