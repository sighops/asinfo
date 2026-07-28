import gzip
import json
import re
from ipaddress import collapse_addresses, ip_network

import pytricia

_ASDOT_PATTERN = re.compile(r"^AS(?P<high>\d+)(?:\.(?P<low>\d+))?\Z", re.IGNORECASE)
_UINT16_MAX = 0xFFFF
_UINT32_MAX = 0xFFFFFFFF


class IpAsn:
    """IPv4/IPv6 to ASN lookup table, built from a BGP MRT/RIB-derived IP-ASN database."""

    def __init__(self, ipasn_file=None, as_names_file=None, ipasn_string=None):
        """
        Loads an IP-ASN database and prepares it for lookups.

        Provide exactly one data source: `ipasn_file` (a path to a database
        file, optionally gzip-compressed) or `ipasn_string` (the database
        contents already in memory). Format is a text file with lines of 
        "NETWORK/BITS<tab>ASN".  See the ipasn-utils scripts for building one 
        from a BGP MRT/RIB dump.

        `as_names_file`, if given, additionally loads AS names (ASN -> name)
        from a JSON file for use with get_as_name().
        """
        self.records = pytricia.PyTricia()
        self.as_prefixes = {}
        self.ipasndb_file = ipasn_file
        self.asnames_file = as_names_file
        self.asnames = None

        if ipasn_file is not None:
            opener = gzip.open if ipasn_file.endswith(".gz") else open
            with opener(ipasn_file, "rt") as f:
                for line in f:
                    self.process_load_line(line)
        elif ipasn_string is not None:
            for line in ipasn_string.splitlines():
                self.process_load_line(line)
        else:
            raise ValueError("No data given: pass either ipasn_file or ipasn_string.")

        self.asnames = self.read_asnames() if as_names_file else None

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

    def read_asnames(self):
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

    def get_as_prefixes_effective(self, asn):
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
        prefixes = self.get_as_prefixes_effective(asn)
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

        :raises RuntimeError: if this IpAsn was created without as_names_file.
        """
        if not self.asnames:
            raise RuntimeError("AS names were not loaded (pass as_names_file to __init__)")
        return self.asnames.get(asn, None)

    def __repr__(self):
        return f"IpAsn({self.ipasndb_file!r}, {self.asnames_file!r})"

    def __iter__(self):
        for prefix in self.records:
            yield prefix, self.records[prefix]

    @staticmethod
    def convert_32bit_to_asdot(asn):
        """Formats a 32-bit AS number in ASDOT notation (RFC 5396):
        "AS<high>.<low>" for AS numbers above 65535, or plain "AS<number>"
        otherwise."""
        if not 0 <= asn <= _UINT32_MAX:
            raise ValueError(f"{asn} is out of range for a 32-bit AS number")
        high, low = divmod(asn, 2**16)
        return f"AS{low}" if high == 0 else f"AS{high}.{low}"

    @staticmethod
    def convert_asdot_to_32bit(asdot):
        """Parses an ASDOT-notation AS number (RFC 5396) - either "AS<number>"
        or "AS<high>.<low>", where <high> and <low> are each a 16-bit
        component (0-65535) - into its plain 32-bit integer form."""
        match = _ASDOT_PATTERN.match(asdot)
        if not match:
            raise ValueError(
                f"{asdot!r} is not a valid ASDOT string; expected AS<number> or AS<high>.<low>"
            )
        high, low = match.group("high"), match.group("low")
        if low is None:
            asn = int(high)
            if asn > _UINT32_MAX:
                raise ValueError(f"{asdot!r} is out of range for a 32-bit AS number")
            return asn
        high, low = int(high), int(low)
        if high > _UINT16_MAX or low > _UINT16_MAX:
            raise ValueError(f"{asdot!r} has a component greater than {_UINT16_MAX}")
        return (high << 16) | low
