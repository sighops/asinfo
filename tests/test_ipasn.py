import os

import pytest

import ipasn
from ipasn import IpAsn

FAKE_IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "data/ipasn.fake")
IPASN_DB_PATH = os.path.join(os.path.dirname(__file__), "data/ipasn_20140513.dat.gz")
IPASN6_DB_PATH = os.path.join(os.path.dirname(__file__), "data/ipasn6_20151101.dat.gz")
AS_NAMES_FILE_PATH = os.path.join(os.path.dirname(__file__), "data/asnames.json")
AS_NAMES_COMPRESSED_FILE_PATH = os.path.join(os.path.dirname(__file__), "data/asnames.json.gz")


@pytest.fixture(scope="module")
def asndb():
    return IpAsn(IPASN_DB_PATH)


@pytest.fixture(scope="module")
def asndb_fake():
    return IpAsn(FAKE_IPASN_DB_PATH)


def test_correctness(asndb_fake):
    """IpAsn returns the correct AS number against a small hand-built database."""
    for i in range(4):
        asn, prefix = asndb_fake.lookup(f"1.0.0.{i}")
        assert asn == 1
        assert prefix == "1.0.0.0/30"
    for i in range(4, 256):
        asn, prefix = asndb_fake.lookup(f"1.0.0.{i}")
        assert asn == 2
        assert prefix == "1.0.0.0/24"
    for i in range(256):
        asn, prefix = asndb_fake.lookup(f"2.0.0.{i}")
        assert asn == 3
        assert prefix == "2.0.0.0/24"
    for i in range(128, 256):
        asn, prefix = asndb_fake.lookup(f"3.{i}.0.0")
        assert asn == 4
        assert prefix == "3.0.0.0/8"
    for i in range(0, 128):
        asn, prefix = asndb_fake.lookup(f"3.{i}.0.0")
        assert asn == 5
        assert prefix == "3.0.0.0/9"

    asn, prefix = asndb_fake.lookup("5.0.0.0")
    assert asn is None
    assert prefix is None


def test_as_number_convert_success():
    """Correct conversion between 32-bit and ASDOT number formats for ASNs."""
    assert IpAsn.convert_32bit_to_asdot(71234) == "AS1.5698"
    assert IpAsn.convert_32bit_to_asdot(131393) == "AS2.321"
    assert IpAsn.convert_32bit_to_asdot(4294901760) == "AS65535.0"
    assert IpAsn.convert_32bit_to_asdot(4294967295) == "AS65535.65535"
    assert IpAsn.convert_32bit_to_asdot(0) == "AS0"

    assert IpAsn.convert_asdot_to_32bit("AS1.0") == 65536
    assert IpAsn.convert_asdot_to_32bit("AS1.5698") == 71234
    assert IpAsn.convert_asdot_to_32bit("AS65535.65535") == 4294967295
    assert IpAsn.convert_asdot_to_32bit("AS0") == 0
    assert IpAsn.convert_asdot_to_32bit("AS2.321") == 131393


@pytest.mark.parametrize("bad_asdot", ["AS]2.321", "AS2..321", "AS2.", "AS.098"])
def test_as_number_convert_fail(bad_asdot):
    with pytest.raises(ValueError, match="is not a valid ASDOT string"):
        IpAsn.convert_asdot_to_32bit(bad_asdot)


def test_as_number_convert_out_of_range():
    # Each ASDOT component is a 16-bit field (RFC 5396) - 65536 doesn't fit.
    with pytest.raises(ValueError, match="component greater than 65535"):
        IpAsn.convert_asdot_to_32bit("AS1.65536")
    with pytest.raises(ValueError, match="component greater than 65535"):
        IpAsn.convert_asdot_to_32bit("AS65536.0")
    # A plain ASDOT number is still capped at the 32-bit AS number space.
    with pytest.raises(ValueError, match="out of range for a 32-bit AS number"):
        IpAsn.convert_asdot_to_32bit("AS4294967296")
    with pytest.raises(ValueError, match="out of range for a 32-bit AS number"):
        IpAsn.convert_32bit_to_asdot(4294967296)
    with pytest.raises(ValueError, match="out of range for a 32-bit AS number"):
        IpAsn.convert_32bit_to_asdot(-1)


def test_get_tud_prefixes(asndb):
    """Correct prefixes are returned for a predetermined AS."""
    prefixes1 = asndb.get_as_prefixes(1128)
    prefixes2 = asndb.get_as_prefixes(1128)
    prefixes3 = asndb.get_as_prefixes("1128")

    assert set(prefixes1) == {"130.161.0.0/16", "131.180.0.0/16", "145.94.0.0/16"}
    assert prefixes1 == prefixes2  # should cache, and hence return same
    assert prefixes1 == prefixes3  # string & int for asn should return the same


def test_get_prefixes2(asndb):
    """get_as_prefixes() on a border case (bug report #10).

    Why this border-case is interesting:
        $ cat ipasn_20141028.dat | grep 13289$
        82.212.192.0/18  13289
        $ cat ipasn_20141028.dat | grep 82.212.192.0
        82.212.192.0/18  13289
        82.212.192.0/19  29624
    """
    prefixes = asndb.get_as_prefixes(13289)
    assert set(prefixes) == {"82.212.192.0/18"}
    prefixes = asndb.get_as_prefixes(11018)
    assert set(prefixes) == {"216.69.64.0/19"}


def test_get_prefixes_unknown_asn(asndb):
    """get_as_prefixes()/get_as_prefixes_effective() return None (not an
    empty collection) for an ASN with no known prefixes."""
    assert asndb.get_as_prefixes(999999999) is None
    assert asndb.get_as_prefixes_effective(999999999) is None


def test_get_tud_effective_prefixes(asndb):
    prefixes1 = asndb.get_as_prefixes_effective(1128)  # TUDelft AS
    assert set(prefixes1) == {"130.161.0.0/16", "131.180.0.0/16", "145.94.0.0/16"}


def test_address_family(asndb):
    """IpAsn can determine correct and incorrect IPv4/IPv6 addresses (bug #14)."""
    # the following should not raise
    asndb.lookup("8.8.8.8")
    asndb.lookup("2001:500:88:200::8")

    # the following should raise
    with pytest.raises(ValueError):
        asndb.lookup("8.8.8.800")
    with pytest.raises(ValueError):
        asndb.lookup("2001:500g:88:200::8")


def test_ipv6():
    """IPv6 addresses are looked up correctly."""
    db = IpAsn(IPASN6_DB_PATH)
    known_ips = [
        # First three IPs suggested by sebix (bug #14). Confirmed AS on WHOIS.
        ("2001:41d0:2:7a6::1", 16276),   # OVH IPv6, AS16276
        ("2002:2d22:b585::2d22:b585", 6939),  # WHOIS: IPv4 endpoint (45.34.181.133) of
                                               # a 6to4 address. AS6939 = Hurricane Electric
        ("2a02:2770:11:0:21a:4aff:fef0:e779", 196752),  # TILAA, AS196752
        ("2607:f8b0:4006:80f::200e", 15169),  # GOOGLE AAAA
        ("d::d", None),  # random unused IPv6
    ]
    for ip, known_as in known_ips:
        asn, _prefix = db.lookup(ip)
        assert asn == known_as


def test_asnames():
    """AS Name lookup works."""
    db_with_names = IpAsn(IPASN_DB_PATH, as_names_file=AS_NAMES_FILE_PATH)
    asn, _prefix = db_with_names.lookup("8.8.8.8")
    name = db_with_names.get_as_name(asn)
    assert "google" in name.lower()

    assert db_with_names.get_as_name(-1) is None


def test_asnames_compressed():
    """AS Name lookup works from a gzip-compressed names file."""
    db_with_names = IpAsn(IPASN_DB_PATH, as_names_file=AS_NAMES_COMPRESSED_FILE_PATH)
    asn, _prefix = db_with_names.lookup("8.8.8.8")
    name = db_with_names.get_as_name(asn)
    assert "google" in name.lower()

    assert db_with_names.get_as_name(-1) is None


def test_find_asns_by_name():
    """Reverse (name -> ASN) lookup, case-insensitive substring match."""
    db_with_names = IpAsn(IPASN_DB_PATH, as_names_file=AS_NAMES_FILE_PATH)
    matches = db_with_names.find_asns_by_name("google")
    asn, _prefix = db_with_names.lookup("8.8.8.8")
    assert asn in dict(matches)
    assert all("google" in name.lower() for _asn, name in matches)


def test_find_asns_by_name_no_matches():
    db_with_names = IpAsn(IPASN_DB_PATH, as_names_file=AS_NAMES_FILE_PATH)
    assert db_with_names.find_asns_by_name("no-such-as-name-xyz") == []


def test_find_asns_by_name_without_as_names_raises(asndb):
    with pytest.raises(RuntimeError):
        asndb.find_asns_by_name("google")


def test_version_is_set():
    assert isinstance(ipasn.__version__, str)
    assert ipasn.__version__


def test_assize(asndb):
    """AS size calculation correctness."""
    assert sum(2 ** (32 - int(px.split("/")[1])) for px in []) == 0  # empty prefix list

    assert asndb.get_as_size(1133) == 65536    # Uni Twente AS, 1 /16 prefix. Manually checked.
    assert asndb.get_as_size(1128) == 196608   # TU-Delft AS, 3 non-overlapping /16s. RIPE stat.
    assert asndb.get_as_size(1124) == 163840   # UVA AS, 3 non-overlapping prefixes (2 /16, 1 /17).


def test_load_from_string():
    """IpAsn can load a database from an in-memory string (ipasn_string),
    not just a file path, and behaves identically either way."""
    with open(FAKE_IPASN_DB_PATH) as f:
        db_text = f.read()
    db = IpAsn(ipasn_string=db_text)
    assert db.lookup("1.0.0.1") == (1, "1.0.0.0/30")
    assert db.lookup("2.0.0.1") == (3, "2.0.0.0/24")
    assert db.lookup("5.0.0.0") == (None, None)


def test_constructor_requires_a_data_source():
    with pytest.raises(ValueError):
        IpAsn()


def test_iteration_yields_prefix_asn_pairs(asndb_fake):
    """Iterating an IpAsn yields (prefix, asn) pairs covering every loaded
    prefix - not just prefix strings - so the whole database can be
    walked/exported without a separate lookup per prefix."""
    pairs = dict(asndb_fake)
    assert pairs == {
        "1.0.0.0/30": 1,
        "1.0.0.0/24": 2,
        "2.0.0.0/24": 3,
        "3.0.0.0/8": 4,
        "3.0.0.0/9": 5,
    }
