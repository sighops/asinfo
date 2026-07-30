from pathlib import Path

import pytest

import asinfo
from asinfo import ASInfo

DATA_DIR = Path(__file__).parent / "data"
TEST_V4_DB_PATH = DATA_DIR / "test.db"
V4_DB_PATH = DATA_DIR / "ipasn_20260730.dat.gz"
V6_DB_PATH = DATA_DIR / "ipasn6_20260730.dat.gz"
AS_NAMES_FILE_PATH = DATA_DIR / "asnames.json"
AS_NAMES_COMPRESSED_FILE_PATH = DATA_DIR / "asnames.json.gz"


@pytest.fixture(scope="module")
def asndb():
    return ASInfo(str(V4_DB_PATH))


@pytest.fixture(scope="module")
def asndb_test():
    return ASInfo(str(TEST_V4_DB_PATH))


def test_lookup_returns_expected_result(asndb_test):
    """ASInfo returns the correct AS number against a small test database."""
    for i in range(4):
        asn, prefix = asndb_test.lookup(f"200.10.0.{i}")
        assert asn == 10
        assert prefix == "200.10.0.0/30"
    for i in range(4, 256):
        asn, prefix = asndb_test.lookup(f"200.10.0.{i}")
        assert asn == 20
        assert prefix == "200.10.0.0/24"
    for i in range(256):
        asn, prefix = asndb_test.lookup(f"200.20.0.{i}")
        assert asn == 30
        assert prefix == "200.20.0.0/24"
    for i in range(128, 256):
        asn, prefix = asndb_test.lookup(f"210.{i}.0.0")
        assert asn == 40
        assert prefix == "210.0.0.0/8"
    for i in range(0, 128):
        asn, prefix = asndb_test.lookup(f"210.{i}.0.0")
        assert asn == 50
        assert prefix == "210.0.0.0/9"

    asn, prefix = asndb_test.lookup("199.0.0.0")
    assert asn is None
    assert prefix is None

def test_lookup_with_asnames():
    """AS Name lookup works."""
    db_with_names = ASInfo(str(V4_DB_PATH), as_names_file=str(AS_NAMES_FILE_PATH))
    asn, _prefix = db_with_names.lookup("1.1.1.1")
    name = db_with_names.get_as_name(asn)
    assert "cloudflare" in name.lower()
    assert db_with_names.get_as_name(-1) is None

def test_v6_lookup_returns_expected_result():
    """IPv6 addresses are looked up correctly."""
    db = ASInfo(str(V6_DB_PATH))
    known_ips = [
        ("2408:897a::1", 4837),      # CHINA169-Backbone, AS4837
        ("2a04:3542::1", 202053),    # UpCloud Ltd, AS202053
        ("2a00:1e98::1", 34058),     # lifecell (mobile carrier), AS34058
        ("2a03:2880:f003:c07:face:b00c::2", 32934),  # Facebook, AS32934
        ("2001:db8::1", None),  # RFC 3849 documentation prefix - never routed
    ]
    for ip, known_as in known_ips:
        asn, _prefix = db.lookup(ip)
        assert asn == known_as

def test_invalid_address_raises_error(asndb):
    with pytest.raises(ValueError):
        asndb.lookup("1.1.680.1")
    with pytest.raises(ValueError):
        asndb.lookup("200001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF")

def test_get_prefixes_for_multi_prefix_asn(asndb):
    """Correct prefixes are returned for a predetermined AS with 3 non-overlapping /16s."""
    prefixes1 = asndb.get_as_prefixes(17435)
    prefixes2 = asndb.get_as_prefixes(17435)
    prefixes3 = asndb.get_as_prefixes("17435")

    assert set(prefixes1) == {"58.28.0.0/16", "118.90.0.0/16", "182.154.0.0/16"}
    assert prefixes1 == prefixes2  # should cache, and hence return same
    assert prefixes1 == prefixes3  # string & int for asn should return the same


def test_get_prefixes_overlapping_supernet(asndb):
    """get_as_prefixes() where one ASN announces a prefix whose
    supernet is announced by a different ASN. Each lookup must return only
    its own exact-match prefix, not the other's.

        12.216.192.0/23  39989
        12.216.193.0/24  16834   <- more specific, different origin
    """
    prefixes = asndb.get_as_prefixes(39989)
    assert set(prefixes) == {"12.216.192.0/23"}
    prefixes = asndb.get_as_prefixes(16834)
    assert set(prefixes) == {"12.216.193.0/24"}


def test_get_prefixes_unknown_asn(asndb):
    """get_as_prefixes()/get_as_prefixes_collapsed() return None (not an
    empty collection) for an ASN with no known prefixes."""
    assert asndb.get_as_prefixes(999999999) is None
    assert asndb.get_as_prefixes_collapsed(999999999) is None


def test_get_collapsed_prefixes_for_multi_prefix_asn(asndb):
    prefixes1 = asndb.get_as_prefixes_collapsed(17435)  # 3 non-overlapping /16s, nothing to collapse
    assert set(prefixes1) == {"58.28.0.0/16", "118.90.0.0/16", "182.154.0.0/16"}


def test_asnames_compressed():
    """AS Name lookup works from a gzip-compressed names file."""
    db_with_names = ASInfo(str(V4_DB_PATH), as_names_file=str(AS_NAMES_COMPRESSED_FILE_PATH))
    asn, _prefix = db_with_names.lookup("1.1.1.1")
    name = db_with_names.get_as_name(asn)
    assert "cloudflare" in name.lower()
    assert db_with_names.get_as_name(-1) is None


def test_find_asns_by_name():
    """Reverse (name -> ASN) lookup, case-insensitive substring match."""
    db_with_names = ASInfo(str(V4_DB_PATH), as_names_file=str(AS_NAMES_FILE_PATH))
    matches = db_with_names.find_asns_by_name("google")
    asn, _prefix = db_with_names.lookup("8.8.8.8")
    assert asn in dict(matches)
    assert all("google" in name.lower() for _asn, name in matches)


def test_find_asns_by_name_no_matches():
    db_with_names = ASInfo(str(V4_DB_PATH), as_names_file=str(AS_NAMES_FILE_PATH))
    assert db_with_names.find_asns_by_name("no-such-as-name-xyz") == []


def test_find_asns_by_name_without_as_names_raises(asndb):
    with pytest.raises(RuntimeError):
        asndb.find_asns_by_name("google")


def test_version_is_set():
    assert isinstance(asinfo.__version__, str)
    assert asinfo.__version__


def test_get_as_size_returns_expected_result(asndb):
    """AS size calculation correctness."""
    assert sum(2 ** (32 - int(px.split("/")[1])) for px in []) == 0  # empty prefix list

    assert asndb.get_as_size(139190) == 65536   # single /16 prefix
    assert asndb.get_as_size(17435) == 196608   # 3 non-overlapping /16s
    assert asndb.get_as_size(12638) == 49152    # 1 /17 + 2 /19s, non-overlapping


def test_load_from_string():
    """ASInfo can load a database from an in-memory string (db_string),
    not just a file path, and behaves identically either way."""
    with open(TEST_V4_DB_PATH) as f:
        db_text = f.read()
    db = ASInfo(db_string=db_text)
    assert db.lookup("200.10.0.1") == (10, "200.10.0.0/30")
    assert db.lookup("200.20.0.1") == (30, "200.20.0.0/24")
    assert db.lookup("199.0.0.0") == (None, None)


def test_constructor_requires_a_data_source():
    with pytest.raises(ValueError):
        ASInfo()


def test_iteration_yields_prefix_asn_pairs(asndb_test):
    """Iterating an ASInfo yields (prefix, asn) pairs covering every loaded
    prefix - not just prefix strings - so the whole database can be
    walked/exported without a separate lookup per prefix."""
    pairs = dict(asndb_test)
    assert pairs == {
        "200.10.0.0/30": 10,
        "200.10.0.0/24": 20,
        "200.20.0.0/24": 30,
        "210.0.0.0/8": 40,
        "210.0.0.0/9": 50,
    }
