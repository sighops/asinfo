from os import path

import pytest

from ipasn.mrt import MrtFormatError, parse_mrt_file

RIB_TD1_PARTDUMP = path.join(path.dirname(__file__), "data/rib.20080501.0644_firstMB.bz2")
RIB_TD2_PARTDUMP = path.join(path.dirname(__file__), "data/rib.20140523.0600_firstMB.bz2")
RIB6_TD2_PARTDUMP = path.join(path.dirname(__file__), "data/rib6.20151101.0600_firstMB.bz2")
RIB_TD2_RECORD_FAIL_PARTDUMP = path.join(path.dirname(__file__),
                                         "data/bview.20140112.1600_3samples.bz2")


def assert_known_origins(converted, expected):
    """Black-box check against known-good prefix -> origin-AS mappings for
    real RouteViews/RIPE RIB archives. These fixtures are deliberately
    truncated ("_firstMB") to keep them small - parse_mrt_file() is expected
    to stop cleanly at the truncation point (see the EOFError handling in
    mrt/tabledump.py) rather than raise, so only a subset of each fixture's
    known-good prefixes will actually be present in the result; every prefix
    that *is* present must match exactly.
    """
    checked = 0
    for prefix, want in expected.items():
        got = converted.get(prefix)
        if got is None:
            continue  # past the truncation point in this partial fixture
        checked += 1
        assert got == want, f"wrong origin for {prefix}"
    assert checked > 0, "none of the expected prefixes were found at all"


def test_table_dump_v1():
    """TABLE_DUMP (v1): 16-bit ASNs, IPv4."""
    converted = parse_mrt_file(RIB_TD1_PARTDUMP, skip_record_on_error=True)
    assert len(converted) > 0
    assert_known_origins(converted, {
        "3.0.0.0/8": 80,
        "4.79.181.0/24": 14780,
        "6.9.0.0/20": 668,
        "8.2.118.0/23": 13909,
        "8.3.52.0/23": 26759,
        "8.4.96.0/20": 15162,
        "8.6.48.0/21": 36492,
        "8.7.81.0/24": 25741,
        "8.7.232.0/24": 13909,
    })


def test_table_dump_v2():
    """TABLE_DUMP_V2: 32-bit ASNs, IPv4, including an AS_SET-origin prefix."""
    converted = parse_mrt_file(RIB_TD2_PARTDUMP, skip_record_on_error=True)
    assert len(converted) > 0
    assert_known_origins(converted, {
        "1.0.4.0/24": 56203,
        "1.0.5.0/24": 56203,
        "1.0.20.0/23": 2519,
        "1.0.38.0/24": 24155,
        "1.0.128.0/17": 9737,
        "1.1.57.0/24": 132537,
        "1.38.0.0/17": {38266},
        "1.116.0.0/16": 131334,
        "5.128.0.0/14": {50923},
        "5.128.0.0/16": 31200,
    })


def test_table_dump_v2_ipv6():
    """TABLE_DUMP_V2: 32-bit ASNs, IPv6."""
    converted = parse_mrt_file(RIB6_TD2_PARTDUMP, skip_record_on_error=True)
    assert len(converted) > 0
    assert_known_origins(converted, {
        "2001:504:2e::/48": 10578,
        "2001:57a:e030::/45": 22773,
        "2001:590:1800::/38": 4436,
        "2001:67c:368::/48": 12509,
        "2001:67c:14d8::/48": 61413,
        "2001:67c:22f4::/48": 200490,
        "2001:67c:2c90::/48": 60092,
        "2001:978:1801::/48": 174,
        "2001:dc5:0:55::/64": 9700,
        "2001:df2:f000::/48": 55319,
        "2001:12c4::/32": 28262,
        "2001:1838:5000::/40": 23352,
        "2001:1a88::/32": 15600,
        "2001:4478:1900::/40": 4802,
        "2001:4888:4:fe00::/64": 22394,
        "2001:49f0:a015::/48": 174,
        "2001:b032:1b::/48": 3462,
    })


def test_skip_record_on_error_false_raises():
    """With skip_record_on_error unset (default False), a record whose
    path attributes don't yield a usable origin AS raises MrtFormatError."""
    with pytest.raises(MrtFormatError):
        parse_mrt_file(RIB_TD2_RECORD_FAIL_PARTDUMP)


def test_skip_record_on_error_true_skips():
    """With skip_record_on_error=True, the one bad record among the
    fixture's 3 is skipped and the other 2 are returned."""
    res = parse_mrt_file(RIB_TD2_RECORD_FAIL_PARTDUMP, skip_record_on_error=True)
    assert len(res) == 2


def test_default_route_is_dropped():
    """0.0.0.0/0 and ::/0 aren't meaningful in an ASN lookup table and
    should never appear in parse_mrt_file()'s output."""
    converted = parse_mrt_file(RIB_TD2_PARTDUMP, skip_record_on_error=True)
    assert "0.0.0.0/0" not in converted
    assert "::/0" not in converted


def test_on_progress_callback():
    """on_progress is called with skip/error/summary messages, and parsing
    works fine without one (the default)."""
    messages = []
    parse_mrt_file(RIB_TD2_RECORD_FAIL_PARTDUMP, skip_record_on_error=True,
                    on_progress=messages.append)
    assert any("skipping" in m for m in messages)
    assert any(m.startswith("done:") for m in messages)
