from os import path

import pytest

from ipasn.mrt import MrtFormatError, parse_mrt_file

RIB_TD1_PARTDUMP = path.join(path.dirname(__file__), "data/rib.20080501.0644_firstMB.bz2")
RIB_TD2_PARTDUMP = path.join(path.dirname(__file__), "data/rib.20260730.1400_first2MB.bz2")
RIB6_TD2_PARTDUMP = path.join(path.dirname(__file__), "data/rib6.20260730.1400_firstMB.bz2")
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
    """TABLE_DUMP_V2: 32-bit ASNs, IPv4, including AS_SET-origin prefixes."""
    converted = parse_mrt_file(RIB_TD2_PARTDUMP, skip_record_on_error=True)
    assert len(converted) > 0
    assert_known_origins(converted, {
        "1.0.0.0/24": 13335,
        "1.0.4.0/24": 38803,
        "1.0.5.0/24": 38803,
        "1.0.6.0/24": 38803,
        "1.0.7.0/24": 38803,
        "1.0.16.0/24": 2519,
        "1.0.64.0/18": 18144,
        "1.0.128.0/17": 23969,
        "8.41.202.0/24": {40179},
        "15.0.64.0/18": {8035, 13979},
    })


def test_table_dump_v2_ipv6():
    """TABLE_DUMP_V2: 32-bit ASNs, IPv6, including AS_SET-origin prefixes."""
    converted = parse_mrt_file(RIB6_TD2_PARTDUMP, skip_record_on_error=True)
    assert len(converted) > 0
    assert_known_origins(converted, {
        "2000:b70:25::/48": 262191,
        "2001::/32": 6939,
        "2001:4:112::/48": 112,
        "2001:200::/32": 2500,
        "2001:200:900::/40": 7660,
        "2001:200:e00::/40": 4690,
        "2001:200:c000::/35": 23634,
        "2001:200:e000::/35": 7660,
        "2001:218::/32": 2914,
        "2001:218:2200::/40": 18259,
        "2001:218:8000::/38": 2914,
        "2001:218:e000::/38": 2914,
        "2001:480:240::/48": {687},
        "2001:678:6d0::/48": {212748},
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
