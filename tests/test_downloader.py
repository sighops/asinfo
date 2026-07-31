import json
from pathlib import Path
from urllib.error import URLError

import pytest

from asinfo.downloader import Downloader

RIB_FIXTURE = Path(__file__).parent / "data" / "rib.20260730.1400_first2MB.bz2"


class FakeResponse:
    def __init__(self, data: bytes):
        self._data = data

    def read(self):
        return self._data

    def close(self):
        pass


class FakeFTP:
    """Stand-in for ftplib.FTP: records what was retrieved, serves
    `listing` for nlst(), and writes `content` back via retrbinary()."""

    def __init__(self, listing=(), content=b""):
        self.listing = list(listing)
        self.content = content
        self.retrieved_path = None
        self.quit_called = False

    def __call__(self, host):
        self.host = host
        return self

    def login(self):
        pass

    def nlst(self, path):
        return [f"{path}/{name}" for name in self.listing]

    def retrbinary(self, cmd, callback):
        assert cmd.startswith("RETR ")
        self.retrieved_path = cmd[len("RETR ") :]
        callback(self.content)

    def quit(self):
        self.quit_called = True


def test_get_latest_rib_file_url_https(monkeypatch):
    html = (
        '<a href="rib.20260101.0000.bz2">rib.20260101.0000.bz2</a>\n'
        '<a href="rib.20260101.0200.bz2">rib.20260101.0200.bz2</a>\n'
    )
    seen_urls = []

    def fake_urlopen(url):
        seen_urls.append(url)
        return FakeResponse(html.encode("latin-1"))

    monkeypatch.setattr("asinfo.downloader.urlopen", fake_urlopen)
    d = Downloader()
    url = d.get_latest_rib_file_url_https()

    assert url.endswith("rib.20260101.0200.bz2")
    assert "archive.routeviews.org/bgpdata/" in seen_urls[0]


def test_download_latest_rib_file_requires_outfile():
    d = Downloader()
    with pytest.raises(ValueError, match="no outfile specified"):
        d.download_latest_rib_file()


def test_download_latest_rib_file(monkeypatch, tmp_path):
    content = RIB_FIXTURE.read_bytes()
    monkeypatch.setattr("asinfo.downloader.urlopen", lambda url: FakeResponse(content))

    d = Downloader()
    outfile = str(tmp_path / "out.dat")
    d.download_latest_rib_file(file_url="https://example.test/rib.bz2", outfile=outfile)

    assert Path(outfile + ".bz2").read_bytes() == content
    text = Path(outfile).read_text()
    assert "38803" in text  # known ASN in this fixture (see tests/test_mrtx.py)


def test_convert_rib_to_dat_file(tmp_path):
    outfile = str(tmp_path / "out.dat")
    d = Downloader()
    d.convert_rib_to_dat_file(str(RIB_FIXTURE), outfile)

    text = Path(outfile).read_text()
    assert "1.0.4.0/24\t38803" in text


def test_fetch_asnames_as_json(monkeypatch):
    html = (
        '<a href="/cgi-bin/as-report?as=AS1&view=2.0">AS1  </a>LVLT-1, US\n'
        '<a href="/cgi-bin/as-report?as=AS15169&view=2.0">AS15169  </a>GOOGLE, US\n'
    )
    monkeypatch.setattr(
        "asinfo.downloader.urlopen", lambda url: FakeResponse(html.encode("latin-1"))
    )

    d = Downloader()
    result = json.loads(d.fetch_asnames_as_json())

    assert result == {"1": "LVLT-1, US", "15169": "GOOGLE, US"}


def test_parse_asnames_html():
    html = '<a href="foo">AS15169 </a>GOOGLE, US\n<a href="bar">AS1 </a>LVLT-1, US\n'
    d = Downloader()
    assert d.parse_asnames_html(html) == {"15169": "GOOGLE, US", "1": "LVLT-1, US"}


def test_get_latest_rib_file_path_ftp(monkeypatch):
    fake_ftp = FakeFTP(listing=["rib.20260101.0000.bz2", "rib.20260101.0200.bz2", "README"])
    monkeypatch.setattr("asinfo.downloader.FTP", fake_ftp)

    d = Downloader()
    path = d.get_latest_rib_file_path_ftp()

    assert path.endswith("rib.20260101.0200.bz2")
    assert fake_ftp.quit_called


def test_get_latest_rib_file_path_ftp_no_files_raises(monkeypatch):
    fake_ftp = FakeFTP(listing=["README", "not-a-rib-file.txt"])
    monkeypatch.setattr("asinfo.downloader.FTP", fake_ftp)

    d = Downloader()
    with pytest.raises(LookupError):
        d.get_latest_rib_file_path_ftp()


def test_download_latest_rib_file_https_failure_is_not_caught(monkeypatch, tmp_path):
    """No automatic FTP fallback - an HTTPS failure propagates as-is."""

    def failing_urlopen(url):
        raise URLError("connection refused")

    monkeypatch.setattr("asinfo.downloader.urlopen", failing_urlopen)
    fake_ftp = FakeFTP(listing=["rib.20260101.0000.bz2"])
    monkeypatch.setattr("asinfo.downloader.FTP", fake_ftp)

    d = Downloader()
    outfile = str(tmp_path / "out.dat")
    with pytest.raises(URLError):
        d.download_latest_rib_file(outfile=outfile)

    assert fake_ftp.retrieved_path is None  # FTP was never touched


def test_download_latest_rib_file_explicit_ftp_protocol(monkeypatch, tmp_path):
    content = RIB_FIXTURE.read_bytes()
    fake_ftp = FakeFTP(listing=["rib.20260101.0000.bz2"], content=content)
    monkeypatch.setattr("asinfo.downloader.FTP", fake_ftp)
    # If HTTPS were touched at all, this would blow up the test - proves ftp
    # protocol doesn't fall back to (or start with) HTTPS either.
    monkeypatch.delattr("asinfo.downloader.urlopen")

    d = Downloader()
    outfile = str(tmp_path / "out.dat")
    d.download_latest_rib_file(outfile=outfile, protocol="ftp")

    assert fake_ftp.retrieved_path.endswith("rib.20260101.0000.bz2")
    assert Path(outfile + ".bz2").read_bytes() == content
    assert "38803" in Path(outfile).read_text()


def test_download_latest_rib_file_unknown_protocol_raises(tmp_path):
    d = Downloader()
    outfile = str(tmp_path / "out.dat")
    with pytest.raises(ValueError, match="unknown protocol"):
        d.download_latest_rib_file(outfile=outfile, protocol="gopher")
