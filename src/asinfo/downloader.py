from __future__ import annotations

import json
import re
import sys
from datetime import UTC, datetime
from ftplib import FTP
from urllib.request import urlopen

from asinfo import mrt


class Downloader:
    FTP_HOST = "archive.routeviews.org"
    FTP_ROOT_V4 = "bgpdata"

    def __init__(self) -> None:
        self.RIB_URL_V4_TEMPLATE = "https://archive.routeviews.org/bgpdata/%s/RIBS/"
        self.RIB_URL_V6_TEMPLATE = "https://archive.routeviews.org/route-views6/bgpdata/%s/RIBS/"
        self.RIB_FILE_PAT = re.compile(r'href="(rib\.\d+\.\d+\.bz2)"', re.U)
        self.RIB_FILENAME_PAT = re.compile(r"rib\.\d+\.\d+\.bz2$", re.U)

        self.ASNAMES_URL = "http://www.cidr-report.org/as2.0/autnums.html"
        self.ASNAME_PAT = re.compile(r'<a href=".+">AS(\d+)\s*</a>\s*(.+)', re.U)

    def download_latest_rib_file(
        self,
        file_url: str | None = None,
        outfile: str | None = None,
        protocol: str = "https",
    ) -> None:
        """Downloads the latest RIB archive and converts it to the IP-ASN dat format.

        `protocol` selects the transport: "https" (default) or "ftp". There
        is no automatic fallback between them - a failure is raised as-is;
        pass protocol="ftp" explicitly if that's what you want.
        """
        if outfile is None:
            raise ValueError("no outfile specified")

        intermediate_outfile = outfile + ".bz2"
        if protocol == "https":
            if file_url is None:
                file_url = self.get_latest_rib_file_url()
            print("Downloading:", file_url)
            resp = urlopen(file_url)
            with open(intermediate_outfile, "wb") as f:
                f.write(resp.read())
        elif protocol == "ftp":
            self._download_latest_rib_file_ftp(intermediate_outfile)
        else:
            raise ValueError(f"unknown protocol {protocol!r}; expected 'https' or 'ftp'")

        self.convert_file(intermediate_outfile, outfile)

    def get_latest_rib_file_url(self) -> str:
        # Get the latest. Archive entries are listed using UTC
        now = datetime.now(UTC)
        date_path = now.strftime("%Y") + "." + now.strftime("%m")
        archive_url = self.RIB_URL_V4_TEMPLATE % (date_path)

        # TODO: Consider determining expected filename and fallback to finding it if 404.
        #       New files are added every 2 hours. Could determine expected filename with
        #       hour % 2 == 0 and save a network call.
        resp = urlopen(archive_url)
        data = resp.read()
        data = data.decode("latin-1")
        files = self.RIB_FILE_PAT.findall(data)
        filename = files[-1]
        file_url = archive_url + filename
        return file_url

    def get_latest_rib_file_path_ftp(self) -> str:
        """Returns the FTP path (relative to FTP_HOST's root) of the latest
        RIB archive, e.g. "bgpdata/2026.07/RIBS/rib.20260728.1200.bz2"."""
        now = datetime.now(UTC)
        date_path = f"{self.FTP_ROOT_V4}/{now.strftime('%Y.%m')}/RIBS"
        ftp = FTP(self.FTP_HOST)
        try:
            ftp.login()
            files = ftp.nlst(date_path)
        finally:
            ftp.quit()
        rib_files = sorted(f for f in files if self.RIB_FILENAME_PAT.search(f))
        if not rib_files:
            raise LookupError(f"No RIB files found via FTP in {date_path}")
        return rib_files[-1]

    def _download_latest_rib_file_ftp(self, intermediate_outfile: str) -> None:
        remote_path = self.get_latest_rib_file_path_ftp()
        print("Downloading via FTP:", remote_path)
        ftp = FTP(self.FTP_HOST)
        try:
            ftp.login()
            with open(intermediate_outfile, "wb") as f:
                ftp.retrbinary(f"RETR {remote_path}", f.write)
        finally:
            ftp.quit()

    def convert_file(self, in_file: str, out_file: str) -> None:
        prefixes = mrt.parse_mrt_file(
            in_file, on_progress=lambda msg: print(msg, file=sys.stderr), skip_record_on_error=True
        )
        mrt.dump_prefixes_to_file(prefixes, out_file)

    def download_asnames(self) -> str:
        http = urlopen(self.ASNAMES_URL)
        data = http.read()
        http.close()

        # TODO: use another lib like requests or implement logic to detect encoding of the
        # http response. The site uses latin-1 now but that may not always be true in the future.
        text = data.decode("latin-1")
        names = self.to_dict(text)
        return json.dumps(names)

    def to_dict(self, html: str) -> dict[str, str]:
        names = self.ASNAME_PAT.findall(html)
        return dict(names)
