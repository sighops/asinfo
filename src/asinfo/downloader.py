from urllib.request import urlopen
from ftplib import FTP
from datetime import datetime, UTC
import json
import re
import sys
from asinfo import mrt

class Downloader:

    FTP_HOST = "archive.routeviews.org"
    FTP_ROOT_V4 = "bgpdata"

    def __init__(self):
        self.RIB_URL_V4_TEMPLATE = "https://archive.routeviews.org/bgpdata/%s/RIBS/"
        self.RIB_URL_V6_TEMPLATE = "https://archive.routeviews.org/route-views6/bgpdata/%s/RIBS/"
        self.RIB_FILE_PAT = re.compile(r'href="(rib\.\d+\.\d+\.bz2)"', re.U)
        self.RIB_FILENAME_PAT = re.compile(r'rib\.\d+\.\d+\.bz2$', re.U)

        self.ASNAMES_URL = 'http://www.cidr-report.org/as2.0/autnums.html'
        self.ASNAME_PAT = re.compile(r'<a href=".+">AS(\d+)\s*</a>\s*(.+)', re.U)

    def download_latest_rib_file(self, file_url=None, outfile=None, protocol="https"):
        """Downloads the latest RIB archive and converts it to the IP-ASN dat format.

        `protocol` selects the transport: "https" (default) or "ftp". There
        is no automatic fallback between them - a failure is raised as-is;
        pass protocol="ftp" explicitly if that's what you want.
        """
        if outfile == None:
            raise Exception("no outfile specified")

        intermediate_outfile = outfile + '.bz2'
        if protocol == "https":
            if file_url == None:
                file_url = self.get_latest_rib_file_url()
            print("Downloading:", file_url)
            resp = urlopen(file_url)
            with open(intermediate_outfile, 'wb') as f:
                f.write(resp.read())
        elif protocol == "ftp":
            self._download_latest_rib_file_ftp(intermediate_outfile)
        else:
            raise ValueError(f"unknown protocol {protocol!r}; expected 'https' or 'ftp'")

        self.convert_file(intermediate_outfile, outfile)


    def get_latest_rib_file_url(self):
        # Get the latest. Archive entries are listed using UTC
        now = datetime.now(UTC)
        date_path = now.strftime("%Y") + "." + now.strftime("%m")
        archive_url = self.RIB_URL_V4_TEMPLATE % (date_path)

        # TODO: Consider determining expected filename and fallback to finding it if 404. New files are added every 2 hours.
        #       Could determine expected filename with hour % 2 == 0 and save a network call.
        resp = urlopen(archive_url)
        data = resp.read()
        data = data.decode('latin-1')
        files = self.RIB_FILE_PAT.findall(data)
        filename = files[-1]
        file_url = archive_url + filename
        return file_url

    def get_latest_rib_file_path_ftp(self):
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

    def _download_latest_rib_file_ftp(self, intermediate_outfile):
        remote_path = self.get_latest_rib_file_path_ftp()
        print("Downloading via FTP:", remote_path)
        ftp = FTP(self.FTP_HOST)
        try:
            ftp.login()
            with open(intermediate_outfile, 'wb') as f:
                ftp.retrbinary(f'RETR {remote_path}', f.write)
        finally:
            ftp.quit()

    def download_multiple_ribs(self, dates):
        """
        Currently expects a list of dates to be given in format YYYYMMDD.HHMM
        NOTE:  Starting at 2009-05-15 16:00 ribs files are available every 2 hours on the hour.  Before that the
        timestamps vary and this will likely fail for earlier dates.
        """
        for date in dates:
            date_path = date[:4] + "." + date[4:6]
            filename = "rib." + date + ".1200.bz2"
            url_base = self.RIB_URL_V4_TEMPLATE % (date_path)
            success = False
            try:
                download_rib_file(url_base + filename)
                success = True
            except:
                pass

            if success == False:
                print("Couldn't find file for", filename)
                filename = "rib." + date + ".1400.bz2"
                print("Trying again for ", filename)
                try:
                    download_rib_file(url_base + filename)
                    success = True
                except:
                    pass

            if success:
                print("Got", filename, "for", date)
            else:
                print("Couldn't download file for", date)

    def convert_file(self, in_file, out_file):
        prefixes = mrt.parse_mrt_file(
            in_file,
            on_progress=lambda msg: print(msg, file=sys.stderr),
            skip_record_on_error=True
        )
        mrt.dump_prefixes_to_file(prefixes, out_file)

    def download_asnames(self):
        http = urlopen(self.ASNAMES_URL)
        data = http.read()
        http.close()

        # TODO: use another lib like requests or implement logic to detect encoding of the http response. The site uses
        # latin-1 now but that may not always be true in the future.
        data = data.decode('latin-1')
        data = self.to_dict(data)
        return json.dumps(data)

    def to_dict(self, html):
        names = self.ASNAME_PAT.findall(html)
        return dict(names)