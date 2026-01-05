from urllib.request import urlopen
from datetime import datetime, UTC
import json
import re
from ipasn import mrtx

class Downloader:

    def __init__(self):
        self.RIB_URL_V4_TEMPLATE = "https://archive.routeviews.org/bgpdata/%s/RIBS/"
        self.RIB_URL_V6_TEMPLATE = "https://archive.routeviews.org/route-views6/bgpdata/%s/RIBS/"
        self.RIB_FILE_PAT = re.compile(r'href="(rib\.\d+\.\d+\.bz2)"', re.U)

        self.ASNAMES_URL = 'http://www.cidr-report.org/as2.0/autnums.html'
        self.ASNAME_PAT = re.compile(r'<a href=".+">AS(\d+)\s*</a>\s*(.+)', re.U)
    
    def download_latest_rib_file(self, file_url=None, outfile=None):
        if outfile == None:
            raise Exception("no outfile specified")

        if file_url == None:
            file_url = self.get_latest_rib_file_url()

        print("Downloading:", file_url)
        resp = urlopen(file_url)

        intermediate_outfile = outfile + '.bz2'
        with open(intermediate_outfile, 'wb') as f:
            f.write(resp.read())

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

    def download_multiple_ribs(self, dates):
        """
        Currently expects a list of dates to be given in format YYYYMMDD.HHMM
        NOTE:  Starting at 2009-05-15 16:00 ribs files are available every 2 hours on the hour.  Before that the
        timestamps vary and this will likely fail for earlier dates.
        """
        for date in dates:
            date_path = date[:4] + "." + date[4:6]
            filename = "rib." + date + ".1200.bz2"
            url_base = self.RIB_URL_TEMPLATE % (archive_root, date_path)
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
        prefixes = mrtx.parse_mrt_file(
            in_file,
            print_progress=True,
            skip_record_on_error=True
        )
        mrtx.dump_prefixes_to_file(prefixes, out_file)

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