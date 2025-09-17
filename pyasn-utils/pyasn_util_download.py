#!/usr/bin/python

# Copyright (c) 2009-2017 Hadi Asghari
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Script to download the latest routeview bgpdata, or for a certain period
# Thanks to Vitaly Khamin (https://github.com/khamin) for the FTP code

from datetime import datetime, UTC
from argparse import ArgumentParser
from sys import exit
from urllib.request import urlopen
import re

URL_TEMPLATE = "https://archive.routeviews.org/%s/%s/RIBS/"
FILE_PAT = re.compile(r'href="(rib\.\d+\.\d+\.bz2)"', re.U)

def download_file(file_url=None, outfile=None):
    if file_url == None:
        file_url = get_latest_file_url()

    print("Downloading:", file_url)
    resp = urlopen(file_url)
    if outfile == None:
        outfile = file_url.split("/")[-1]
    with open(outfile, 'wb') as f:
        f.write(resp.read())

def get_latest_file_url():
    # Get the latest. Archive entries are listed using UTC
    now = datetime.now(UTC)
    date_path = now.strftime("%Y") + "." + now.strftime("%m")
    archive_url = URL_TEMPLATE % (archive_root, date_path)

    # TODO: Consider determining expected filename and fallback to finding it if 404. New files are added every 2 hours.
    #       Could determine expected filename with hour % 2 == 0 and save a network call.
    resp = urlopen(archive_url)
    data = resp.read()
    data = data.decode('latin-1')
    files = FILE_PAT.findall(data)
    filename = files[-1]
    file_url = archive_url + filename

def download_multiple(file):
    dates = []
    with open(file, 'r') as f:
        for line in f:
            line = line.strip()
            if len(line) != 8:
                print("Skipping... this line appears to be formatted incorrectly:", line)
                continue
            dates.append(line)
    for date in dates:
        date_path = date[:4] + "." + date[4:6]
        filename = "rib." + date + ".0600.bz2"
        url_base = URL_TEMPLATE % (archive_root, date_path)
        success = False
        try:
            download_file(url_base + filename)
            success = True
        except:
            pass

        if success == False:
            print("Couldn't find file for", filename)
            filename = "rib." + date + ".0000.bz2"
            print("Trying again for ", filename)
            try:
                download_file(url_base + filename)
                success = True
            except:
                pass

        if success:
            print("Got", filename, "for", date)
        else:
            print("Couldn't download file for", date)

if __name__ == '__main__':
    # Parse command line options
    parser = ArgumentParser(description="Script to download MRT/RIB BGP archives (from RouteViews).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--latestv4', '-4', '--latest', action='store_true',
                       help='Grab lastest IPV4 data')
    group.add_argument('--latestv6', '-6', action='store_true', help='Grab lastest IPV6 data')
    group.add_argument('--latestv46', '-46', action='store_true', help='Grab lastest IPV4/V6 data')
    group.add_argument('--dates-from-file', '-f', action='store',
                       help='Grab IPV4 archives for specifc dates (one date, YYYYMMDD, per line)')
    parser.add_argument('--filename', dest="outfile", action='store', help="Specify name with which the file will be saved")
    args = parser.parse_args()

    if args.latestv4:
        archive_root = "bgpdata"
    elif args.latestv6:
        archive_root = "route-views6/bgpdata"
    elif args.latestv46:
        archive_root = "route-views4/bgpdata"
    else:
        archive_root = "bgpdata"

    if args.dates_from_file:
        download_multiple(args.dates_from_file)
    else:
        download_file(outfile=args.outfile)
    print("Done")
