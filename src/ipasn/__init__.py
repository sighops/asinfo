# Copyright (c) 2014-2017 Hadi Asghari
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

import gzip
import re
from collections import defaultdict
from os import path
from ipaddress import collapse_addresses, ip_network
import pytricia
import json


class IpAsn:
    """
    Class to do fast offline & historical Autonomous-System-Number lookups for IPv4/IPv6 addresses.
    """

    def __init__(self, ipasn_file, as_names_file=None):
        """
        Creates a new instance of ipasn.\n
        :param ipasn_file:
            Filename of the IP-ASN database to load
            (The database can be a simple text file with lines of "NETWORK/BITS\tASN".
             You can create database files from BGP MRT/RBI dumps using the ipasn-utils
             scripts provided alongside the ipasn package. Alternatively, you can download
             prebuilt database from the ipasn homepage.)
        :param as_names_file:
            if given, loads autonomous system names from this file (warning: not fully tested)
        """
        self.records = pytricia.PyTricia()
        self.ip_version = None
        self.as_prefixes = defaultdict(set)
        self.ipasndb_file = ipasn_file
        self.asnames_file = as_names_file
        self.asnames = None

        if self.ipasndb_file is not None:
            if self.ipasndb_file.endswith(".gz"):
                with gzip.open(self.ipasndb_file, 'rt') as f:
                    for line in f:
                        self.process_load_line(line)
            else:
                with open(self.ipasndb_file, 'r') as f:
                    for line in f:
                        self.process_load_line(line)
        else:
            raise ValueError("No data given, all parameters are empty.")
        self.asnames = self.read_asnames() if as_names_file else None

        # For supporting pickling of object.  This freezes the patricia tree for modification.
        self.records.freeze()

    def process_load_line(self, line):
        if line == '' or line == '\n':
            return
        if  line[0] in ';#':
            return
        prefix, asn = line.split()
        self.records[prefix] = asn
        self.as_prefixes[int(asn)].add(prefix)

    def read_asnames(self):
        """
        Reads autonomous system names (warning: this method is not fully tested)
        """
        if self.asnames_file.endswith('.gz'):
            with gzip.open(self.asnames_file, 'rt') as f:
                raw_data = f.read()
            names = json.loads(raw_data)

        else:
            with open(self.asnames_file, 'r', encoding='utf-8') as fs:
                names = json.load(fs)

        try:
            formatted_names = dict([(int(k), v) for k, v in names.items()])
        except ValueError:
            raise Exception("Autonomous system names file contains non-nummeric ASNs")

        return formatted_names

    # TODO: determine if needed and improve if so.  Ideally, if v4 and v6 lookups are needed then an IpAsn object
    #       would be used for each version.  This is recommended by pytricia for performance reasons.
    def get_ip_version(self, ip):
        if self.ip_version:
            return self.ip_version

        if ':' in ip:
            self.ip_version = 'v6'
        else:
            self.ip_version =  'v4'
        return self.ip_version

    def lookup(self, ip):
        """
        Returns the as number and best matching prefix for given ip address.\n
        :param ip_address: String representation of ip address , for example "8.8.8.8".
        :raises: ValueError if an invalid IP address is passed.
        :return: (asn, prefix) of a given IP address.\n
            'asn' is the 32-bit AS Number that holds this IP address, as advertised on BGP.\n
            'prefix' is the best matching prefix in the BGP table for the given IP address.\n
            Returns (None, None) if the IP address is not found (=not advertised, unreachable)
        """

        # TODO: determine if needed, do something with it if so.  Might be good to enforce using one object per ip version for performance.
        version = self.get_ip_version(ip)
        try:
            asn = self.records[ip]
            prefix = self.records.get_key(ip)
            return int(asn), prefix
        except KeyError:
            return None, None

    def get_as_prefixes(self, asn):
        """ :return: All prefixes advertised by given ASN """
        return self.as_prefixes[int(asn)]

    def get_as_prefixes_effective(self, asn):
        """
        Returns the effective address space of given ASN by removing all overlaps among prefixes
        :return: The effective prefixes resulting from removing overlaps of given ASN's prefixes
        """
        prefixes = self.get_as_prefixes(asn)
        if prefixes:
            non_overlapping_4 = collapse_addresses([ip_network(i) for i in prefixes if ':' not in i])
            non_overlapping_6 = collapse_addresses([ip_network(i) for i in prefixes if ':' in i])
            return [i.compressed for i in non_overlapping_4] + \
                   [i.compressed for i in non_overlapping_6]
        return None

    def get_as_size(self, asn):
        """
        Returns the size of an AS as the total count of IPv4 addresses that the AS is responsible for
        :param asn: The autonomous system number
        :return: number of unique IPv4 addresses routed by AS
        """
        prefixes = self.get_as_prefixes_effective(asn)
        if prefixes:
            size = sum([2 ** (32 - int(px.split('/')[1])) for px in prefixes if ':' not in px])
            return size
        return 0

    def get_as_size_v6(self, asn):
        """
        Returns the size of an AS as the total count of IPv6 addresses that the AS is responsible for
        :param asn: The autonomous system number
        :return: number of unique IPv6 addresses routed by AS
        """
        prefixes = self.get_as_prefixes_effective(asn)
        if prefixes:
            size = sum([2 ** (128 - int(px.split('/')[1])) for px in prefixes if ':' in px])
            return size
        return 0

    def get_as_name(self, asn):
        """
        Under construction, do not use!\n
        :param asn: 32-bit ASN
        :return: the AS-Name associated with this ASN
        """
        if not self.asnames:
            raise Exception("Autonomous system names not loaded during initialization")
        return self.asnames.get(asn, None)

    def __repr__(self):
        return "IpAsn(%s, '%s')" % (self.ipasndb_file, self.asnames_file)

    def __iter__(self):
        for rec in self.records:
            yield rec


    @staticmethod
    def convert_32bit_to_asdot_asn_format(asn):
        """
        Converts a 32bit AS number into the ASDOT format AS[Number].[Number] - see rfc5396.\n
        :param asn: The number of an AS in numerical format.
        :return: The AS number in AS[Number].[Number] format.
        """
        div, mod = divmod(asn, 2**16)
        return "AS%d.%d" % (div, mod) if div > 0 else "AS%d" % mod

    @staticmethod
    def convert_asdot_to_32bit_asn(asdot):
        """
        Converts a asdot representation of an AS to a 32bit AS number - see rfc5396.\n
        :param asdot:  "AS[Number].[Number]" representation of an autonomous system
        :return: 32bit AS number
        """
        pattern = re.compile(r'^(AS|as|aS|As)[0-9]+(\.[0-9]+)?')
        match = pattern.fullmatch(asdot)
        if not match:
            raise ValueError("Invalid asdot format for input. input format must be something like"
                             " AS<Number> or AS<Number>.<Number> ")
        if asdot.find(".") > 0:  # asdot input is of the format AS[d+].<d+> for example AS1.234
            s1, s2 = asdot.split(".")
            i1 = int(s1[2:])
            i2 = int(s2)
            asn = 2**16 * i1 + i2
        else:
            asn = int(asdot[2:])  # asdot input is of the format AS[d+] for example AS123
        return asn
