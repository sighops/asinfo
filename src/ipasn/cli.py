from argparse import HelpFormatter, ArgumentParser
from .downloader import Downloader
from sys import argv
import pdb
import os
from pathlib import Path
import ipasn
import pickle
import re

class CustomFormatter(HelpFormatter):
    def _metavar_formatter(self, action, default_metavar):
        if action.metavar is not None:
            result = action.metavar
        elif action.choices is not None:
            result = 'ONE OF: %s' % ' | '.join(map(str, action.choices))
        else:
            result = default_metavar

        def format(tuple_size):
            if isinstance(result, tuple):
                return result
            else:
                return (result, ) * tuple_size
        return format

class cli:

    def __init__(self):

        self.default_path = str(Path('~/.ipasn/cache').expanduser())
        self.default_as_names_file = self.default_path + '/asnames'
        self.default_db_file = self.default_path + '/asndb'
        self.default_pickle_file = self.default_path + '/asndb_pickle'
        self.ipv4_pat = re.compile(r'\d+\.\d+\.\d+\.\d+')

        parser = ArgumentParser(
            formatter_class=CustomFormatter,
            description='ipasn command line utility for lookups and file downloads',
            usage="ipasn COMMAND [OPTIONS]"
        )
        subparser = parser.add_subparsers(title="Commands", dest="command", metavar="")


        # Download parser and args
        dl = subparser.add_parser(
            "download",
            help="Download files used by ipasn to perform various lookups",
            formatter_class=CustomFormatter
        )
        dl.set_defaults(func=self.download)
        dl.add_argument("type", choices=['asnames', 'ribs'])

        lu = subparser.add_parser(
            "lookup",
            help="Lookup asn, prefixes, names, etc. using locally downloaded files",
            formatter_class=CustomFormatter
        )
        lu.set_defaults(func=self.lookup)
        lu.add_argument("term", help="Search term.  Can be a v4/v6 ip address, ASN, or AS name.")




        self.parser = parser

    def process(self):
        # By default argparse quietly exits if no arguments supplied.  At least print the help...
        args = self.parser.parse_args(None if argv[1:] else ['--help'])
        args.func(args)

    def setup_local_dir_if_not_exist(self):
        path = Path('~/.ipasn/cache').expanduser()
        if path.exists():
            return
        path.mkdir(parents=True, exist_ok=True)


    def download(self, args):
        self.setup_local_dir_if_not_exist()
        self.downloader = Downloader()

        match args.type:
            case "asnames":
                self.download_asnames()
            case "ribs":
                self.download_ribs()
            case "all":
                self.download_ribs()
                self.download_asnames()
            case _:
                self.parser.print_help()

    def download_asnames(self):
        print("Downloading latest AS names")
        names = self.downloader.download_asnames()
        fpath = self.default_as_names_file
        with open(fpath, 'w', encoding="utf-8") as f:
            f.write(names)
        print("Finished downloading")
        print("AS names file saved to:", fpath)

    def download_ribs(self):
        print("Downloading latest routes")
        fpath = self.default_db_file
        names = self.downloader.download_latest_rib_file(outfile=fpath)

        db = ipasn.IpAsn(fpath, self.default_as_names_file)
        p = pickle.dumps(db)
        pfpath = self.default_pickle_file
        with open(pfpath, 'wb') as f:
            f.write(p)

        print("Finished downloading")
        print("ASN to prefix db file saved to:", fpath)

    def lookup(self, args):
        f = open(self.default_pickle_file, 'rb')
        db = pickle.loads(f.read())

        term_type = self.detect_term_type(args.term)
        match term_type:
            case "v4":
                print("%s, %s" % db.lookup(args.term))
            case "v6":
                print("%s, %s" % db.lookup(args.term))
            case "asn":
                term = int(args.term.lower().strip("as"))
                prefixes = db.get_as_prefixes(term)
                for p in prefixes:
                    print(p)
            case "name":




    def detect_term_type(self, term):
        # TODO: somewhere, probably need to convert asdot syntax to support that
        # TODO: improve this and support as names
        term = term.lower()
        if ":" in term:
            return "v6"
        if "as" in term:
            return "asn"
        if self.ipv4_pat.match(term):
            return "v4"
        return "name"





if __name__ == '__main__':
    cli = cli()
    cli.process()
