from __future__ import annotations

import pickle
import re
import sys
from argparse import Action, ArgumentParser, HelpFormatter, Namespace
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import asinfo

from .downloader import Downloader


class CustomFormatter(HelpFormatter):
    def _metavar_formatter(
        self, action: Action, default_metavar: str
    ) -> Callable[[int], tuple[str, ...]]:
        if action.metavar is not None:
            result = action.metavar
        elif action.choices is not None:
            result = f"ONE OF: {' | '.join(map(str, action.choices))}"
        else:
            result = default_metavar

        def format(tuple_size: int) -> tuple[str, ...]:
            if isinstance(result, tuple):
                return result
            else:
                return (result,) * tuple_size

        return format


class CLI:
    downloader: Downloader

    def __init__(self) -> None:
        self.default_path = str(Path("~/.asinfo/cache").expanduser())
        self.default_as_names_file = self.default_path + "/asnames"
        self.default_db_file = self.default_path + "/asndb"
        self.default_pickle_file = self.default_path + "/asndb_pickle"
        self.ipv4_pat = re.compile(r"\d+\.\d+\.\d+\.\d+")

        parser = ArgumentParser(
            formatter_class=CustomFormatter,
            description="asinfo command line utility for lookups and file downloads",
            usage="asinfo COMMAND [OPTIONS]",
        )
        parser.add_argument("--version", action="version", version=f"asinfo {asinfo.__version__}")
        subparser = parser.add_subparsers(title="Commands", dest="command", metavar="")

        # Download parser and args
        dl = subparser.add_parser(
            "download",
            help="Download files used by asinfo to perform various lookups",
            formatter_class=CustomFormatter,
        )
        dl.set_defaults(func=self.download)
        dl.add_argument("type", choices=["asnames", "ribs", "all"])

        lu = subparser.add_parser(
            "lookup",
            help="Lookup asn, prefixes, names, etc. using locally downloaded files",
            formatter_class=CustomFormatter,
        )
        lu.set_defaults(func=self.lookup)
        lu.add_argument("term", help="Search term.  Can be a v4/v6 ip address, ASN, or AS name.")

        st = subparser.add_parser(
            "status",
            help="Show how old the locally cached data is",
            formatter_class=CustomFormatter,
        )
        st.set_defaults(func=self.status)

        self.parser = parser

    def run(self) -> None:
        # By default argparse quietly exits if no arguments supplied.  At least print the help...
        args = self.parser.parse_args(None if sys.argv[1:] else ["--help"])
        args.func(args)

    def ensure_cache_dir_exists(self) -> None:
        path = Path("~/.asinfo/cache").expanduser()
        if path.exists():
            return
        path.mkdir(parents=True, exist_ok=True)

    def download(self, args: Namespace) -> None:
        self.ensure_cache_dir_exists()
        self.downloader = Downloader()

        match args.type:
            case "asnames":
                self.download_asnames()
            case "ribs":
                self.download_ribs()
            case "all":
                # asnames first: download_ribs() unconditionally loads
                # default_as_names_file into IpAsn(), which fails if it
                # doesn't exist yet.
                self.download_asnames()
                self.download_ribs()
            case _:
                self.parser.print_help()

    def download_asnames(self) -> None:
        print("Downloading latest AS names")
        names = self.downloader.fetch_asnames_as_json()
        fpath = self.default_as_names_file
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(names)
        print("Finished downloading")
        print("AS names file saved to:", fpath)

    def download_ribs(self) -> None:
        print("Downloading latest routes")
        fpath = self.default_db_file
        self.downloader.download_latest_rib_file(outfile=fpath)

        db = asinfo.ASInfo(fpath, self.default_as_names_file)
        p = pickle.dumps(db)
        pfpath = self.default_pickle_file
        with open(pfpath, "wb") as f:
            f.write(p)

        print("Finished downloading")
        print("ASN to prefix db file saved to:", fpath)

    def lookup(self, args: Namespace) -> None:
        with open(self.default_pickle_file, "rb") as f:
            db = pickle.loads(f.read())

        term_type = self.detect_term_type(args.term)
        match term_type:
            case "v4" | "v6":
                asn, prefix = db.lookup(args.term)
                print(f"{asn}, {prefix}")
            case "asn":
                term = int(args.term.lower().strip("as"))
                try:
                    name = db.get_as_name(term)
                except RuntimeError:
                    name = None
                if name:
                    print(f"AS{term}  {name}")
                for p in db.get_as_prefixes(term) or []:
                    print(p)
            case "name":
                try:
                    matches = db.find_asns_by_name(args.term)
                except RuntimeError:
                    print(
                        "AS names not loaded - run `asinfo download asnames` first.",
                        file=sys.stderr,
                    )
                    return
                if not matches:
                    print(f"No AS names matching {args.term!r}", file=sys.stderr)
                for asn, name in matches:
                    print(f"AS{asn}  {name}")

    def status(self, args: Namespace | None = None) -> None:
        print(self._format_age("ASN database", self.default_pickle_file))
        print(self._format_age("AS names", self.default_as_names_file))

    def _format_age(self, label: str, path: str) -> str:
        p = Path(path)
        if not p.exists():
            return f"{label}: not downloaded yet ({path})"
        mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=UTC)
        age = datetime.now(UTC) - mtime
        if age.days > 0:
            age_str = f"{age.days}d {age.seconds // 3600}h ago"
        elif age.seconds >= 3600:
            age_str = f"{age.seconds // 3600}h {(age.seconds % 3600) // 60}m ago"
        else:
            age_str = f"{age.seconds // 60}m ago"
        return f"{label}: {mtime.strftime('%Y-%m-%d %H:%M:%S UTC')} ({age_str}) - {path}"

    def detect_term_type(self, term: str) -> str:
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


def main() -> None:
    CLI().run()


if __name__ == "__main__":
    main()
