import json
import pickle
from argparse import Namespace
from pathlib import Path

import pytest

import asinfo
from asinfo import AsInfo
from asinfo.cli import cli as CLI
from asinfo.cli import main
from asinfo.downloader import Downloader

FAKE_DB_PATH = Path(__file__).parent / "data" / "ipasn.fake"


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Redirects the hardcoded ~/.asinfo/cache paths cli.py uses into a temp dir."""
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def cli_with_pickled_db(home):
    c = CLI()
    c.setup_local_dir_if_not_exist()
    db = AsInfo(str(FAKE_DB_PATH))
    with open(c.default_pickle_file, "wb") as f:
        pickle.dump(db, f)
    return c


@pytest.fixture
def cli_with_pickled_db_and_names(home, tmp_path):
    c = CLI()
    c.setup_local_dir_if_not_exist()
    names_file = tmp_path / "asnames.json"
    names_file.write_text(json.dumps({"1": "EXAMPLE-ONE-NET", "2": "EXAMPLE-TWO-NET"}))
    db = AsInfo(str(FAKE_DB_PATH), as_names_file=str(names_file))
    with open(c.default_pickle_file, "wb") as f:
        pickle.dump(db, f)
    return c


def test_help_shows_custom_metavar_choices(home, capsys):
    c = CLI()
    with pytest.raises(SystemExit):
        c.parser.parse_args(["download", "--help"])
    out = capsys.readouterr().out
    assert "ONE OF: asnames | ribs | all" in out


def test_default_paths(home):
    c = CLI()
    expected = str(home / ".asinfo" / "cache")
    assert c.default_path == expected
    assert c.default_as_names_file == expected + "/asnames"
    assert c.default_db_file == expected + "/asndb"
    assert c.default_pickle_file == expected + "/asndb_pickle"


def test_setup_local_dir_if_not_exist_creates_dir(home):
    c = CLI()
    assert not Path(c.default_path).exists()
    c.setup_local_dir_if_not_exist()
    assert Path(c.default_path).is_dir()


def test_setup_local_dir_if_not_exist_is_idempotent(home):
    c = CLI()
    c.setup_local_dir_if_not_exist()
    c.setup_local_dir_if_not_exist()  # should not raise
    assert Path(c.default_path).is_dir()


@pytest.mark.parametrize("term,expected", [
    ("8.8.8.8", "v4"),
    ("2001:4860:4860::8888", "v6"),
    ("AS15169", "asn"),
    ("as15169", "asn"),
    ("15169", "name"),  # bare numeric ASNs (no "AS" prefix) aren't recognized - known gap
    ("google", "name"),
])
def test_detect_term_type(home, term, expected):
    c = CLI()
    assert c.detect_term_type(term) == expected


def test_detect_term_type_as_substring_misclassifies_names(home):
    """Known bug: detect_term_type() checks `"as" in term`, a substring match,
    not a prefix match. A plain name containing "as" anywhere - like "fastly" -
    gets misclassified as an ASN instead of a name, and int()-parsing it in
    lookup()'s "asn" branch would raise ValueError."""
    c = CLI()
    assert c.detect_term_type("fastly") == "asn"


def test_process_no_args_prints_help(home, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["asinfo"])
    c = CLI()
    with pytest.raises(SystemExit):
        c.process()  # --help exits after printing (argparse's own behavior)
    out = capsys.readouterr().out
    assert "asinfo COMMAND [OPTIONS]" in out


def test_argparse_wiring_download(home):
    c = CLI()
    args = c.parser.parse_args(["download", "asnames"])
    assert args.command == "download"
    assert args.type == "asnames"
    assert args.func == c.download


def test_argparse_wiring_lookup(home):
    c = CLI()
    args = c.parser.parse_args(["lookup", "8.8.8.8"])
    assert args.command == "lookup"
    assert args.term == "8.8.8.8"
    assert args.func == c.lookup


def test_download_asnames_writes_file(home, monkeypatch):
    monkeypatch.setattr(Downloader, "download_asnames", lambda self: json.dumps({"15169": "GOOGLE"}))
    c = CLI()
    c.download(Namespace(type="asnames"))
    content = json.loads(Path(c.default_as_names_file).read_text())
    assert content == {"15169": "GOOGLE"}


def test_download_ribs_writes_pickle(home, monkeypatch):
    def fake_download_latest_rib_file(self, file_url=None, outfile=None):
        Path(outfile).write_bytes(FAKE_DB_PATH.read_bytes())

    monkeypatch.setattr(Downloader, "download_latest_rib_file", fake_download_latest_rib_file)
    c = CLI()
    c.setup_local_dir_if_not_exist()
    # download_ribs() unconditionally loads default_as_names_file - simulate
    # having already downloaded AS names (see the bug test below for what
    # happens without this).
    Path(c.default_as_names_file).write_text(json.dumps({"1": "TEST-AS"}))
    c.downloader = Downloader()

    c.download_ribs()

    assert Path(c.default_pickle_file).exists()
    with open(c.default_pickle_file, "rb") as f:
        db = pickle.loads(f.read())
    assert db.lookup("1.0.0.1") == (1, "1.0.0.0/30")


def test_download_ribs_crashes_without_prior_asnames_download(home, monkeypatch):
    """Known bug: download_ribs() always passes default_as_names_file to
    AsInfo(), which tries to open it unconditionally - crashes if `asinfo
    download ribs` is run before `asinfo download asnames` has ever run."""
    def fake_download_latest_rib_file(self, file_url=None, outfile=None):
        Path(outfile).write_bytes(FAKE_DB_PATH.read_bytes())

    monkeypatch.setattr(Downloader, "download_latest_rib_file", fake_download_latest_rib_file)
    c = CLI()
    c.setup_local_dir_if_not_exist()
    c.downloader = Downloader()

    with pytest.raises(FileNotFoundError):
        c.download_ribs()


def test_download_all_runs_asnames_before_ribs(home, monkeypatch):
    """`download all` must fetch asnames before ribs on a fresh cache dir -
    see the ordering fix in download()'s "all" case and the bug documented
    in test_download_ribs_crashes_without_prior_asnames_download."""
    monkeypatch.setattr(Downloader, "download_asnames", lambda self: json.dumps({"1": "TEST-AS"}))

    def fake_download_latest_rib_file(self, file_url=None, outfile=None):
        Path(outfile).write_bytes(FAKE_DB_PATH.read_bytes())

    monkeypatch.setattr(Downloader, "download_latest_rib_file", fake_download_latest_rib_file)

    c = CLI()
    c.download(Namespace(type="all"))  # must not raise

    assert Path(c.default_as_names_file).exists()
    assert Path(c.default_pickle_file).exists()


def test_lookup_v4(cli_with_pickled_db, capsys):
    cli_with_pickled_db.lookup(Namespace(term="1.0.0.1"))
    assert capsys.readouterr().out.strip() == "1, 1.0.0.0/30"


def test_lookup_asn_without_names_loaded(cli_with_pickled_db, capsys):
    """No AS-names file was loaded into this pickled db - lookup should
    still work, just without a name line."""
    cli_with_pickled_db.lookup(Namespace(term="AS1"))
    assert capsys.readouterr().out.strip() == "1.0.0.0/30"


def test_lookup_asn_unknown_does_not_crash(cli_with_pickled_db, capsys):
    """get_as_prefixes() returns None for an unknown ASN - lookup() must not
    try to iterate that directly."""
    cli_with_pickled_db.lookup(Namespace(term="AS999999"))
    assert capsys.readouterr().out == ""


def test_lookup_asn_shows_name_when_available(cli_with_pickled_db_and_names, capsys):
    cli_with_pickled_db_and_names.lookup(Namespace(term="AS1"))
    out = capsys.readouterr().out
    assert "AS1  EXAMPLE-ONE-NET" in out
    assert "1.0.0.0/30" in out


def test_lookup_name_finds_matches(cli_with_pickled_db_and_names, capsys):
    cli_with_pickled_db_and_names.lookup(Namespace(term="example-one"))
    assert "AS1  EXAMPLE-ONE-NET" in capsys.readouterr().out


def test_lookup_name_no_matches(cli_with_pickled_db_and_names, capsys):
    cli_with_pickled_db_and_names.lookup(Namespace(term="nonexistent-xyz"))
    assert "No AS names matching" in capsys.readouterr().err


def test_lookup_name_without_names_loaded(cli_with_pickled_db, capsys):
    cli_with_pickled_db.lookup(Namespace(term="google"))
    assert "AS names not loaded" in capsys.readouterr().err


def test_status_no_data_downloaded(home, capsys):
    c = CLI()
    c.status()
    out = capsys.readouterr().out
    assert "not downloaded yet" in out
    assert c.default_pickle_file in out
    assert c.default_as_names_file in out


def test_status_shows_age_after_download(home, capsys):
    c = CLI()
    c.setup_local_dir_if_not_exist()
    Path(c.default_pickle_file).write_bytes(b"fake")
    Path(c.default_as_names_file).write_text("{}")

    c.status()

    out = capsys.readouterr().out
    assert "ASN database:" in out
    assert "AS names:" in out
    assert "ago)" in out


def test_argparse_wiring_status(home):
    c = CLI()
    args = c.parser.parse_args(["status"])
    assert args.command == "status"
    assert args.func == c.status


def test_version_flag(home, capsys):
    c = CLI()
    with pytest.raises(SystemExit):
        c.parser.parse_args(["--version"])
    assert capsys.readouterr().out.strip() == f"asinfo {asinfo.__version__}"


def test_main_invokes_process(monkeypatch):
    called = []
    monkeypatch.setattr(CLI, "process", lambda self: called.append(True))
    main()
    assert called == [True]
