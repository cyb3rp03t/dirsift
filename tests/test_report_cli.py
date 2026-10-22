"""``dirsift report`` and ``dirsift scan -o``: the report from the command line."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_cli import saved_run
from typer.testing import CliRunner

from dirsift import cli
from dirsift import report_text as T
from dirsift.models import ScanResult

runner = CliRunner()


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setenv("DIRSIFT_NO_BANNER", "1")
    monkeypatch.setenv("COLUMNS", "200")


def sidecar(run: Path, **fields) -> Path:
    path = run.parent / "assessments" / run.name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": 1, "revision": 1, **fields}), encoding="utf-8")
    return path


def test_help_shows_the_report_flags_and_hides_the_old_one():
    reply = runner.invoke(cli.app, ["report", "--help"])
    assert reply.exit_code == 0
    for flag in ("--out", "--tlp", "--author", "--assessment", "--logo"):
        assert flag in reply.stdout
    for gone in ("--scaffold", "--format", "--theme", "--max-rows"):
        assert gone not in reply.stdout


def test_without_out_the_markdown_goes_to_stdout(tmp_path: Path):
    reply = runner.invoke(cli.app, ["report", str(saved_run(tmp_path))])
    assert reply.exit_code == 0
    assert reply.stdout.startswith("**TLP:AMBER**")
    assert T.TLP_NOT_SET in reply.stderr


def test_an_unknown_extension_names_the_two_that_work(tmp_path: Path):
    reply = runner.invoke(cli.app, ["report", str(saved_run(tmp_path)), "-o",
                                    str(tmp_path / "x.txt")])
    assert reply.exit_code == 2
    assert ".md" in reply.stderr and ".pdf" in reply.stderr
    assert not (tmp_path / "x.txt").exists()


def test_there_is_no_format_flag(tmp_path: Path):
    reply = runner.invoke(cli.app, ["report", str(saved_run(tmp_path)), "--format", "pdf"])
    assert reply.exit_code == 2


def test_the_extension_picks_pdf(tmp_path: Path):
    out = tmp_path / "r.pdf"
    reply = runner.invoke(cli.app, ["report", str(saved_run(tmp_path)), "-o", str(out)])
    assert reply.exit_code == 0, reply.stderr
    assert out.read_bytes().startswith(b"%PDF-")


def test_the_old_scaffold_flag_warns_and_changes_nothing(tmp_path: Path):
    run = saved_run(tmp_path)
    plain = runner.invoke(cli.app, ["report", str(run)])
    flagged = runner.invoke(cli.app, ["report", str(run), "--no-scaffold"])
    assert flagged.exit_code == 0
    assert "scaffold" in flagged.stderr
    assert "scaffold" not in plain.stderr
    strip = [line for line in plain.stdout.splitlines() if "Generated" not in line]
    again = [line for line in flagged.stdout.splitlines() if "Generated" not in line]
    assert strip == again


def test_a_saved_red_tlp_opens_and_closes_the_file(tmp_path: Path):
    run = saved_run(tmp_path)
    sidecar(run, tlp="RED")
    out = tmp_path / "x.md"
    reply = runner.invoke(cli.app, ["report", str(run), "-o", str(out)])
    assert reply.exit_code == 0
    lines = out.read_text(encoding="utf-8").rstrip().splitlines()
    assert lines[0].startswith("**TLP:RED**") and lines[-1].startswith("**TLP:RED**")
    assert T.TLP_NOT_SET not in reply.stderr


def test_a_looser_tlp_than_the_saved_one_warns(tmp_path: Path):
    run = saved_run(tmp_path)
    sidecar(run, tlp="RED")
    reply = runner.invoke(cli.app, ["report", str(run), "--tlp", "green"])
    assert reply.exit_code == 0
    assert T.TLP_DOWNGRADE.format(choice="GREEN", saved="RED") in " ".join(reply.stderr.split())
    assert reply.stdout.startswith("**TLP:GREEN**")


@pytest.mark.parametrize("label", ["amber+strict", "TLP:AMBER+STRICT", "Amber+Strict"])
def test_the_tlp_label_is_read_loosely(tmp_path: Path, label):
    reply = runner.invoke(cli.app, ["report", str(saved_run(tmp_path)), "--tlp", label])
    assert reply.exit_code == 0
    assert reply.stdout.startswith("**TLP:AMBER+STRICT**")


def test_an_unknown_tlp_is_refused(tmp_path: Path):
    reply = runner.invoke(cli.app, ["report", str(saved_run(tmp_path)), "--tlp", "purple"])
    assert reply.exit_code == 2
    assert T.TLP_UNKNOWN in " ".join(reply.stderr.split())


def test_a_broken_assessment_names_the_field(tmp_path: Path):
    run = saved_run(tmp_path)
    sidecar(run, confidence="Certain")
    reply = runner.invoke(cli.app, ["report", str(run)])
    assert reply.exit_code == 1
    assert "confidence" in reply.stderr


def test_the_author_flag_overrides_and_is_not_saved(tmp_path: Path):
    run = saved_run(tmp_path)
    path = sidecar(run, author="Saved Name", assessment="Suspicious", confidence="Low")
    before = path.read_bytes()
    reply = runner.invoke(cli.app, ["report", str(run), "--author", "Other Name"])
    assert reply.exit_code == 0
    assert "Other Name" in reply.stdout and "Saved Name" not in reply.stdout
    assert path.read_bytes() == before


def test_an_assessment_file_can_be_named(tmp_path: Path):
    run = saved_run(tmp_path)
    elsewhere = tmp_path / "mine.json"
    elsewhere.write_text(json.dumps({"schema": 1, "found_via": "a feed"}), encoding="utf-8")
    reply = runner.invoke(cli.app, ["report", str(run), "--assessment", str(elsewhere)])
    assert reply.exit_code == 0
    assert "**Found via:** a feed" in reply.stdout
    missing = runner.invoke(cli.app, ["report", str(run), "--assessment",
                                      str(tmp_path / "none.json")])
    assert missing.exit_code == 1


def test_logo_none_leaves_the_image_out(tmp_path: Path):
    reply = runner.invoke(cli.app, ["report", str(saved_run(tmp_path)), "--logo", "none"])
    assert reply.exit_code == 0
    assert "<img" not in reply.stdout
    bad = runner.invoke(cli.app, ["report", str(saved_run(tmp_path)), "--logo", "file"])
    assert bad.exit_code == 2


@pytest.mark.parametrize("name", ["x.pdf", "x.md"])
def test_scan_writes_the_report_and_says_the_run_was_not_saved(tmp_path, monkeypatch, name):
    monkeypatch.setattr(cli, "scan", lambda url, options: ScanResult(root_url=url))
    out = tmp_path / name
    reply = runner.invoke(cli.app, ["scan", "http://203.0.113.24/files/", "-o", str(out)])
    assert reply.exit_code == 0, reply.stderr
    assert out.exists()
    if name.endswith(".md"):
        assert "| Run | run not saved |" in out.read_text(encoding="utf-8")


def test_scan_checks_the_extension_before_it_walks(tmp_path, monkeypatch):
    walked = []
    monkeypatch.setattr(cli, "scan", lambda url, options: walked.append(url))
    reply = runner.invoke(cli.app, ["scan", "http://203.0.113.24/files/", "-o",
                                    str(tmp_path / "x.txt")])
    assert reply.exit_code == 2
    assert walked == []


def test_scan_with_json_names_the_saved_run(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda url, options: ScanResult(root_url=url))
    out, run = tmp_path / "x.md", tmp_path / "runs" / "one.json"
    reply = runner.invoke(cli.app, ["scan", "http://203.0.113.24/files/", "-o", str(out),
                                    "--json", str(run)])
    assert reply.exit_code == 0, reply.stderr
    assert "| Run | `one` |" in out.read_text(encoding="utf-8")
