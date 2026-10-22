"""The triage report model and its Markdown rendering.

The runs come from fixtures other tests already hold: the detections fixture
(every indicator type, a secret, a wallet shaped value, a shared host) and the
leak oracle's run (real file text through the real extractor, many secrets).
An empty run and a run that ended on HTTP 499 cover the edges.
"""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime

import pytest
from test_detections import LIVE, ROOT, STARTED, fixture_result
from test_leak_oracle import leak_result, leaks

from dirsift import report_text as T
from dirsift.analyze import analyze
from dirsift.extract import SecretPieces, defang, secret_shown
from dirsift.models import ScanError, ScanResult
from dirsift.report import LOGO_DATA_URI, render_markdown
from dirsift.report_logo import FAVICON_SVG_INLINE
from dirsift.report_model import (
    AssessmentEmpty,
    ReportOptions,
    build_report,
    report_id,
)

GENERATED = datetime(2026, 10, 22, 18, 10, 4, tzinfo=UTC)
VERSION = "0.1.0"

#: The logo as the Markdown report carries it. Held here so that a change to
#: the drawing or its encoding is a deliberate change to this line.
LOGO_B64 = (
    "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiIgd2lkdGg9"
    "IjE2IiBoZWlnaHQ9IjE2IiByb2xlPSJpbWciIGFyaWEtbGFiZWw9IkRpclNpZnQiPiA8dGl0bGU+RGlyU2lmdDwv"
    "dGl0bGU+IDxzdHlsZT4ua3tmaWxsOiMwNzBiMTJ9LmF7ZmlsbDojMGE3YWFifSBAbWVkaWEgKHByZWZlcnMtY29s"
    "b3Itc2NoZW1lOiBkYXJrKXsua3tmaWxsOiNlOWVlZmF9LmF7ZmlsbDojNTZjN2YyfX08L3N0eWxlPiA8cGF0aCBj"
    "bGFzcz0iayIgZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMSAxaDExbDMgM3YxaC0ybC0yLTJIM3Y0aDEydjVsLTMg"
    "M0gxdi00aDJ2Mmg4bDItMlY5SDF6Ii8+IDxwYXRoIGNsYXNzPSJhIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0z"
    "IDdoMTB2MkgzeiIvPiA8L3N2Zz4="
)


def report_of(result: ScanResult, candidates=None, assessment=None, **opts):
    options = ReportOptions(**{"version": VERSION, **opts})
    return build_report(result, candidates or [], options, assessment, GENERATED,
                        "0" * 64 if opts.get("run_name") else None)


def detections_result() -> ScanResult:
    """The detections fixture, its defanged forms written the way the extractor writes them."""
    result = fixture_result()
    for i in result.iocs:
        i.defanged = defang(i.value)
    return result


def detections_report(**kw):
    return report_of(detections_result(), run_name="golden-run", **kw)


def leak_report(**kw):
    result, candidates = analyze(leak_result())
    return report_of(result, candidates, run_name="leak-run", **kw)


def empty_report():
    return report_of(ScanResult(root_url=ROOT, started_at=STARTED), run_name="empty")


def refused_report():
    result = ScanResult(
        root_url=ROOT,
        started_at=STARTED,
        errors=[ScanError(url=ROOT, stage="walk", detail="HTTP 499")],
    )
    return report_of(result, run_name="ended-499")


ALL = {
    "detections": detections_report,
    "leak": leak_report,
    "empty": empty_report,
    "refused": refused_report,
}


# Gates every rendering must pass

_CODE_BLOCK = re.compile(r"```.*?```", re.S)
_CODE_SPAN = re.compile(r"``.+?``|`[^`]*`")
_IMG = re.compile(r"<img[^>]*>")
_DOUBLE_HYPHEN = re.compile(r"(?<![-\w])--(?![-\w])|\w--\w")
_LIVE_SHAPE = re.compile(
    r"\bhttps?://|\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\b[a-z0-9-]+\.(?:com|net|org|io|dev|fun|live|host|co|top|xyz)\b",
    re.I,
)


def own_text(markdown: str) -> str:
    """The parts of a rendering DirSift wrote itself: no code, no data values, no logo."""
    text = _CODE_BLOCK.sub("", markdown)
    text = _CODE_SPAN.sub("", text)
    return _IMG.sub("", text)


def forbidden_hits(text: str) -> list[str]:
    for phrase in T.FORBIDDEN_ALLOWED:
        text = text.replace(phrase, "")
    return [w for w in T.FORBIDDEN_WORDS if re.search(rf"\b{w}\b", text, re.I)]


EM_DASH, EN_DASH = chr(0x2014), chr(0x2013)


def punctuation_hits(text: str) -> list[str]:
    out = []
    if EM_DASH in text:
        out.append("em dash")
    if EN_DASH in text:
        out.append("en dash")
    if _DOUBLE_HYPHEN.search(text):
        out.append("double hyphen")
    return out


def live_hits(text: str, allowed: frozenset[str] = frozenset()) -> list[str]:
    text = text.replace(LOGO_DATA_URI, "")
    for path in sorted(allowed, key=len, reverse=True):
        text = text.replace(path, "")
    return sorted({m.group(0) for m in _LIVE_SHAPE.finditer(text)})


def secret_hits(text: str, result: ScanResult) -> list[str]:
    """Eight character pieces of long secrets; secrets under eight only as a whole token.

    A secret's shown form (type, a public prefix, length, fingerprint) is the
    form every output uses and has its own tests, so it is taken out first.
    """
    text = re.sub(r"\s+", "", text)  # a PDF line break may fall inside a shown form
    for ioc in result.iocs:
        if ioc.ioc_type == "secret":
            text = text.replace(re.sub(r"\s+", "", secret_shown(ioc)), "")
    pieces = SecretPieces(result.iocs)
    found = [text[i:i + 8] for i in range(len(text) - 7) if text[i:i + 8] in pieces.pieces]
    for short in pieces.short:
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(short)}(?![A-Za-z0-9_])", text):
            found.append(short)
    return found


# Report ID


def test_the_report_id_test_vector():
    started = datetime(2026, 9, 16, 11, 59, 16, 244131, tzinfo=UTC)
    assert report_id("http://203.0.113.10/", started) == "DSR-20260916-115916-af71"


def test_the_report_id_does_not_move_with_the_generation_time():
    one = report_of(detections_result())
    two = build_report(detections_result(), [], ReportOptions(version=VERSION), None,
                       datetime(2030, 1, 1, tzinfo=UTC))
    assert one.report_id == two.report_id


# Markdown shape


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_first_and_last_lines_carry_the_tlp_and_the_second_the_logo(make):
    markdown = render_markdown(make())
    lines = markdown.rstrip("\n").splitlines()
    assert lines[0].startswith("**TLP:AMBER** · " + T.TLP_DEFINITIONS["AMBER"])
    assert lines[2].startswith(f'<img src="{LOGO_DATA_URI}"')
    assert "**DirSift**" in lines[2]
    assert lines[-1].startswith("**TLP:AMBER** · Report `DSR-")
    assert lines[-1].endswith(f"Generated by DirSift {VERSION}")


def test_the_logo_data_uri_is_the_fixed_string():
    assert LOGO_DATA_URI == "data:image/svg+xml;base64," + LOGO_B64
    assert base64.b64decode(LOGO_B64).decode() == FAVICON_SVG_INLINE


def test_logo_none_leaves_the_image_out_and_keeps_the_name():
    markdown = render_markdown(detections_report(), logo="none")
    assert "<img" not in markdown
    assert markdown.splitlines()[2] == "**DirSift** · " + T.REPORT_KIND


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_no_scaffold_and_no_html_comment(make):
    markdown = render_markdown(make())
    assert "Writeup scaffold" not in markdown
    assert "<!--" not in markdown


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_twelve_sections_and_three_appendices_in_order(make):
    report = make()
    numbers = [s.number for s in report.sections]
    assert numbers == [str(n) for n in range(1, 13)] + ["A", "B", "C"]
    markdown = render_markdown(report)
    heads = re.findall(r"^## (.+)$", markdown, re.M)
    assert heads[0] == "Contents"
    assert len(heads) == 16


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_no_heading_is_left_empty(make):
    """Every heading is followed by text, or opens straight into a subsection."""
    parts = re.split(r"^(#{2,3}) .*$", render_markdown(make()), flags=re.M)[1:]
    levels, bodies = parts[0::2], parts[1::2]
    for n, (level, body) in enumerate(zip(levels, bodies, strict=True)):
        deeper = n + 1 < len(levels) and len(levels[n + 1]) > len(level)
        assert body.strip() or deeper


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_the_summary_stays_under_150_words(make):
    assert make().summary_words < 150


# Gates


def test_the_catalogue_carries_no_forbidden_word_em_dash_or_double_hyphen():
    skip = {"FORBIDDEN_WORDS", "FORBIDDEN_ALLOWED", "ICD203_SCALE"}  # analyst help text
    texts = []
    for name, value in vars(T).items():
        if name.startswith("_") or name in skip:
            continue
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, dict):
            texts += [str(k) for k in value] + [str(v) for v in value.values()]
        elif isinstance(value, tuple):
            texts += [str(v) for v in value]
    joined = "\n".join(texts)
    assert forbidden_hits(_CODE_SPAN.sub("", joined)) == []
    assert punctuation_hits(_CODE_SPAN.sub("", joined)) == []


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_the_rendering_carries_no_forbidden_word(make):
    assert forbidden_hits(own_text(render_markdown(make()))) == []


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_the_rendering_carries_no_em_dash_or_double_hyphen(make):
    assert punctuation_hits(own_text(render_markdown(make()))) == []


def test_no_live_value_in_the_markdown():
    for make in ALL.values():
        report = make()
        assert live_hits(render_markdown(report), report.listing_paths) == []
    markdown = render_markdown(detections_report())
    for value in LIVE:
        assert value not in markdown


def test_no_piece_of_a_secret_in_the_markdown():
    result, candidates = analyze(leak_result())
    markdown = render_markdown(report_of(result, candidates, run_name="leak-run"))
    assert leaks(markdown) == []
    assert secret_hits(markdown, result) == []
    detections = detections_result()
    assert secret_hits(render_markdown(report_of(detections)), detections) == []


def test_a_wallet_shaped_value_that_fails_its_checksum_is_masked_everywhere():
    result = detections_result()
    wallet = next(i.value for i in result.iocs if i.ioc_type == "btc")
    markdown = render_markdown(report_of(result))
    # this one is a valid address, so it is shown defanged as a value
    assert "Bitcoin-shaped" in markdown
    broken = detections_result()
    for i in broken.iocs:
        if i.ioc_type == "btc":
            i.value = i.defanged = wallet[:-1] + ("x" if wallet[-1] != "x" else "y")
    text = render_markdown(report_of(broken))
    assert wallet[:-1] not in text
    assert "bitcoin_shaped" in text
    assert T.NOTE_B58 in text


# Rules: signals and labels, each with a case that fires and one that does not


def notes_of(report, value: str) -> str:
    markdown = render_markdown(report)
    rows = [line for line in markdown.splitlines() if value in line and line.startswith("|")]
    return " ".join(rows)


def notes_for(result: ScanResult, value: str) -> list[str]:
    from dirsift.report_model import ReportOptions, _Builder

    builder = _Builder(result, [], ReportOptions(), {}, GENERATED, "0" * 64, ())
    return builder.notes(next(i for i in result.iocs if i.value == value))


def test_the_target_itself_and_its_port_are_labelled():
    result = detections_result()
    result.target_ip = "203.0.113.9"
    assert notes_for(result, "203.0.113.9:4444")[:2] == [T.NOTE_TARGET, "port 4444"]
    assert T.NOTE_TARGET not in notes_for(detections_result(), "203.0.113.9:4444")


def test_a_network_base_address_and_a_log_only_address():
    result = detections_result()
    result.iocs[1].value = "198.51.0.0"
    assert T.NOTE_BASE in notes_for(result, "198.51.0.0")
    result.entries[0].url = ROOT + "access.log"
    result.entries[0].name = "access.log"
    for i in result.iocs:
        i.sources = [ROOT + "access.log" if u.endswith("loader.sh") else u for u in i.sources]
        i.source_url = i.sources[0]
    assert T.NOTE_FROM_LOGS in notes_for(result, "cdn.panel-gate.xyz")
    assert T.NOTE_FROM_LOGS not in notes_for(detections_result(), "cdn.panel-gate.xyz")


def test_shared_hosting_and_protocol_identifier_labels():
    markdown = render_markdown(report_of(detections_result()))
    assert "on shared hosting (`githubusercontent[.]com`)" in markdown
    assert "protocol identifiers (`@libssh[.]org`), not mailboxes" in markdown
    result = detections_result()
    result.iocs = [i for i in result.iocs if "githubusercontent" not in i.value
                   and "libssh" not in i.value]
    markdown = render_markdown(report_of(result))
    assert "on shared hosting" not in markdown
    assert "protocol identifier" not in markdown


def test_a_resolver_is_left_out_of_most_useful_first():
    markdown = render_markdown(report_of(detections_result()))
    most = markdown.split("### Most useful first", 1)[1].split("## 9.", 1)[0]
    assert "8[.]8[.]8[.]8" not in most
    assert "public resolver" in markdown.split("### Most useful first", 1)[0]


def test_key_material_and_names_list_signals():
    result = detections_result()
    result.entries[3].name = "id_rsa"
    result.entries[3].url = ROOT + "id_rsa"
    markdown = render_markdown(report_of(result))
    assert T.SIGNAL_KEY in markdown
    assert T.SIGNAL_NAMES in markdown
    assert T.SIGNAL_KEY not in render_markdown(report_of(detections_result()))


def test_identical_content_signal_needs_two_whole_non_empty_files():
    result = detections_result()
    result.entries[2].sha256 = result.entries[0].sha256
    result.entries[2].truncated = False
    assert "identical SHA256: same content under 2 names" in render_markdown(report_of(result))
    assert "identical SHA256" not in render_markdown(report_of(detections_result()))


def test_an_executable_with_no_extension_is_a_signal():
    result = detections_result()
    result.entries[2].name = "payload"
    result.entries[2].url = ROOT + "bin/payload"
    assert T.SIGNAL_NOEXT in render_markdown(report_of(result))
    assert T.SIGNAL_NOEXT not in render_markdown(report_of(detections_result()))


def test_home_dot_files_need_two_in_one_folder():
    result = detections_result()
    for e, name in zip(result.entries[1:3], (".bashrc", ".profile"), strict=True):
        e.name, e.url, e.parent_url = name, ROOT + name, ROOT
    assert T.SIGNAL_HOME in render_markdown(report_of(result))
    result.entries[2].name = "plain.txt"
    assert T.SIGNAL_HOME not in render_markdown(report_of(result))


def test_the_secret_is_masked_and_counted():
    markdown = render_markdown(report_of(detections_result()))
    assert T.TYPE_SECRET_NOTE in markdown
    assert "Rotate the credentials found in `loader.sh`" in markdown


# Edges


def test_an_empty_run_writes_a_sentence_in_every_section():
    report = empty_report()
    markdown = render_markdown(report)
    assert T.NOTHING_LISTED in markdown
    assert T.NO_INDICATORS in markdown
    assert T.HASHES_NONE in markdown
    assert T.VT_NONE in markdown
    assert T.NO_CANDIDATES in markdown
    assert T.NO_NOTES in markdown
    assert T.NOTE_NETWORK_NONE in markdown
    assert isinstance(report.sections[2].blocks[0], AssessmentEmpty)


def test_a_run_that_ended_on_499_never_says_refused_or_stopped_listing():
    markdown = render_markdown(refused_report())
    assert "HTTP 499" in markdown
    assert "stopped listing" not in markdown
    assert "refused" not in markdown.lower()


def test_a_later_run_that_could_not_list_the_root_is_named():
    first = detections_result()
    later = ScanResult(root_url=ROOT, started_at=datetime(2026, 10, 3, tzinfo=UTC),
                       errors=[ScanError(url=ROOT, stage="walk", detail="HTTP 499")])
    report = build_report(first, [], ReportOptions(run_name="golden-run", version=VERSION),
                          None, GENERATED, "0" * 64, [("golden-run", first), ("later", later)])
    markdown = render_markdown(report)
    assert "A later run on 2026-10-03 could not list the root (HTTP 499)." in markdown
    assert "run `later` on 2026-10-03 could not list the root (HTTP 499)" in markdown


def test_amber_strict_adds_the_detections_warning():
    markdown = render_markdown(detections_report(tlp="AMBER+STRICT"))
    assert T.STRICT_WARNING in markdown
    assert markdown.startswith("**TLP:AMBER+STRICT**")
    assert T.STRICT_WARNING not in render_markdown(detections_report())


def test_an_unsaved_scan_says_so():
    markdown = render_markdown(report_of(detections_result()))
    assert "| Run | run not saved |" in markdown
    assert "(run not saved)" in markdown


# A filled assessment

FILLED = {
    "schema": 1,
    "revision": 2,
    "run_sha256": "1" * 64,
    "tlp": "RED",
    "author": "Analyst One",
    "status": "Final",
    "assessment": "Suspicious",
    "confidence": "Moderate",
    "priority": "Medium",
    "bottom_line": "Staging host.",
    "rationale": "The loader fetches from http://198.51.100.7/x and runs it.",
    "attribution": "None asserted",
    "found_via": "A listing title search, 2026-09-16.",
    "alternatives": [{"explanation": T.ALTERNATIVES[4], "status": "Ruled out",
                      "reason": "The scripts fetch from this address directly."}],
    "attack": [{"tactic": "Command and Control", "technique": "Ingress Tool Transfer",
                "id": "T1105", "evidence": "loader.sh"}],
    "attack_version": "v18",
    "history": [{"version": "1.1", "at": "2026-10-22T18:20:00Z", "by": "Analyst One",
                 "fields": ["assessment"]},
                {"version": "1.2", "at": "2026-10-22T18:31:00Z", "by": "Analyst One",
                 "fields": ["bottom_line"]}],
}


def test_a_filled_assessment_is_defanged_and_versioned():
    report = detections_report(assessment=FILLED, tlp="RED")
    markdown = render_markdown(report)
    assert "hxxp://198[.]51[.]100[.]7/x" in markdown
    assert "http://198.51.100.7" not in markdown
    assert report.version == "1.2"
    assert "Final, reviewed by Analyst One." in markdown
    assert "Ruled out: The scripts fetch from this address directly." in markdown
    assert "Ingress Tool Transfer (T1105)" in markdown and "version v18" in markdown
    assert "**Found via:** A listing title search" in markdown
    assert T.CHANGELOG_SHA_DIFFERS in markdown
    assert report.review_line == "Reviewed by Analyst One"


def test_the_author_option_overrides_the_file():
    report = detections_report(assessment=FILLED, author="Someone Else")
    assert "Final, reviewed by Someone Else." in render_markdown(report)


def test_a_url_outside_the_root_and_a_scan_note_are_defanged():
    """Found on real runs: a listed entry on another host, and a note quoting a URL."""
    result = detections_result()
    result.entries.append(result.entries[0].model_copy(
        update={"url": "https://other.example/x/", "name": "x", "is_dir": True}))
    result.errors.append(ScanError(url=ROOT, stage="walk",
                                   detail="ScopeError: out of scope: https://other.example/"))
    result.title = "Index of http://other.example/"
    markdown = render_markdown(report_of(result))
    assert "https://other.example" not in markdown and "http://other.example" not in markdown
    assert "hxxps://other[.]example/x/" in markdown
    assert "out of scope: hxxps://other[.]example/" in markdown


# Analyst free text must not reach a Markdown viewer as active content.

HOSTILE = {
    **FILLED,
    "bottom_line": "<script>alert(1)</script> and a [link](javascript:alert(1))",
    "rationale": "<img src=x onerror=alert(1)> near evil[.]example[.]com",
    "attribution": "![](http://198.51.100.9/pixel.png) & more",
    "found_via": "<b>bold</b> title",
    "author": "A<script>B",
    "references": ["<a href='javascript:alert(1)'>x</a>", "see [here](javascript:void)"],
}


def test_analyst_text_is_escaped_in_the_markdown_report():
    report = detections_report(assessment=HOSTILE, tlp="RED")
    markdown = render_markdown(report, logo="none")  # the logo is the only real <img>
    # No raw HTML tag survives: the angle brackets become entities.
    assert "<script>" not in markdown and "</script>" not in markdown
    assert "<img" not in markdown and "<a href" not in markdown
    assert "&lt;script&gt;" in markdown and "&lt;img" in markdown
    # No inline link or image can carry a scheme: the parenthesis after ] is broken.
    assert "](javascript:" not in markdown
    assert "](http://" not in markdown
    assert r"]\(javascript:" in markdown
    # A defanged indicator inside analyst text is left readable.
    assert "evil[.]example[.]com" in markdown
    # The catalogue's own formatting is untouched.
    assert "**Found via:**" in markdown


# The change log reads in time order; the status does not deny a review.

def changelog_rows(markdown: str) -> list[list[str]]:
    part = markdown.split("## Appendix C.", 1)[1]
    return [[c.strip() for c in line.strip("|").split("|")]
            for line in part.splitlines()
            if line.startswith("| ") and "Version" not in line and ":-" not in line]


def test_the_change_log_lists_analyst_edits_first_and_the_generation_last():
    rows = changelog_rows(render_markdown(detections_report(assessment=FILLED, tlp="RED")))
    versions = [r[0] for r in rows]
    assert versions[:2] == ["1.1", "1.2"]
    generated = next(r for r in rows if r[2].startswith("DirSift") and "Generated" in r[3])
    assert rows.index(generated) > 1  # after the analyst's rows
    assert generated[0] == "1.2" and "version 1.2" in generated[3]


def test_a_report_without_edits_keeps_its_single_generation_row():
    rows = changelog_rows(render_markdown(detections_report()))
    assert len(rows) == 1 and rows[0][0] == "1.0"
    assert rows[0][3] == T.CHANGELOG_GENERATED.format(name="`golden-run`")


def test_a_preliminary_status_does_not_say_nobody_reviewed_it():
    markdown = render_markdown(detections_report(assessment={**FILLED, "status": "Preliminary"}))
    assert "No analyst has reviewed" not in markdown
    assert T.STATUS_PRELIMINARY in markdown
