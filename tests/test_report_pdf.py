"""The PDF rendering: page rules, a closed document, the two faces, the same bytes.

The runs are the same fixtures the Markdown tests use. Text is read back
with pypdf, so the checks see what a reader's copy and paste would see.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import time

import pytest
from pypdf import PdfReader
from pypdf.generic import IndirectObject
from test_leak_oracle import leak_result, leaks
from test_report import (
    ALL,
    FILLED,
    detections_report,
    detections_result,
    forbidden_hits,
    leak_report,
    live_hits,
    punctuation_hits,
    report_of,
    secret_hits,
)

from dirsift import report_text as T
from dirsift.analyze import analyze
from dirsift.models import Entry
from dirsift.report import render_markdown
from dirsift.report_pdf import MARGIN_BOTTOM, MISSING_GLYPH, drawable, escape, render_pdf

#: SHA256 of the detections fixture's PDF, fixed date and version. The same on
#: Windows and Linux. A ReportLab upgrade or a deliberate layout change moves
#: it: check the pages, then update this line on purpose (DIRSIFT_UPDATE_GOLDEN=1
#: prints the new value).
GOLDEN_SHA256 = "dbdd7f8013f0c033d0e927129a90da468bef223016164b7822cc5983b072f85a"

ACTIVE = re.compile(
    rb"/(URI|Annots|JavaScript|JS|Launch|OpenAction|AcroForm|EmbeddedFiles?|AA|RichMedia"
    rb"|GoToR|GoToE|SubmitForm|ImportData|XFA)\b"
)
FACES = re.compile(r"/[A-Z]{6}\+(IBMPlexSans|IBMPlexSans-SmBld|JetBrainsMono-Regular|"
                   r"JetBrainsMono-Bold)$")


@pytest.fixture(scope="module")
def pdf() -> bytes:
    return render_pdf(detections_report())


def pages_text(data: bytes) -> list[str]:
    return [page.extract_text() or "" for page in PdfReader(io.BytesIO(data)).pages]


def flat(text: str) -> str:
    return re.sub(r"\s+", "", text)


def walk(obj, seen: set, found: list) -> None:
    """Every key of every dictionary reachable from ``obj``."""
    if isinstance(obj, IndirectObject):
        key = (obj.idnum, obj.generation)
        if key in seen:
            return
        seen.add(key)
        obj = obj.get_object()
    if hasattr(obj, "keys"):
        for k in obj.keys():
            found.append(str(k))
            walk(obj[k] if not isinstance(obj.get(k), IndirectObject) else obj.get(k), seen,
                 found)
    elif isinstance(obj, list):
        for item in obj:
            walk(item, seen, found)


def test_page_two_holds_the_summary_and_the_key_facts(pdf):
    pages = pages_text(pdf)
    assert "Executive summary" in pages[1] and "Key facts" in pages[1]
    assert any("Analyst assessment" in p for p in pages[1:3])


def body_rows(data: bytes) -> list[dict[float, str]]:
    """Per page, the body text (above the footer band) as {height: row text}."""
    out = []
    for page in PdfReader(io.BytesIO(data)).pages:
        rows: dict = {}

        def visit(text, cm, tm, font, size, rows=rows):
            if text.strip():
                rows.setdefault(round(tm[5] * cm[3] + cm[5], 1), []).append(text)

        page.extract_text(visitor_text=visit)
        out.append({y: "".join(t) for y, t in rows.items() if y > MARGIN_BOTTOM + 2})
    return out


def heading_forms(section) -> set[str]:
    """A heading row: the number and the title, with or without the reader
    label. A contents row adds a page number after the label, so it is not one."""
    h = flat((f"Appendix {section.number}" if section.appendix else section.number)
             + section.title)
    return {h, h + flat(section.reader_label), h + flat(section.reader_label).upper()}


def heading_pages(report, data: bytes) -> dict[str, int | None]:
    """The page each section heading is drawn on, by section key."""
    pages = body_rows(data)
    return {s.key: next((n for n, rows in enumerate(pages, 1)
                         if any(flat(r) in heading_forms(s) for r in rows.values())), None)
            for s in report.sections}


def orphaned_headings(report, data: bytes) -> list[tuple[int, str]]:
    """Pages, but the last, whose lowest body line is a section heading."""
    heads = set().union(*(heading_forms(s) for s in report.sections))
    out = []
    for n, rows in enumerate(body_rows(data)[:-1], 1):
        if rows and flat(rows[min(rows)]) in heads:
            out.append((n, rows[min(rows)]))
    return out


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_the_summary_and_key_facts_open_page_two_and_the_assessment_follows(make):
    """Template 9.1: page two holds the contents, the summary and the key facts;
    the analyst assessment follows on page two or opens page three. Keeping a
    heading with its box must not push a section onto a page of its own."""
    report = make()
    at = heading_pages(report, render_pdf(report))
    assert at["summary"] == 2 and at["facts"] == 2, at
    assert at["assessment"] in (2, 3), at


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_no_page_ends_with_a_section_heading(make):
    report = make()
    assert orphaned_headings(report, render_pdf(report)) == []


@pytest.mark.parametrize("make", [lambda: detections_report(),
                                  lambda: detections_report(assessment=FILLED, tlp="RED")],
                         ids=["empty", "filled"])
def test_the_analyst_assessment_heading_is_never_orphaned(make):
    """The section heading and its box share a page, with the box empty or filled."""
    report = make()
    data = render_pdf(report)
    assert orphaned_headings(report, data) == []
    assert heading_pages(report, data)["assessment"] in (2, 3)


def test_document_control_is_on_the_cover_only(pdf):
    pages = pages_text(pdf)
    assert [n for n, p in enumerate(pages, 1) if "Run file SHA256" in p] == [1]


@pytest.mark.parametrize("make", ALL.values(), ids=ALL.keys())
def test_every_page_carries_two_tlp_labels_and_the_name(make):
    report = make()
    for n, text in enumerate(pages_text(render_pdf(report)), 1):
        assert flat(text).count(report.tlp_label) >= 2, n
        assert "DirSift" in text, n


def test_pages_are_numbered_out_of_the_total(pdf):
    pages = pages_text(pdf)
    total = len(pages)
    for n, text in enumerate(pages[1:], 2):
        assert f"Page{n}/{total}" in flat(text)


def test_the_document_has_no_active_content(pdf):
    assert ACTIVE.findall(pdf) == []
    reader = PdfReader(io.BytesIO(pdf))
    keys: list = []
    walk(reader.trailer, set(), keys)
    assert not {"/URI", "/Annots", "/JavaScript", "/JS", "/Launch", "/OpenAction",
                "/AcroForm", "/EmbeddedFile", "/EmbeddedFiles", "/AA"} & set(keys)


def test_only_the_two_faces_are_embedded(pdf):
    reader = PdfReader(io.BytesIO(pdf))
    names = set()
    for page in reader.pages:
        fonts = page["/Resources"].get("/Font", {})
        for ref in fonts.values():
            font = ref.get_object()
            names.add(str(font["/BaseFont"]))
            descendant = font.get("/DescendantFonts")
            desc = (descendant[0].get_object() if descendant else font).get("/FontDescriptor")
            if desc is not None:
                assert "/FontFile2" in desc.get_object()
    assert names
    assert all(FACES.fullmatch(n) for n in names), names
    assert b"Helvetica" not in pdf


def test_the_same_report_gives_the_same_bytes(pdf):
    assert render_pdf(detections_report()) == pdf


def test_the_bytes_match_the_golden_hash(pdf):
    digest = hashlib.sha256(pdf).hexdigest()
    if os.environ.get("DIRSIFT_UPDATE_GOLDEN"):
        print("golden pdf sha256", digest)
        return
    assert digest == GOLDEN_SHA256, (
        "The PDF bytes changed. If ReportLab was upgraded or the layout was changed on "
        "purpose, look at the pages and update GOLDEN_SHA256."
    )


def test_the_pdf_text_has_no_live_value_no_secret_and_no_banned_wording(pdf):
    report = detections_report()
    text = "\n".join(pages_text(pdf))
    assert live_hits(text, report.listing_paths) == []
    assert secret_hits(text, detections_result()) == []
    # a line break may fall inside an allowed phrase; the words are what count
    assert forbidden_hits(re.sub(r"\s+", " ", text)) == []
    assert punctuation_hits(text) == []
    result, candidates = analyze(leak_result())
    leak_text = "\n".join(pages_text(render_pdf(report_of(result, candidates,
                                                          run_name="leak-run"))))
    assert leaks(leak_text) == []
    assert secret_hits(leak_text, result) == []


def test_markdown_and_pdf_say_the_same_things(pdf):
    report = detections_report()
    markdown = render_markdown(report)
    text = flat("\n".join(pages_text(pdf)))
    # the headings, in order, after the contents list
    at = text.find(flat("Executive summary"), text.find("Contents") + 400)
    for s in report.sections:
        at = text.find(flat(s.title), at)
        assert at >= 0, s.title
    hashes = set(re.findall(r"\b[0-9a-f]{64}\b", markdown))
    assert hashes and all(h in text for h in hashes)
    appendix_b = markdown.split("## Appendix B.", 1)[1].split("## Appendix C.", 1)[0]
    values = {line.split()[0] for line in re.findall(r"```text\n(.*?)```", appendix_b, re.S)[0]
              .splitlines() if line.strip()}
    assert values and all(flat(v) in text for v in values)
    assert report.report_id in text and report.tlp_label in text


def test_markup_in_a_file_name_prints_as_text():
    result = detections_result()
    hostile = '<a href="http://x">click</a><img src="http://127.0.0.1:1/b.png"/>&amp;'
    result.entries.append(Entry(url=result.root_url + "x", name=hostile, kind="data",
                                parent_url=result.root_url))
    data = render_pdf(report_of(result))
    assert ACTIVE.findall(data) == []
    text = flat("\n".join(pages_text(data)))
    assert flat(hostile) in text
    assert escape(hostile) == ("&lt;a href=\"http://x\"&gt;click&lt;/a&gt;&lt;img "
                               "src=\"http://127.0.0.1:1/b.png\"/&gt;&amp;amp;")


def test_names_outside_the_faces_do_not_break_the_document():
    result = detections_result()
    for n, name in enumerate(["отчет.exe", "发票.pdf", "invoice‮gpj.exe",
                              "payload\U0001f480.bin"]):
        result.entries.append(Entry(url=result.root_url + f"h{n}", name=name, kind="data",
                                    parent_url=result.root_url))
    assert render_pdf(report_of(result)).startswith(b"%PDF")


def test_a_five_thousand_row_run_is_fast_and_small():
    """The detections fixture, its files repeated under numbered names."""
    result = detections_result()
    base = list(result.entries)
    result.entries = []
    for n in range(1250):
        for e in base:
            copy = e.model_copy()
            copy.url = e.url + f".{n}"
            copy.name = e.name + f".{n}"
            result.entries.append(copy)
    assert len(result.entries) == 5000
    start = time.perf_counter()
    data = render_pdf(report_of(result))
    took = time.perf_counter() - start
    # A guard against a pathological slowdown, not a benchmark: shared CI
    # runners take two to three times as long as a desktop.
    assert took < 60, took
    assert len(data) < 1_000_000, len(data)


def test_the_leak_run_renders():
    assert render_pdf(leak_report()).startswith(b"%PDF-")


# Analyst text the faces cannot draw is marked and the reader told.

RTL = {**FILLED, "rationale": "Seen at the loader. مرحبا שלום end.",
       "author": "Q‮A"}


def test_right_to_left_analyst_text_is_marked_not_dropped():
    report = detections_report(assessment=RTL, tlp="RED")
    text = "\n".join(pages_text(render_pdf(report)))
    assert MISSING_GLYPH in text  # the gap is visible
    assert flat("Seen at the loader.") in flat(text) and "end." in text
    assert flat(T.GLYPHS_MISSING.replace(MISSING_GLYPH, "")) in flat(text).replace(
        MISSING_GLYPH, "")
    # the Markdown carries every character
    markdown = render_markdown(report)
    assert "مرحبا שלום" in markdown


def test_a_report_the_faces_can_draw_has_no_glyph_note(pdf):
    text = flat("\n".join(pages_text(pdf)))
    assert MISSING_GLYPH not in text
    assert flat("outside the fonts this PDF carries") not in text


def test_drawable_keeps_what_the_faces_cover():
    assert drawable("Türkçe şğı Ελλάδα отчёт") == ("Türkçe şğı Ελλάδα отчёт", 0)
    assert drawable("a‮b") == ("a" + MISSING_GLYPH + "b", 1)


# A long indicator list starts on the page its appendix heading opens.

def test_a_long_indicator_list_starts_under_its_appendix_heading():
    from dirsift.extract import defang
    from dirsift.models import Ioc

    result = detections_result()
    source = result.files[0].url
    for net in ("198.51.100", "203.0.113"):
        for n in range(256):
            value = f"{net}.{n}"
            result.iocs.append(Ioc(ioc_type="ipv4", value=value, defanged=defang(value),
                                   source_url=source, sources=[source]))
    pages = pages_text(render_pdf(report_of(result, run_name="golden-run")))
    at = next(n for n, p in enumerate(pages) if re.search(r"Appendix B\s*All indicators", p))
    assert "IPv4 (" in pages[at]
    assert sum(1 for line in pages[at].splitlines() if "[.]" in line) >= 3
