"""The report against the runs on this machine. Skipped where there are none.

``runs/`` is never committed (real targets stay out of git), so these tests
run only on a machine that has scanned something. Two more inputs are
optional and named by environment variables:

``DIRSIFT_SAMPLE_REPORT`` is a Markdown file the report must reproduce byte
for byte, for the run named by ``DIRSIFT_SAMPLE_RUN``, with the generation
time and version below. ``DIRSIFT_SAMPLE_ASN`` is the address table that
sample was placed against.
"""

from __future__ import annotations

import io
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pypdf import PdfReader
from test_report import forbidden_hits, live_hits, own_text, punctuation_hits, secret_hits
from test_report_pdf import heading_pages, orphaned_headings

from dirsift.asn import AsnTable
from dirsift.report import render_markdown
from dirsift.report_model import ReportOptions, build_report, load_run_for_report
from dirsift.report_pdf import render_pdf

RUNS = Path(__file__).resolve().parents[1] / "runs"
RUN_FILES = sorted(RUNS.glob("*.json")) if RUNS.is_dir() else []
GENERATED = datetime(2026, 10, 22, 18, 10, 4, tzinfo=UTC)
VERSION = "0.1.0"
#: Lines that carry text before the appendices, in Markdown. The bar is 200.
NONBLANK_BAR = 200

needs_runs = pytest.mark.skipif(not RUN_FILES, reason="no runs on this machine")


def report_for(path: Path, table: AsnTable | None = None):
    loaded = load_run_for_report(path, asn_table=table or AsnTable())
    options = ReportOptions(run_name=loaded.name, version=VERSION,
                            asn_recorded=loaded.asn_recorded)
    return loaded, build_report(loaded.result, loaded.candidates, options, None, GENERATED,
                                loaded.run_sha256, loaded.siblings)


@needs_runs
@pytest.mark.parametrize("path", RUN_FILES, ids=lambda p: p.stem)
def test_every_run_gives_a_markdown_and_a_pdf_that_pass_the_gates(path):
    loaded, report = report_for(path)
    markdown = render_markdown(report)
    data = render_pdf(report)
    assert data.startswith(b"%PDF-")
    pdf_text = "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)
    assert live_hits(markdown, report.listing_paths) == []
    assert secret_hits(markdown, loaded.result) == []
    assert secret_hits(pdf_text, loaded.result) == []
    # the page title is the server's own text, data like a file name
    lines = [line for line in markdown.splitlines() if not line.startswith("| Page title |")]
    ours = own_text("\n".join(lines))
    assert forbidden_hits(ours) == []
    assert punctuation_hits(ours) == []
    assert report.summary_words < 150


@needs_runs
@pytest.mark.parametrize("path", RUN_FILES, ids=lambda p: p.stem)
def test_no_heading_is_orphaned_and_the_opening_pages_hold_on_any_run(path):
    """Over every run on this machine, ASN table absent (the case the orphan
    showed in): no section heading is the last line of a page, and keeping
    headings with their boxes leaves the template's opening pages as they were
    (9.1): summary and key facts on page two, the assessment on two or three."""
    _, report = report_for(path)
    data = render_pdf(report)
    assert orphaned_headings(report, data) == []
    at = heading_pages(report, data)
    assert at["summary"] == 2 and at["facts"] == 2 and at["assessment"] in (2, 3), at


def sample_inputs():
    names = ("DIRSIFT_SAMPLE_REPORT", "DIRSIFT_SAMPLE_RUN", "DIRSIFT_SAMPLE_ASN")
    values = [os.environ.get(n) for n in names]
    if not all(values) or not all(Path(v).exists() for v in values):
        pytest.skip("sample report, run and table not named")
    return [Path(v) for v in values]


def test_the_sample_report_is_reproduced_byte_for_byte():
    expected, run, table = sample_inputs()
    _, report = report_for(run, AsnTable.load(table))
    assert render_markdown(report).encode("utf-8") == expected.read_bytes()


def test_the_sample_stays_under_the_line_bar_and_its_pdf_near_sixteen_pages():
    _, run, table = sample_inputs()
    _, report = report_for(run, AsnTable.load(table))
    before = render_markdown(report).split("## Appendix A.", 1)[0]
    nonblank = sum(1 for line in before.splitlines() if line.strip())
    print(f"non-blank lines before the appendices: {nonblank} of {NONBLANK_BAR}")
    assert nonblank < NONBLANK_BAR
    pages = len(PdfReader(io.BytesIO(render_pdf(report))).pages)
    assert 14 <= pages <= 18, pages
