"""Render the triage report model as Markdown.

The model in ``report_model`` decides every sentence; this module only lays it
out. The first and last lines carry the TLP label, the second the DirSift
mark and name. Every host, address and URL in the model is already defanged,
so the page can be pasted into a chat or a ticket as it is.

``human_size`` and ``network_note`` are small helpers the terminal summary and
the console share with the report.
"""

from __future__ import annotations

import base64

from . import report_text as T
from .report_logo import FAVICON_SVG_INLINE
from .report_model import (
    AssessmentEmpty,
    AssessmentFull,
    Bullets,
    Free,
    Heading,
    Note,
    Para,
    Pre,
    Report,
    Summary,
    Table,
)

LOGO_DATA_URI = "data:image/svg+xml;base64," + base64.b64encode(
    FAVICON_SVG_INLINE.encode("utf-8")).decode("ascii")
LOGO_MODES = ("inline", "none")


def human_size(size: int | None) -> str:
    if size is None:
        return "-"
    value = float(size)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024 or unit == "T":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}T"


def network_note(asn: int | None, as_name: str = "", country: str = "") -> str:
    """How an address is described once its network is known.

    Written as one string because that is how it is read: the number, who
    announces it, and where they said it was. Missing parts are simply absent.
    """
    if not asn:
        return ""
    parts = [f"AS{asn}"]
    if as_name:
        parts.append(as_name)
    tail = " ".join(parts)
    return f"{tail}, {country}" if country else tail


def md_escape(text: str) -> str:
    """Analyst free text, made inert for a Markdown viewer that renders to HTML.

    The three HTML-significant characters become entities so a ``<script>`` or
    an ``<img onerror=...>`` prints as those characters, and the one Markdown
    construct that can carry an active scheme, the inline link or image target,
    is broken by escaping the parenthesis after ``]``. A defanged indicator
    such as ``evil[.]example`` survives untouched, because it has no following
    parenthesis.
    """
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("](", "]\\(")


def md_cell(text: str) -> str:
    """A table cell: pipes escaped, line breaks folded so the row stays one line.

    Analyst free text is escaped first; the catalogue's own cells keep the
    Markdown the report writes on purpose (a bold status, a code span)."""
    if isinstance(text, Free):
        text = md_escape(text)
    return " ".join(text.replace("|", "\\|").splitlines())


def _md_block(add, blk) -> None:
    if isinstance(blk, Para):
        add(md_escape(blk.text) if isinstance(blk.text, Free) else blk.text)
        add("")
    elif isinstance(blk, Note):
        add(f"_{blk.text}_")
        add("")
    elif isinstance(blk, Heading):
        add(f"### {blk.text}")
        add("")
    elif isinstance(blk, Summary):
        add(blk.text)
        add("")
        add(f"_{blk.closing}_")
        add("")
    elif isinstance(blk, Table):
        add("| " + " | ".join(blk.headers) + " |")
        add("| " + " | ".join(":-" if a == "l" else "-:" for a in blk.aligns) + " |")
        for row in blk.rows:
            add("| " + " | ".join(md_cell(c) for c in row) + " |")
        add("")
    elif isinstance(blk, Pre):
        if blk.title:
            add(f"**{blk.title}**")
            add("")
        fence = "````" if any("```" in line for line in blk.lines) else "```"
        add(fence + "text")
        for line in blk.lines:
            add(line)
        add(fence)
        add("")
    elif isinstance(blk, Bullets):
        for item in blk.items:
            add(("1. " if blk.ordered else "- ") + " ".join(item.splitlines()))
        add("")
    elif isinstance(blk, AssessmentEmpty):
        add(f"> {blk.lead} {blk.fields}")
        add("")
    elif isinstance(blk, AssessmentFull):
        add(f"> **{blk.status}.** {blk.assessment}: {blk.definition}.")
        add(">")
        add("> | Field | Value |")
        add("> | :- | :- |")
        for key, value in blk.rows:
            add(f"> | {key} | {md_cell(value)} |")
        if blk.references:
            add(">")
            add("> References:")
            add(">")
            for ref in blk.references:
                text = md_escape(ref) if isinstance(ref, Free) else ref
                add("> - " + " ".join(text.splitlines()))
        add("")
    else:  # pragma: no cover - every block type is handled above
        raise TypeError(type(blk).__name__)


def render_markdown(report: Report, *, logo: str = "inline") -> str:
    """The report as Markdown. ``logo="none"`` leaves the image out and keeps the name."""
    if logo not in LOGO_MODES:
        raise ValueError(f"logo must be one of {', '.join(LOGO_MODES)}")
    out: list[str] = []
    add = out.append
    tlp = report.tlp_label
    add(f"**{tlp}** · {report.tlp_definition}")
    add("")
    mark = f'<img src="{LOGO_DATA_URI}" alt="" width="28" height="28"> ' if logo == "inline" \
        else ""
    add(f"{mark}**DirSift** · {T.REPORT_KIND}")
    add("")
    add("# " + T.TITLE.format(target=report.target))
    add("")
    add("| Document control | |")
    add("| :- | :- |")
    for key, value in report.doc_control:
        add(f"| {key} | {md_cell(value)} |")
    add("")
    add("## Contents")
    add("")
    for s in report.sections:
        if not s.appendix:
            add(f"{s.number}. {s.title} ({s.reader_label})")
    add("")
    add("Appendices: " + " · ".join(f"{s.number}. {s.title} ({s.reader_label})"
                                    for s in report.sections if s.appendix))
    add("")
    for s in report.sections:
        prefix = f"Appendix {s.number}. " if s.appendix else f"{s.number}. "
        add(f"## {prefix}{s.title}")
        add("")
        for blk in s.blocks:
            _md_block(add, blk)
    add(f"**{tlp}** · Report `{report.report_id}` · Generated by {report.generator}")
    return "\n".join(out).rstrip() + "\n"
