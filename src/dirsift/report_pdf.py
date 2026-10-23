"""Render the triage report model as a PDF.

Only the light print palette exists: the colours are the print tokens of the
console stylesheet, read by ``report_tokens``. Text is IBM Plex Sans and data
is JetBrains Mono, the official static files shipped in ``report_assets``;
nothing falls back to a built in face. The marks are drawn from path data, so
no image or SVG is read.

The file is a closed document. It has no links, no annotations, no scripts,
no forms and no embedded files, and nothing in it points outside itself. All
text that reaches the layout engine's markup passes through ``escape`` first,
so a file name such as ``<a href=...>`` prints as those characters.

Output is byte for byte reproducible: the document is written in the writer's
invariant mode, and every date in it comes from the model.
"""

from __future__ import annotations

import io
import re
from functools import cache
from importlib.resources import files

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from . import report_logo
from . import report_text as T
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
)
from .report_model import (
    Table as ModelTable,
)
from .report_tokens import tokens

PAGE_W, PAGE_H = A4
MARGIN_X = 18 * mm
MARGIN_TOP = 20 * mm
MARGIN_BOTTOM = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X

SANS = "DirSiftPlex"
SANS_BOLD = "DirSiftPlex-SemiBold"
MONO = "DirSiftMono"
MONO_BOLD = "DirSiftMono-Bold"
FONT_FILES = {
    SANS: "IBMPlexSans-Regular.ttf",
    SANS_BOLD: "IBMPlexSans-SemiBold.ttf",
    MONO: "JetBrainsMono-Regular.ttf",
    MONO_BOLD: "JetBrainsMono-Bold.ttf",
}

PT_BODY = 9.5
PT_SMALL = 8
PT_MONO = 8
PT_MONO_TABLE = 7.5
PT_H2 = 13
PT_H3 = 10.5

#: Lines of a code block that must fit under its title on the same page; the
#: block splits after them (CodeBlock never leaves fewer than three on a page).
CODE_LINES_WITH_TITLE = 3

#: Badge colour roles (template section 9.4): text and border, then ground.
BADGES = {
    "none": ("print-ink-2", "paper"),
    "high": ("print-alert", "print-alert-wash"),
    "medium": ("print-caution", "print-caution-wash"),
    "low": ("print-accent-strong", "print-accent-wash"),
    "info": ("print-ink-2", "paper-raised"),
    "ok": ("print-ok", "print-ok-wash"),
}
ASSESSMENT_BADGE = {"Malicious infrastructure": "high", "Suspicious": "medium",
                    "Benign or research": "ok", "Undetermined": "info"}
PRIORITY_BADGE = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}

_CODE = re.compile(r"`` (.+?) ``|`([^`]+)`")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_KEEP_WHOLE = re.compile(
    r"\d{4}-\d\d-\d\dT[\d:]+Z|[0-9a-f]{32}|[0-9a-f]{64}|DSR-[\w-]+")


@cache
def _register_fonts() -> None:
    folder = files("dirsift").joinpath("report_assets/fonts")
    for name, filename in FONT_FILES.items():
        with folder.joinpath(filename).open("rb") as fh:
            pdfmetrics.registerFont(TTFont(name, io.BytesIO(fh.read())))
    pdfmetrics.registerFontFamily(SANS, normal=SANS, bold=SANS_BOLD, italic=SANS,
                                  boldItalic=SANS_BOLD)
    pdfmetrics.registerFontFamily(MONO, normal=MONO, bold=MONO_BOLD, italic=MONO,
                                  boldItalic=MONO_BOLD)


#: What a character the report's faces cannot draw is shown as. Every face
#: carries it, so the gap is visible instead of silently empty.
MISSING_GLYPH = "�"
_KEEP_AS_IS = frozenset("\n\r\t")


def drawable(text: str) -> tuple[str, int]:
    """Text with every character the body face has no glyph for replaced by
    MISSING_GLYPH, and how many were replaced. The faces carry Latin, Latin
    Extended, Greek and Cyrillic; right-to-left scripts need shaping and
    reordering the layout engine does not do, so they are marked, not drawn."""
    _register_fonts()
    cmap = pdfmetrics.getFont(SANS).face.charToGlyph
    out = []
    lost = 0
    for ch in text:
        if ch in _KEEP_AS_IS or ord(ch) in cmap:
            out.append(ch)
        else:
            out.append(MISSING_GLYPH)
            lost += 1
    return "".join(out), lost


def escape(text: str) -> str:
    """The one way text enters the layout engine's markup: as characters, never tags."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def inline(text: str, code_size: float = PT_MONO, code_back: str | None = None) -> str:
    """Model text to paragraph markup: ``code`` spans in the data face, **bold** in
    the heavier weight, everything escaped. A short code span, a hash, a time stamp
    or a report ID is kept on one line."""
    out = []
    pos = 0
    back = f' backColor="{code_back}"' if code_back else ""
    for m in _CODE.finditer(text):
        out.append(_BOLD.sub(r"<b>\1</b>", escape(text[pos:m.start()])))
        value = m.group(1) if m.group(1) is not None else m.group(2)
        shown = escape(value)
        if len(value) <= 24 or _KEEP_WHOLE.fullmatch(value):
            shown = shown.replace(" ", "&nbsp;")
        out.append(f'<font face="{MONO}" size="{code_size}"{back}>{shown}</font>')
        pos = m.end()
    out.append(_BOLD.sub(r"<b>\1</b>", escape(text[pos:])))
    return "".join(out).replace("\n", "<br/>")


def plain(text: str) -> str:
    return _BOLD.sub(r"\1", _CODE.sub(lambda m: m.group(1) or m.group(2), text))


def _style(commands: list) -> TableStyle:
    """A table style that sets every cell in the report's face, so no string cell
    falls back to a built in font."""
    return TableStyle([("FONTNAME", (0, 0), (-1, -1), SANS), ("FONTSIZE", (0, 0), (-1, -1),
                                                               PT_SMALL), *commands])


def _unbold(m: re.Match) -> str:
    return m.group(1)


def _pieces(text: str):
    """(piece, is_code) for model text, code spans kept whole."""
    pos = 0
    for m in _CODE.finditer(text):
        yield text[pos:m.start()], False
        yield (m.group(1) if m.group(1) is not None else m.group(2)), True
        pos = m.end()
    yield text[pos:], False


def _text_width(text: str, font: str) -> float:
    """The widest line of a cell, set on one line."""
    best = 0.0
    for line in text.splitlines() or [""]:
        w = 0.0
        for piece, is_code in _pieces(line):
            piece = _BOLD.sub(_unbold, piece)
            w += pdfmetrics.stringWidth(piece, MONO if is_code else font,
                                        PT_MONO_TABLE if is_code else PT_SMALL)
        best = max(best, w)
    return best


def _min_width(text: str, font: str) -> float:
    """The widest piece a cell cannot break: a word, a short code span, a hash."""
    best = 0.0
    for piece, is_code in _pieces(text):
        if is_code:
            unit = piece if (len(piece) <= 24 or _KEEP_WHOLE.fullmatch(piece)) else piece[:24]
            best = max(best, pdfmetrics.stringWidth(unit, MONO, PT_MONO_TABLE))
        else:
            for word in _BOLD.sub(_unbold, piece).split():
                best = max(best, pdfmetrics.stringWidth(word, font, PT_SMALL))
    return best


class _Styles:
    def __init__(self, c: dict) -> None:
        ink = c["print-ink"]
        ink2 = c["print-ink-2"]
        self.body = ParagraphStyle("body", fontName=SANS, fontSize=PT_BODY, leading=13.6,
                                   textColor=ink, spaceAfter=2.4 * mm)
        self.note = ParagraphStyle("note", parent=self.body, fontSize=PT_SMALL, leading=11,
                                   textColor=ink2)
        self.h3 = ParagraphStyle("h3", parent=self.body, fontName=SANS_BOLD, fontSize=PT_H3,
                                 leading=13, spaceBefore=4 * mm, spaceAfter=1.5 * mm,
                                 keepWithNext=1)
        self.cell = ParagraphStyle("cell", parent=self.body, fontSize=PT_SMALL, leading=10.4,
                                   spaceAfter=0)
        self.cell_key = ParagraphStyle("cellkey", parent=self.cell, textColor=ink2)
        self.cell_head = ParagraphStyle("cellhead", parent=self.cell, fontName=SANS_BOLD)
        self.cell_num = ParagraphStyle("cellnum", parent=self.cell, alignment=2)
        self.cell_head_num = ParagraphStyle("cellheadnum", parent=self.cell_head, alignment=2)
        self.kv_small = ParagraphStyle("kvsmall", parent=self.cell, fontSize=7.5, leading=9.6)
        self.kv_small_key = ParagraphStyle("kvsmallkey", parent=self.kv_small, textColor=ink2)
        self.bullet = ParagraphStyle("bullet", parent=self.body, leftIndent=5 * mm,
                                     bulletIndent=1 * mm, spaceAfter=1.2 * mm,
                                     bulletFontName=SANS)
        self.summary = ParagraphStyle("summary", parent=self.body, spaceAfter=1.5 * mm)
        self.toc = ParagraphStyle("toc", parent=self.cell, fontSize=7.5, leading=9.4)
        self.toc_n = ParagraphStyle("tocn", parent=self.toc, fontName=MONO,
                                    textColor=c["print-accent"])
        self.toc_p = ParagraphStyle("tocp", parent=self.toc, fontName=MONO, textColor=ink2,
                                    alignment=2)
        self.continued = ParagraphStyle("cont", parent=self.note, spaceAfter=1 * mm)
        self.cover_cell = ParagraphStyle("covercell", parent=self.cell)
        self.cover_key = ParagraphStyle("coverkey", parent=self.cell, textColor=ink2)
        self.cover_title = ParagraphStyle("covertitle", fontName=SANS_BOLD, fontSize=26,
                                          leading=30, textColor=c["ink"])
        self.cover_target = ParagraphStyle("covertarget", fontName=MONO, fontSize=18,
                                           leading=22, textColor=c["lamp"])
        self.cover_note = ParagraphStyle("covernote", parent=self.note)
        self.assess_head = ParagraphStyle("assesshead", parent=self.body, fontName=SANS_BOLD,
                                          fontSize=PT_H3, leading=13, spaceAfter=0)
        self.assess_why = ParagraphStyle("assesswhy", parent=self.note, spaceAfter=0)


def _colours() -> dict:
    return {name: HexColor(value) for name, value in tokens().items()}


def _tlp_colour(c: dict, tlp: str):
    level = tlp.split("+")[0].lower()
    return c[f"tlp-{level}"]


def draw_tlp(canvas, c: dict, tlp: str, x_right: float, y: float, size: float = 12) -> float:
    """The TLP label, FIRST style: coloured letters on black, right aligned at x_right."""
    label = "TLP:" + tlp
    width = pdfmetrics.stringWidth(label, SANS_BOLD, size) + 2 * 2.2 * mm
    height = size * 1.2 + 1.2 * mm
    canvas.saveState()
    canvas.setFillColor(c["tlp-ground"])
    canvas.rect(x_right - width, y, width, height, stroke=0, fill=1)
    canvas.setFillColor(_tlp_colour(c, tlp))
    canvas.setFont(SANS_BOLD, size)
    canvas.drawString(x_right - width + 2.2 * mm, y + 0.6 * mm + size * 0.22, label)
    canvas.restoreState()
    return width


class Badge(Flowable):
    """A small bordered label: a reader label, a status, a scale value."""

    def __init__(self, text: str, fg, bg, *, dashed: bool = False, size: float = PT_SMALL,
                 upper: bool = False, font: str = SANS_BOLD, meter: int | None = None,
                 meter_off=None) -> None:
        super().__init__()
        self.text = text.upper() if upper else text
        self.fg, self.bg, self.dashed, self.size, self.font = fg, bg, dashed, size, font
        self.meter, self.meter_off = meter, meter_off
        self.pad = 1.4 * mm
        meter_w = 3 * 1.2 * mm + 2 * 0.5 * mm + 1.2 * mm if meter is not None else 0
        self.width = pdfmetrics.stringWidth(self.text, font, size) + 2 * self.pad + meter_w
        self.height = size * 1.45
        self._meter_w = meter_w

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(self.bg)
        c.setStrokeColor(self.fg)
        c.setLineWidth(0.6)
        if self.dashed:
            c.setDash(1.5, 1)
        c.rect(0, 0, self.width, self.height, stroke=1, fill=1)
        c.setDash()
        x = self.pad
        if self.meter is not None:
            for i in range(3):
                c.setFillColor(self.fg if i < self.meter else self.meter_off)
                c.rect(x + i * (1.2 * mm + 0.5 * mm), self.height * 0.2, 1.2 * mm,
                       self.height * 0.6, stroke=0, fill=1)
            x += self._meter_w
        c.setFillColor(self.fg)
        c.setFont(self.font, self.size)
        c.drawString(x, self.height * 0.28, self.text)
        c.restoreState()


class SectionHeading(Flowable):
    """An H2: number, title, the reader label on the right, a rule under it.

    It records the page it lands on, which the contents list reads on the next pass.
    """

    def __init__(self, number: str, title: str, label: str, key: str, pages: dict,
                 c: dict) -> None:
        super().__init__()
        self.number, self.title, self.label, self.key = number, title, label, key
        self.pages, self.c = pages, c
        self.height = 8 * mm
        self.spaceBefore = 5 * mm
        self.spaceAfter = 2.5 * mm
        self.keepWithNext = 1

    def wrap(self, aw, ah):
        self.width = aw
        return aw, self.height

    def draw(self):
        canv = self.canv
        self.pages[self.key] = canv.getPageNumber()
        c = self.c
        canv.saveState()
        base = 2.2 * mm
        canv.setFillColor(c["print-accent"])
        canv.setFont(MONO, PT_H3)
        canv.drawString(0, base, self.number)
        x = pdfmetrics.stringWidth(self.number, MONO, PT_H3) + 2.5 * mm
        canv.setFillColor(c["print-ink"])
        canv.setFont(SANS_BOLD, PT_H2)
        title = self.title
        room = self.width - x - 22 * mm
        while pdfmetrics.stringWidth(title, SANS_BOLD, PT_H2) > room and len(title) > 4:
            title = title[:-1]
        canv.drawString(x, base, title)
        badge = Badge(self.label, c["print-ink-2"], c["paper"], size=7, upper=True)
        badge.canv = canv
        canv.translate(self.width - badge.width, base - 0.6 * mm)
        badge.draw()
        canv.restoreState()
        canv.saveState()
        canv.setStrokeColor(c["print-ink"])
        canv.setLineWidth(1)
        canv.line(0, 0, self.width, 0)
        canv.restoreState()


class CodeBlock(Flowable):
    """A code block that breaks across pages, saying so at the top of each part."""

    def __init__(self, lines: list[str], title: str | None, c: dict, *, size: float = 7,
                 continued: bool = False, prewrapped: bool = False) -> None:
        super().__init__()
        self.prewrapped = prewrapped
        self.source = lines
        self.title = title
        self.c = c
        self.size = size
        self.leading = size * 1.45
        self.continued = continued
        self.pad = 2 * mm
        self._lines: list[str] | None = None

    def _wrap_lines(self, aw: float) -> list[str]:
        if self.prewrapped:
            return list(self.source)
        char = pdfmetrics.stringWidth("M", MONO, self.size)
        per = max(8, int((aw - 2 * 3 * mm) // char))
        out = []
        for line in self.source:
            if not line:
                out.append("")
                continue
            while len(line) > per:
                out.append(line[:per])
                line = "  " + line[per:]
            out.append(line)
        return out

    def _label(self) -> str | None:
        if not self.continued:
            return None
        return f"{self.title} {T.CONTINUED}" if self.title else T.CONTINUED

    def wrap(self, aw, ah):
        self.width = aw
        self._lines = self._wrap_lines(aw)
        label = 1 if self._label() else 0
        self.height = (len(self._lines) + label) * self.leading + 2 * self.pad
        return aw, self.height

    def split(self, aw, ah):
        lines = self._lines if self._lines is not None else self._wrap_lines(aw)
        label = 1 if self._label() else 0
        fit = int((ah - 2 * self.pad) // self.leading) - label
        if fit < 3 or len(lines) - fit < 1:
            return []
        first = CodeBlock(lines[:fit], self.title, self.c, size=self.size,
                          continued=self.continued, prewrapped=True)
        rest = CodeBlock(lines[fit:], self.title, self.c, size=self.size, continued=True,
                         prewrapped=True)
        return [first, rest]

    def draw(self):
        canv = self.canv
        c = self.c
        canv.saveState()
        canv.setFillColor(c["paper-sunken"])
        canv.setStrokeColor(c["rule"])
        canv.setLineWidth(0.5)
        canv.rect(0, 0, self.width, self.height, stroke=1, fill=1)
        canv.setStrokeColor(c["rule-strong"])
        canv.setLineWidth(1.5)
        canv.line(0, 0, 0, self.height)
        y = self.height - self.pad - self.size
        label = self._label()
        if label:
            canv.setFillColor(c["print-ink-2"])
            canv.setFont(SANS, self.size)
            canv.drawString(3 * mm, y, label)
            y -= self.leading
        canv.setFillColor(c["print-ink"])
        canv.setFont(MONO, self.size)
        for line in self._lines or []:
            canv.drawString(3 * mm, y, line)
            y -= self.leading
        canv.restoreState()


class Continued(Flowable):
    """A table that, once broken across pages, opens each later part with "(continued)".

    A part keeps at least three body rows; if fewer fit, the whole table moves on.
    """

    def __init__(self, table: Table, style: ParagraphStyle, *, header_rows: int = 1,
                 continued: bool = False) -> None:
        super().__init__()
        self.table = table
        self.style = style
        self.header_rows = header_rows
        self.continued = continued
        self.label = Paragraph(escape(T.CONTINUED), style) if continued else None

    def _label_h(self, aw):
        if not self.label:
            return 0
        _, h = self.label.wrap(aw, 1000)
        return h + self.style.spaceAfter

    def wrap(self, aw, ah):
        lh = self._label_h(aw)
        w, h = self.table.wrap(aw, ah - lh)
        self.width, self.height = w, h + lh
        return w, self.height

    def split(self, aw, ah):
        lh = self._label_h(aw)
        parts = self.table.split(aw, ah - lh)
        if len(parts) < 2:
            return []
        body_rows = len(parts[0]._cellvalues) - self.header_rows
        rest_rows = len(parts[1]._cellvalues) - self.header_rows
        if body_rows < 3 or rest_rows < 1:
            return []
        first = Continued(parts[0], self.style, header_rows=self.header_rows,
                          continued=self.continued)
        rest = Continued(parts[1], self.style, header_rows=self.header_rows, continued=True)
        return [first, rest]

    def drawOn(self, canvas, x, y, _sW=0):
        lh = self._label_h(self.width)
        if self.label:
            self.label.wrap(self.width, 1000)
            self.label.drawOn(canvas, x, y + self.height - self.label.height)
        self.table.drawOn(canvas, x, y, _sW)
        _ = lh

    def draw(self):  # pragma: no cover - drawOn does the work
        pass


class _Renderer:
    def __init__(self, report: Report, pages: dict, total: int) -> None:
        _register_fonts()
        self.r = report
        self.c = _colours()
        self.s = _Styles(self.c)
        self.pages = pages
        self.total = total
        self.new_pages: dict = {}
        self.code_back = tokens()["paper-sunken"]
        self.lost = 0  # analyst characters shown as MISSING_GLYPH

    # page furniture

    def cover_page(self, canvas, doc):
        c, r = self.c, self.r
        canvas.saveState()
        band = 92 * mm
        canvas.setFillColor(c["ground"])
        canvas.rect(0, PAGE_H - band, PAGE_W, band, stroke=0, fill=1)
        canvas.setFillColor(c["lamp"])
        canvas.rect(0, PAGE_H - band, PAGE_W, 1.5 * mm, stroke=0, fill=1)
        lock_w = 74 * mm
        lock_h = report_logo.LOCKUP.height * lock_w / report_logo.LOCKUP.width
        report_logo.draw(canvas, report_logo.LOCKUP, MARGIN_X - 3 * mm,
                         PAGE_H - 18 * mm - lock_h, lock_w,
                         {"ink": c["ink"], "accent": c["lamp"]})
        draw_tlp(canvas, c, r.tlp, PAGE_W - MARGIN_X, PAGE_H - 18 * mm - 6 * mm)
        title = Paragraph(escape(T.COVER_TITLE), self.s.cover_title)
        target = Paragraph(escape(r.target), self.s.cover_target)
        _, th = target.wrap(CONTENT_W, 60 * mm)
        _, hh = title.wrap(CONTENT_W, 40 * mm)
        y = PAGE_H - band + 12 * mm
        target.drawOn(canvas, MARGIN_X, y)
        y += th + 1 * mm
        title.drawOn(canvas, MARGIN_X, y)
        y += hh + 2 * mm
        canvas.setFillColor(c["lamp"])
        canvas.setFont(MONO, PT_SMALL)
        kicker = T.COVER_KICKER.format(date=f"{r.started_at:%Y-%m-%d}").upper()
        canvas.drawString(MARGIN_X, y, kicker)
        # the TLP box: label, FIRST definition, the defang guarantee
        box_y = 24 * mm
        note = Paragraph(escape(r.tlp_definition + " " + T.COVER_TLP_GUARANTEE),
                         self.s.cover_note)
        label_w = pdfmetrics.stringWidth("TLP:" + r.tlp, SANS_BOLD, 12) + 4.4 * mm
        _, nh = note.wrap(CONTENT_W - label_w - 12 * mm, 40 * mm)
        box_h = max(nh, 8 * mm) + 6 * mm
        canvas.setStrokeColor(c["rule"])
        canvas.setLineWidth(0.5)
        canvas.rect(MARGIN_X, box_y, CONTENT_W, box_h, stroke=1, fill=0)
        draw_tlp(canvas, c, r.tlp, MARGIN_X + 4 * mm + label_w, box_y + box_h - 3 * mm - 16)
        note.drawOn(canvas, MARGIN_X + 8 * mm + label_w, box_y + box_h - 3 * mm - nh)
        self.footer(canvas, cover=True)
        canvas.restoreState()

    def footer(self, canvas, *, cover: bool) -> None:
        c, r = self.c, self.r
        y = 7 * mm
        canvas.saveState()
        canvas.setStrokeColor(c["rule"])
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN_X, y + 8 * mm, PAGE_W - MARGIN_X, y + 8 * mm)
        report_logo.draw(canvas, report_logo.FAVICON, MARGIN_X, y + 1.2 * mm, 4 * mm,
                         {"ink": c["print-ink"], "accent": c["print-accent"]})
        canvas.setFillColor(c["print-ink"])
        canvas.setFont(SANS_BOLD, PT_SMALL)
        canvas.drawString(MARGIN_X + 5.6 * mm, y + 2.2 * mm,
                          "DirSift" if cover else r.generator)
        canvas.setFillColor(c["print-ink-2"])
        if cover:
            canvas.setFont(SANS, PT_SMALL)
            canvas.drawCentredString(PAGE_W / 2, y + 2.2 * mm, drawable(r.review_line)[0])
        else:
            canvas.setFont(MONO, PT_SMALL)
            canvas.drawCentredString(PAGE_W / 2, y + 2.2 * mm,
                                     f"Page {canvas.getPageNumber()} / {self.total or '?'}")
        draw_tlp(canvas, c, r.tlp, PAGE_W - MARGIN_X, y)
        canvas.restoreState()

    def body_page(self, canvas, doc):
        c, r = self.c, self.r
        canvas.saveState()
        top = PAGE_H - 8 * mm
        canvas.setFillColor(c["print-ink-2"])
        canvas.setFont(MONO, PT_SMALL)
        canvas.drawString(MARGIN_X, top - 4 * mm, f"{r.report_id} · v{r.version}")
        draw_tlp(canvas, c, r.tlp, PAGE_W - MARGIN_X, top - 5.4 * mm, size=10)
        canvas.setStrokeColor(c["rule"])
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN_X, top - 7 * mm, PAGE_W - MARGIN_X, top - 7 * mm)
        canvas.restoreState()
        self.footer(canvas, cover=False)

    # blocks

    def free(self, text: str) -> str:
        """Analyst text with undrawable characters marked; counts what was marked
        so the document can say so. Other text is passed through."""
        if not isinstance(text, Free):
            return text
        shown, lost = drawable(text)
        self.lost += lost
        return shown

    def para(self, text: str, style: ParagraphStyle) -> Paragraph:
        return Paragraph(inline(self.free(text), code_back=self.code_back), style)

    def cell(self, text: str, style: ParagraphStyle, code_size: float = PT_MONO_TABLE):
        return Paragraph(inline(self.free(text), code_size), style)

    def col_widths(self, headers, rows, fixed: dict | None = None) -> list[float]:
        """Column widths: each column gets at least its widest unbreakable piece, then
        the room left goes to the columns with the most text."""
        n = len(headers)
        fixed = fixed or {}
        pad = 4 * mm + 1
        natural = []
        least = []
        for i in range(n):
            nat = _text_width(headers[i], SANS_BOLD)
            low = _min_width(headers[i], SANS_BOLD)
            for row in rows:
                nat = max(nat, _text_width(row[i], SANS))
                low = max(low, _min_width(row[i], SANS))
            natural.append(nat + pad)
            least.append(low + pad)
        widths = [0.0] * n
        free = [i for i in range(n) if i not in fixed]
        for i, w in fixed.items():
            widths[i] = w
        if not free:
            return widths
        avail = CONTENT_W - sum(fixed.values())
        floor = sum(least[i] for i in free)
        if floor >= avail:
            for i in free:
                widths[i] = least[i] * avail / floor
            return widths
        if sum(natural[i] for i in free) <= avail:
            extra = (avail - sum(natural[i] for i in free)) / len(free)
            for i in free:
                widths[i] = natural[i] + extra
            return widths
        room = avail - floor
        want = {i: natural[i] - least[i] for i in free}
        total = sum(want.values()) or 1
        for i in free:
            widths[i] = least[i] + room * want[i] / total
        return widths

    def table(self, blk: ModelTable):
        s, c = self.s, self.c
        headers = list(blk.headers)
        rows = [list(r) for r in blk.rows]
        aligns = list(blk.aligns)
        fixed: dict = {}
        code_sizes: dict = {}
        if blk.kind == "listing":
            # MD5 sits under SHA256 in one cell, as the template's PDF layout asks
            headers = headers[:3] + ["SHA256 / MD5"] + headers[5:]
            aligns = aligns[:3] + ["l"] + aligns[5:]
            rows = [r[:3] + [r[3] + ("\n" + r[4] if r[4] else "")] + r[5:] for r in rows]
            sha_size = 6.3 if len(headers) <= 5 else 5.6
            sha_w = 64 * pdfmetrics.stringWidth("0", MONO, sha_size) + 3 * mm
            fixed = {1: 15 * mm, 2: 15 * mm, 3: sha_w}
            code_sizes = {3: sha_size}
        elif blk.kind == "vt":
            sha_w = 64 * pdfmetrics.stringWidth("0", MONO, 6) + 3 * mm
            fixed = {1: sha_w, 3: 33 * mm}
            code_sizes = {1: 6, 3: 7}
        elif blk.kind == "kv":
            fixed = {0: 42 * mm}
        widths = self.col_widths(headers, rows, fixed)
        key_style = s.kv_small_key if blk.keep else s.cell_key
        val_style = s.kv_small if blk.keep else s.cell
        data = [[self.cell(h, s.cell_head_num if a == "r" else s.cell_head)
                 for h, a in zip(headers, aligns, strict=True)]]
        for row in rows:
            out = []
            for i, (text, a) in enumerate(zip(row, aligns, strict=True)):
                if blk.kind == "kv":
                    style = key_style if i == 0 else val_style
                else:
                    style = s.cell_num if a == "r" else s.cell
                out.append(self.cell(text, style, code_sizes.get(i, PT_MONO_TABLE)))
            data.append(out)
        pad_v = 0.8 * mm if blk.keep else 1.2 * mm
        table = Table(data, colWidths=widths, repeatRows=1)
        table.setStyle(_style([
            ("BACKGROUND", (0, 0), (-1, 0), c["paper-raised"]),
            ("LINEBELOW", (0, 0), (-1, 0), 1, c["rule-strong"]),
            ("LINEBELOW", (0, 1), (-1, -1), 0.5, c["rule"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 2 * mm if blk.kind != "listing" else 1.4 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2 * mm if blk.kind != "listing" else 1.4 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), pad_v),
            ("BOTTOMPADDING", (0, 0), (-1, -1), pad_v),
        ]))
        if blk.keep:
            return [KeepTogether([table]), Spacer(1, 3 * mm)]
        return [Continued(table, s.continued), Spacer(1, 3 * mm)]

    def summary(self, blk: Summary):
        s, c = self.s, self.c
        inner = [self.para(blk.text, s.summary), self.para(blk.closing, s.note)]
        box = Table([[inner]], colWidths=[CONTENT_W])
        box.setStyle(_style([
            ("BACKGROUND", (0, 0), (-1, -1), c["paper-raised"]),
            ("LINEABOVE", (0, 0), (-1, 0), 1.5, c["print-accent"]),
            ("LEFTPADDING", (0, 0), (-1, -1), 3.5 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3.5 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), 2.5 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5 * mm),
        ]))
        return [KeepTogether([box]), Spacer(1, 3 * mm)]

    def badge(self, text: str, role: str, **kw) -> Badge:
        fg, bg = BADGES[role]
        return Badge(text, self.c[fg], self.c[bg], dashed=role == "none", **kw)

    def assessment_box(self, head: list, rows: list):
        c = self.c
        box = Table([[cell] for cell in head + rows], colWidths=[CONTENT_W])
        box.setStyle(_style([
            ("BOX", (0, 0), (-1, -1), 1, c["print-ink"]),
            ("LINEBEFORE", (0, 0), (0, -1), 2.5 * mm, c["print-accent"]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), 1.2 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.2 * mm),
            ("TOPPADDING", (0, 0), (-1, 0), 3 * mm),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 3 * mm),
        ]))
        return [KeepTogether([box]), Spacer(1, 3 * mm)]

    def head_row(self, title: str, badge: Badge):
        inner_w = CONTENT_W - 9 * mm
        t = Table([[Paragraph(escape(title), self.s.assess_head), badge]],
                  colWidths=[inner_w - badge.width - 2 * mm, badge.width + 2 * mm])
        t.setStyle(_style([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        return t

    def assessment_empty(self, blk: AssessmentEmpty):
        s = self.s
        lead = blk.lead.replace("**Not assessed.** ", "")
        return self.assessment_box(
            [self.head_row(T.NOT_ASSESSED, self.badge(T.AWAITING_ANALYST, "none"))],
            [self.para(lead, s.cell), self.para(blk.fields, s.note)])

    def assessment_full(self, blk: AssessmentFull):
        s, c = self.s, self.c
        status_role = "ok" if blk.status == "Final" else "none"
        conf = {"High": 3, "Moderate": 2, "Low": 1}.get(blk.confidence)
        inner_w = CONTENT_W - 9 * mm
        cells = [
            [Paragraph("Assessment", s.cell_key),
             self.badge(blk.assessment, ASSESSMENT_BADGE.get(blk.assessment, "info"))],
            [Paragraph("Confidence", s.cell_key),
             self.badge(blk.confidence, "low" if conf else "none", meter=conf or 0,
                        meter_off=c["rule"])],
            [Paragraph("Priority for follow-up", s.cell_key),
             self.badge(blk.priority, PRIORITY_BADGE.get(blk.priority, "none"))],
            [Paragraph("Analyst", s.cell_key),
             Paragraph(escape(self.free(Free(blk.author))), s.cell)],
        ]
        grid = Table([cells], colWidths=[inner_w / 4] * 4)
        grid.setStyle(_style([
            ("BACKGROUND", (0, 0), (-1, -1), c["paper-raised"]),
            ("LINEAFTER", (0, 0), (-2, -1), 2 * mm, c["paper"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 2 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), 1.8 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.8 * mm),
        ]))
        kv = Table([[Paragraph(escape(k), s.cell_key), self.cell(v, s.cell)]
                    for k, v in blk.rows[4:]], colWidths=[36 * mm, inner_w - 36 * mm])
        kv.setStyle(_style([
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, c["rule"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 1 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1 * mm),
        ]))
        why = blk.definition[0].upper() + blk.definition[1:] + "."
        rows = [Paragraph(escape(why), s.assess_why), grid, kv]
        if blk.references:
            rows.append(self.para(Free("References: " + "; ".join(blk.references)), s.note))
        return self.assessment_box(
            [self.head_row("Analyst assessment", self.badge(blk.status, status_role))], rows)

    def bullets(self, blk: Bullets):
        out = []
        for n, item in enumerate(blk.items, 1):
            out.append(Paragraph(inline(item, code_back=self.code_back), self.s.bullet,
                                 bulletText=f"{n}." if blk.ordered else "•"))
        out.append(Spacer(1, 1.5 * mm))
        return out

    def pre(self, blk: Pre):
        out = []
        block = CodeBlock(list(blk.lines), blk.title, self.c)
        if blk.title:
            style = ParagraphStyle("pt", parent=self.s.body, spaceBefore=2 * mm,
                                   spaceAfter=1 * mm)
            # Room for the title and the first lines of the block, or a new
            # page. keepWithNext would hand the title and the whole block to a
            # KeepTogether, which moves a long block to the next page in one
            # piece and leaves the page it was meant to start on nearly empty;
            # this keeps the title with its first lines and lets the rest split.
            first = min(len(blk.lines), CODE_LINES_WITH_TITLE)
            out.append(CondPageBreak(style.spaceBefore + style.leading + style.spaceAfter
                                     + first * block.leading + 2 * block.pad))
            out.append(Paragraph("<b>" + escape(blk.title) + "</b>", style))
        out.append(block)
        out.append(Spacer(1, 3 * mm))
        return out

    def block(self, blk):
        s = self.s
        if isinstance(blk, Para):
            return [self.para(blk.text, s.body)]
        if isinstance(blk, Note):
            return [self.para(blk.text, s.note)]
        if isinstance(blk, Heading):
            return [Paragraph(escape(blk.text), s.h3)]
        if isinstance(blk, Summary):
            return self.summary(blk)
        if isinstance(blk, ModelTable):
            return self.table(blk)
        if isinstance(blk, Pre):
            return self.pre(blk)
        if isinstance(blk, Bullets):
            return self.bullets(blk)
        if isinstance(blk, AssessmentEmpty):
            return self.assessment_empty(blk)
        if isinstance(blk, AssessmentFull):
            return self.assessment_full(blk)
        raise TypeError(type(blk).__name__)  # pragma: no cover

    def contents(self):
        s, c = self.s, self.c
        entries = []
        for sec in self.r.sections:
            page = self.pages.get(sec.key)
            badge = Badge(sec.reader_label, c["print-ink-2"], c["paper"], size=6.5, upper=True)
            entries.append([Paragraph(escape(sec.number), s.toc_n),
                            Paragraph(escape(sec.title), s.toc), badge,
                            Paragraph(str(page) if page else "", s.toc_p)])
        half = (len(entries) + 1) // 2
        left, right = entries[:half], entries[half:]
        col = (CONTENT_W - 8 * mm) / 2
        widths = [7 * mm, col - 7 * mm - 20 * mm - 6 * mm, 20 * mm, 6 * mm]
        rows = []
        for i in range(half):
            row = list(left[i]) + [""]
            row += list(right[i]) if i < len(right) else ["", "", "", ""]
            rows.append(row)
        t = Table(rows, colWidths=widths + [8 * mm] + widths)
        t.setStyle(_style([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (2, 0), (2, -1), "RIGHT"),
            ("ALIGN", (7, 0), (7, -1), "RIGHT"),
            ("LINEBELOW", (0, 0), (3, -1), 0.5, c["rule"], None, (1, 1.5)),
            ("LINEBELOW", (5, 0), (8, len(right) - 1), 0.5, c["rule"], None, (1, 1.5)),
            ("LEFTPADDING", (0, 0), (-1, -1), 1),
            ("RIGHTPADDING", (0, 0), (-1, -1), 1),
            ("TOPPADDING", (0, 0), (-1, -1), 0.7 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0.7 * mm),
        ]))
        head = Paragraph("Contents", ParagraphStyle("ch", parent=s.h3, spaceBefore=0,
                                                    keepWithNext=0))
        return [KeepTogether([head, t]), Spacer(1, 2 * mm)]

    def cover_flow(self):
        s, c = self.s, self.c
        rows = [[Paragraph(escape(k), s.cover_key), self.cell(v, s.cover_cell, 7)]
                for k, v in self.r.doc_control if k not in ("TLP", "Distribution")]
        t = Table(rows, colWidths=[48 * mm, CONTENT_W - 48 * mm])
        t.setStyle(_style([
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, c["rule"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 2 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), 1.4 * mm),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.4 * mm),
        ]))
        return [t]

    def story(self):
        out = [*self.cover_flow(), NextPageTemplate("body"), PageBreak()]
        out += self.contents()
        after_assessment = None
        for sec in self.r.sections:
            number = f"Appendix {sec.number}" if sec.appendix else sec.number
            if sec.appendix:
                out.append(PageBreak())
            else:
                out.append(CondPageBreak(30 * mm))
            heading = SectionHeading(number, sec.title, sec.reader_label, sec.key,
                                     self.new_pages, self.c)
            flows: list = []
            for blk in sec.blocks:
                flows += self.block(blk)
            # Keep the heading with the start of the section. ReportLab's
            # keepWithNext only pulls up a following flowable that _ktAllow
            # permits, and it refuses a KeepTogether (a _ContainerSpace), so a
            # section that opens with a boxed block (the summary, the key facts,
            # the analyst assessment) would strand its heading at the foot of a
            # page. The heading joins that block's own contents in one
            # KeepTogether. It must not wrap the block's KeepTogether itself:
            # KeepTogether.wrap reports a sentinel height to force a split, and
            # an outer one that measured it would never fit and would push every
            # such section onto a page of its own. A section that opens with a
            # paragraph or a splittable table keeps the existing keepWithNext,
            # which already works for those.
            if flows and isinstance(flows[0], KeepTogether):
                out.append(KeepTogether([heading, *flows[0]._content]))
                out += flows[1:]
            else:
                out.append(heading)
                out += flows
            if sec.key == "assessment":
                after_assessment = len(out)
        # Analyst text anywhere (the cover, the box, the change log) that held
        # characters the faces cannot draw is marked; the reader is told once,
        # under the assessment, that the Markdown holds the full text.
        if self.lost and after_assessment is not None:
            out.insert(after_assessment, self.para(T.GLYPHS_MISSING, self.s.note))
        return out


class _Doc(BaseDocTemplate):
    def __init__(self, buf, renderer: _Renderer, report: Report):
        super().__init__(
            buf, pagesize=A4, leftMargin=MARGIN_X, rightMargin=MARGIN_X,
            topMargin=MARGIN_TOP, bottomMargin=MARGIN_BOTTOM,
            title="Open directory triage: " + report.target, author="DirSift",
            subject=T.REPORT_KIND, creator=report.generator, producer=report.generator,
            keywords=[], invariant=1, pageCompression=1, initialFontName=SANS,
            initialFontSize=PT_BODY, lang="en",
        )
        cover_frame = Frame(MARGIN_X, 60 * mm, CONTENT_W, PAGE_H - 100 * mm - 60 * mm,
                            id="cover", leftPadding=0, rightPadding=0, topPadding=0,
                            bottomPadding=0)
        body_frame = Frame(MARGIN_X, MARGIN_BOTTOM, CONTENT_W,
                           PAGE_H - MARGIN_TOP - MARGIN_BOTTOM, id="body", leftPadding=0,
                           rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates([
            PageTemplate("cover", [cover_frame], onPage=renderer.cover_page),
            PageTemplate("body", [body_frame], onPage=renderer.body_page),
        ])


def render_pdf(report: Report) -> bytes:
    """The report as PDF bytes. Same model in, same bytes out."""
    pages: dict = {}
    total = 0
    data = b""
    for _ in range(4):
        renderer = _Renderer(report, pages, total)
        buf = io.BytesIO()
        doc = _Doc(buf, renderer, report)
        doc.build(renderer.story())
        data = buf.getvalue()
        new_total = doc.page
        if renderer.new_pages == pages and new_total == total:
            break
        pages, total = dict(renderer.new_pages), new_total
    return data
