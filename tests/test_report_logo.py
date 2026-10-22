"""The marks the PDF draws are the marks in the SVG files.

Two checks. The path data in ``report_logo`` is compared command by command
with the ``d`` attributes of the favicon and the lockup, so an edited SVG that
is not carried over fails here. Then each mark is drawn into a PDF, rasterised
and compared with a picture of the SVG drawn by a browser in its light colour
scheme: the shapes must overlap with an intersection over union of 0.98 or
better.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pypdfium2 as pdfium
import pytest
from PIL import Image
from reportlab.lib.colors import HexColor
from reportlab.pdfgen.canvas import Canvas

from dirsift import report_logo as L

REPO = Path(__file__).resolve().parents[1]
FAVICON = REPO / "src" / "dirsift" / "web" / "static" / "favicon.svg"
LOCKUPS = [REPO / "docs" / "dirsift-lockup-light.svg", REPO / "docs" / "dirsift-lockup-dark.svg"]
GOLDEN = Path(__file__).parent / "golden" / "logo"
TOLERANCE = 1e-6


def svg_paths(path: Path) -> list[str]:
    return re.findall(r'<path[^>]*\sd="([^"]+)"', path.read_text(encoding="utf-8"))


def same(a: list, b: list) -> bool:
    if len(a) != len(b):
        return False
    for x, y in zip(a, b, strict=True):
        if x[0] != y[0] or len(x) != len(y):
            return False
        if any(abs(p - q) > TOLERANCE for p, q in zip(x[1:], y[1:], strict=True)):
            return False
    return True


def test_the_favicon_geometry_matches_the_svg():
    d = svg_paths(FAVICON)
    shapes = L.FAVICON.shapes
    assert len(d) == len(shapes)
    for text, shape in zip(d, shapes, strict=True):
        assert same(L.parse_svg_path(text), list(shape.commands))


@pytest.mark.parametrize("path", LOCKUPS, ids=lambda p: p.stem)
def test_the_lockup_geometry_matches_the_svg(path):
    d = svg_paths(path)
    shapes = L.LOCKUP.shapes
    assert len(d) == len(shapes)
    for text, shape in zip(d, shapes, strict=True):
        assert same(L.parse_svg_path(text), list(shape.commands))
    marks = re.findall(r'<path[^>]*transform="translate\(12 12\) scale\(4\)"', path.read_text(
        encoding="utf-8"))
    assert len(marks) == 2 and all(s.offset == (12.0, 12.0) and s.scale == 4.0
                                   for s in shapes[:2])


def test_a_changed_path_is_caught():
    original = L.parse_svg_path(L.FAVICON_INK)
    moved = L.parse_svg_path(L.FAVICON_INK.replace("h11", "h10.5"))
    assert not same(original, moved)


def test_quadratic_curves_become_the_same_cubic():
    (move, cubic) = L.parse_svg_path("M0 0Q3 3 6 0")
    assert move == ("M", 0.0, 0.0)
    assert cubic[0] == "C"
    assert all(abs(a - b) < TOLERANCE for a, b in zip(cubic[1:], (2, 2, 4, 2, 6, 0),
                                                      strict=True))


def drawn(mark: L.Mark, width_px: int) -> Image.Image:
    """The mark drawn by the report's own code, one PDF point per view box unit."""
    buf = io.BytesIO()
    canvas = Canvas(buf, pagesize=(mark.width, mark.height), invariant=1)
    canvas.setFillColor(HexColor("#ffffff"))
    canvas.rect(0, 0, mark.width, mark.height, stroke=0, fill=1)
    L.draw(canvas, mark, 0, 0, mark.width,
           {"ink": HexColor("#070b12"), "accent": HexColor("#0a7aab")})
    canvas.save()
    page = pdfium.PdfDocument(buf.getvalue())[0]
    return page.render(scale=width_px / mark.width).to_pil().convert("RGB")


def masks(image: Image.Image) -> tuple[set, set]:
    """Pixels at least half covered by a mark, and by the accent.

    Half coverage is the edge both renderers agree on; the faint first
    antialiased pixel is where they differ, and it says nothing about the shape.
    """
    shape, accent = set(), set()
    width, height = image.size
    pixels = image.load()
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y][:3]
            luma = 0.299 * r + 0.587 * g + 0.114 * b
            if luma < 160:
                shape.add((x, y))
            if b - r > 60 and luma < 200:
                accent.add((x, y))
    return shape, accent


def iou(a: set, b: set) -> float:
    return len(a & b) / len(a | b)


@pytest.mark.parametrize(
    ("mark", "golden", "width"),
    [(L.FAVICON, "favicon-256.png", 256), (L.LOCKUP, "lockup-324.png", 324)],
    ids=["favicon", "lockup"],
)
def test_the_drawn_mark_overlaps_the_browser_picture(mark, golden, width):
    ours = drawn(mark, width)
    theirs = Image.open(GOLDEN / golden).convert("RGB")
    assert ours.size == theirs.size
    our_shape, our_accent = masks(ours)
    their_shape, their_accent = masks(theirs)
    assert iou(our_shape, their_shape) >= 0.98
    assert iou(our_accent, their_accent) >= 0.98
