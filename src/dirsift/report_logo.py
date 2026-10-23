"""The Sift Mark and the DirSift lockup as path data, for the PDF report.

The marks are drawn with the PDF writer's own path commands rather than by
reading an SVG at run time: the report needs no SVG library, and the lockup
file does not have to ship in the package. The path data below is the
geometry of ``web/static/favicon.svg`` and ``docs/dirsift-lockup-*.svg``,
turned into absolute commands (moves, lines, cubic curves, closes) with each
quadratic curve raised to the cubic that draws the same curve. A test parses
the SVG files and compares them command by command, so an edit to a logo that
is not carried here fails the suite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

Command = tuple

_TOKEN = re.compile(r"[MmLlHhVvQqCcZz]|-?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")


def parse_svg_path(d: str) -> list[Command]:
    """SVG path data as absolute M, L, C and Z commands.

    Covers the commands the DirSift marks use: M, L, H, V, Q, C and Z, each in
    its absolute and relative form. Repeated coordinates after a command repeat
    it, as SVG allows (after M they are lines).
    """
    tokens = _TOKEN.findall(d)
    out: list[Command] = []
    x = y = 0.0
    start = (0.0, 0.0)
    cmd = ""
    i = 0

    def num() -> float:
        nonlocal i
        value = float(tokens[i])
        i += 1
        return value

    while i < len(tokens):
        if re.fullmatch(r"[A-Za-z]", tokens[i]):
            cmd = tokens[i]
            i += 1
        elif not cmd:
            raise ValueError("path data starts with a number")
        rel = cmd.islower()
        op = cmd.upper()
        if op == "Z":
            out.append(("Z",))
            x, y = start
            continue
        if op == "M":
            nx, ny = num(), num()
            if rel:
                nx, ny = x + nx, y + ny
            out.append(("M", nx, ny))
            x, y = start = (nx, ny)
            cmd = "l" if rel else "L"
        elif op == "L":
            nx, ny = num(), num()
            if rel:
                nx, ny = x + nx, y + ny
            out.append(("L", nx, ny))
            x, y = nx, ny
        elif op == "H":
            nx = num()
            if rel:
                nx += x
            out.append(("L", nx, y))
            x = nx
        elif op == "V":
            ny = num()
            if rel:
                ny += y
            out.append(("L", x, ny))
            y = ny
        elif op == "Q":
            qx, qy, nx, ny = num(), num(), num(), num()
            if rel:
                qx, qy, nx, ny = x + qx, y + qy, x + nx, y + ny
            c1 = (x + 2 / 3 * (qx - x), y + 2 / 3 * (qy - y))
            c2 = (nx + 2 / 3 * (qx - nx), ny + 2 / 3 * (qy - ny))
            out.append(("C", c1[0], c1[1], c2[0], c2[1], nx, ny))
            x, y = nx, ny
        elif op == "C":
            vals = [num() for _ in range(6)]
            if rel:
                vals = [v + (x if k % 2 == 0 else y) for k, v in enumerate(vals)]
            out.append(("C", *vals))
            x, y = vals[4], vals[5]
        else:  # pragma: no cover - the marks use nothing else
            raise ValueError(f"unsupported path command {cmd}")
    return out


@dataclass(frozen=True)
class Shape:
    """One filled path: its commands, the role that picks its colour, and its
    fill rule. ``scale`` and ``offset`` place it in the drawing's view box."""

    role: str  # "ink" or "accent"
    commands: tuple[Command, ...]
    even_odd: bool
    scale: float = 1.0
    offset: tuple[float, float] = (0.0, 0.0)


@dataclass(frozen=True)
class Mark:
    width: float
    height: float
    shapes: tuple[Shape, ...]


def _shape(role: str, d: str, even_odd: bool, scale: float = 1.0,
           offset: tuple[float, float] = (0.0, 0.0)) -> Shape:
    return Shape(role, tuple(parse_svg_path(d)), even_odd, scale, offset)


# The favicon: the Sift Mark on its 16 unit grid.
FAVICON_INK = "M1 1h11l3 3v1h-2l-2-2H3v4h12v5l-3 3H1v-4h2v2h8l2-2V9H1z"
FAVICON_ACCENT = "M3 7h10v2H3z"

# The detailed Sift Mark of the lockup, on the same grid, placed by
# translate(12 12) scale(4) in a 324 by 88 view box.
LOCKUP_MARK_INK = (
    "M1 1h11l3 3v2.75L13 6.25V5l-2-2H3v2.75L15 8.75V12l-3 3H1V9.25L3 9.75V13h8l2-2v-.75L1 7.25z"
)
LOCKUP_MARK_ACCENT = "M3 5.75 13 8.25v2L3 7.75z"

# The DirSift wordmark of the lockup, in view box units.
LOCKUP_WORDMARK = (
    "M98.26 59.68V28.32H107.59Q110.76 28.32 113.1 29.53Q115.44 30.74 116.74 32.93Q118.04 35.13 "
    "118.04 38.1V49.85Q118.04 52.81 116.74 55.02Q115.44 57.23 113.1 58.46Q110.76 59.68 107.59 "
    "59.68ZM103.64 54.74H107.59Q109.92 54.74 111.29 53.42Q112.67 52.11 112.67 49.85V38.1Q112.67 "
    "35.89 111.29 34.58Q109.92 33.26 107.59 33.26H103.64ZM130.71 59.68V54.95H137.01V33.05H130.71"
    "V28.32H148.72V33.05H142.42V54.95H148.72V59.68ZM161.89 59.68V28.32H171.83Q174.95 28.32 177.25 "
    "29.47Q179.56 30.62 180.83 32.72Q182.1 34.81 182.1 37.64Q182.1 40.75 180.55 43.1Q179 45.45 "
    "176.34 46.44L182.53 59.68H176.55L171.09 47.22H167.24V59.68ZM167.24 42.51H171.83Q174.08 "
    "42.51 175.38 41.24Q176.68 39.98 176.68 37.82Q176.68 35.59 175.38 34.31Q174.08 33.03 171.83 "
    "33.03H167.24ZM203.37 60.11Q200.15 60.11 197.8 59.03Q195.45 57.95 194.17 55.96Q192.89 53.98 "
    "192.87 51.27H198.25Q198.25 53.18 199.63 54.29Q201.02 55.4 203.44 55.4Q205.75 55.4 207.05 "
    "54.32Q208.35 53.24 208.35 51.33Q208.35 49.74 207.42 48.57Q206.5 47.41 204.81 46.97L201.19 "
    "45.99Q197.51 45.03 195.5 42.57Q193.48 40.11 193.48 36.65Q193.48 33.99 194.7 32.02Q195.91 "
    "30.05 198.12 28.96Q200.33 27.87 203.35 27.87Q207.88 27.87 210.56 30.22Q213.24 32.57 213.26 "
    "36.52H207.88Q207.88 34.68 206.69 33.63Q205.49 32.58 203.29 32.58Q201.17 32.58 200.01 "
    "33.57Q198.86 34.56 198.86 36.36Q198.86 37.96 199.75 39.12Q200.64 40.27 202.3 40.72L206.04 "
    "41.75Q209.78 42.71 211.75 45.13Q213.72 47.56 213.72 51.12Q213.72 53.79 212.43 55.83Q211.14 "
    "57.86 208.82 58.99Q206.5 60.11 203.37 60.11ZM226.08 59.68V54.95H232.38V33.05H226.08V28.32"
    "H244.09V33.05H237.79V54.95H244.09V59.68ZM257.44 59.68V28.3H276.92V33.28H262.73V41.69H275.8"
    "V46.67H262.81V59.68ZM295.98 59.68V33.28H287.76V28.3H309.57V33.28H301.35V59.68Z"
)

FAVICON = Mark(
    16.0,
    16.0,
    (
        _shape("ink", FAVICON_INK, True),
        _shape("accent", FAVICON_ACCENT, True),
    ),
)

LOCKUP = Mark(
    324.0,
    88.0,
    (
        _shape("ink", LOCKUP_MARK_INK, True, 4.0, (12.0, 12.0)),
        _shape("accent", LOCKUP_MARK_ACCENT, False, 4.0, (12.0, 12.0)),
        _shape("ink", LOCKUP_WORDMARK, False),
    ),
)

#: The Markdown report's second line carries the favicon drawing as a data URI.
#: This is the exact SVG text it encodes; a test holds the base64 form fixed.
FAVICON_SVG_INLINE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16" '
    'role="img" aria-label="DirSift"> <title>DirSift</title> <style>.k{fill:#070b12}'
    ".a{fill:#0a7aab} @media (prefers-color-scheme: dark){.k{fill:#e9eefa}.a{fill:#56c7f2}}"
    '</style> <path class="k" fill-rule="evenodd" d="' + FAVICON_INK + '"/> '
    '<path class="a" fill-rule="evenodd" d="' + FAVICON_ACCENT + '"/> </svg>'
)


def draw(canvas, mark: Mark, x: float, y: float, width: float, colours: dict) -> float:
    """Draw ``mark`` with its lower left corner at (x, y), ``width`` points
    wide, filling each shape with ``colours[role]``. Returns the height drawn.

    SVG counts y downwards and PDF upwards, so the view box is flipped once
    here rather than in the data.
    """
    s = width / mark.width
    height = mark.height * s
    canvas.saveState()
    canvas.translate(x, y + height)
    canvas.scale(s, -s)
    for shape in mark.shapes:
        canvas.saveState()
        canvas.translate(*shape.offset)
        canvas.scale(shape.scale, shape.scale)
        path = canvas.beginPath()
        for command in shape.commands:
            op = command[0]
            if op == "M":
                path.moveTo(command[1], command[2])
            elif op == "L":
                path.lineTo(command[1], command[2])
            elif op == "C":
                path.curveTo(*command[1:])
            else:
                path.close()
        canvas.setFillColor(colours[shape.role])
        canvas.drawPath(path, stroke=0, fill=1, fillMode=0 if shape.even_odd else 1)
        canvas.restoreState()
    canvas.restoreState()
    return height
