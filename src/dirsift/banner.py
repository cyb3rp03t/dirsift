"""Terminal banner.

Printed at the top of every command. Goes to stderr on purpose: piping
``dirsift scan ... > run.json`` must leave the JSON clean.

Letters are rendered one at a time and joined with a single space. Rendering
the whole word in one pyfiglet call packs the glyphs edge to edge, and in
``ansi_shadow`` a narrow ``I`` wedged between two wide neighbours reads as a
wall rather than a letter.
"""

from __future__ import annotations

import os
import shutil
import sys

import pyfiglet
from rich.console import Console

FONT = "ansi_shadow"
GAP = 1
NAME = "DIRSIFT"
TAGLINE = "someone left the lights on"
SIGNATURE = "by cyb3rp03t"

_ART_CACHE: dict[tuple[str, str, int], str] = {}


def _spaced(word: str, font: str = FONT, gap: int = GAP) -> str:
    """Render ``word`` with each glyph separated by ``gap`` spaces."""
    key = (word, font, gap)
    if key in _ART_CACHE:
        return _ART_CACHE[key]

    parts = [pyfiglet.figlet_format(ch, font=font).rstrip("\n").split("\n") for ch in word]
    height = max(len(p) for p in parts)
    parts = [p + [""] * (height - len(p)) for p in parts]
    widths = [max(len(line) for line in p) for p in parts]

    rows = []
    for r in range(height):
        rows.append((" " * gap).join(parts[i][r].ljust(widths[i]) for i in range(len(parts))))

    art = "\n".join(rows).rstrip()
    _ART_CACHE[key] = art
    return art


def banner(sub: str = "", *, force: bool | None = None) -> None:
    """Print the banner to stderr.

    ``sub`` is a one-line note about what this invocation is doing, e.g.
    ``banner("scan | depth 3 | 1 req/s")``.

    Set ``DIRSIFT_NO_BANNER=1`` to suppress it. A terminal too narrow for the
    figlet art falls back to a single line instead of wrapping into rubble.
    """
    if force is None and os.environ.get("DIRSIFT_NO_BANNER"):
        return

    console = Console(stderr=True)
    art = _spaced(NAME)
    art_width = max(len(line) for line in art.split("\n"))
    term_width = shutil.get_terminal_size(fallback=(80, 24)).columns

    if art_width > term_width and sys.stderr.isatty():
        console.print(f"[bold cyan]{NAME}[/] [dim]{SIGNATURE}[/]")
    else:
        console.print(art, style="bold cyan", highlight=False)
        # Letter-spaced tagline only while it still fits under the art.
        spaced_tagline = " ".join(TAGLINE)
        tagline = spaced_tagline if len(spaced_tagline) <= art_width else TAGLINE
        console.print(tagline.center(art_width), style="cyan", highlight=False)
        console.print(SIGNATURE.center(art_width), style="dim", highlight=False)

    if sub:
        console.print(f"  {sub}\n", style="dim", highlight=False)
    else:
        console.print("")
