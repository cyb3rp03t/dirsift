"""The print palette, read from the console's stylesheet.

The console and the PDF report share one set of colour tokens, defined once in
``web/static/dirsift.css``. This module reads the first top level ``:root``
block of that file and takes every ``--name: #hex;`` declaration in it, so a
colour changed in the stylesheet changes the report too. A token the report
needs and the block lacks is an error that names the token.
"""

from __future__ import annotations

import re
from functools import cache
from importlib.resources import files

#: Every token the PDF report draws with (template section 10).
REQUIRED = (
    "paper", "paper-raised", "paper-sunken", "rule", "rule-strong",
    "print-ink", "print-ink-2", "print-accent", "print-accent-strong", "print-accent-wash",
    "print-alert", "print-alert-wash", "print-caution", "print-caution-wash",
    "print-ok", "print-ok-wash",
    "ground", "ink", "lamp",
    "tlp-ground", "tlp-red", "tlp-amber", "tlp-green", "tlp-clear",
)

_DECL = re.compile(r"--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;")
_COMMENT = re.compile(r"/\*.*?\*/", re.S)


class MissingToken(KeyError):
    """A token the report needs is not in the stylesheet's :root block."""

    def __str__(self) -> str:
        return f"the stylesheet's :root block has no --{self.args[0]} token"


def root_block(css: str) -> str:
    """The body of the first ``:root`` rule at the top level of ``css``."""
    text = _COMMENT.sub("", css)
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0 and text.startswith(":root", i):
            open_at = text.index("{", i)
            depth_inner = 1
            j = open_at + 1
            while j < len(text) and depth_inner:
                if text[j] == "{":
                    depth_inner += 1
                elif text[j] == "}":
                    depth_inner -= 1
                j += 1
            return text[open_at + 1:j - 1]
        i += 1
    raise ValueError("no top level :root block in the stylesheet")


def parse_tokens(css: str, required: tuple[str, ...] = REQUIRED) -> dict[str, str]:
    """Token name (without the dashes) to lower case hex, for the :root block."""
    found = {name: value.lower() for name, value in _DECL.findall(root_block(css))}
    for name in required:
        if name not in found:
            raise MissingToken(name)
    return found


@cache
def tokens() -> dict[str, str]:
    css = files("dirsift.web").joinpath("static/dirsift.css").read_text(encoding="utf-8")
    return parse_tokens(css)
