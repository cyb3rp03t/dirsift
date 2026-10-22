"""What the PDF report is drawn with: the print tokens and the two type faces."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
from test_gates import _wheel_names

from dirsift.report_tokens import REQUIRED, MissingToken, parse_tokens, root_block, tokens

FONTS = Path(__file__).resolve().parents[1] / "src" / "dirsift" / "report_assets" / "fonts"
TTF = ("IBMPlexSans-Regular.ttf", "IBMPlexSans-SemiBold.ttf", "JetBrainsMono-Regular.ttf",
       "JetBrainsMono-Bold.ttf")
LICENCES = ("IBM-PLEX-SANS-OFL.txt", "JETBRAINS-MONO-OFL.txt")


def test_every_print_token_is_in_the_stylesheet():
    found = tokens()
    for name in REQUIRED:
        assert re.fullmatch(r"#[0-9a-f]{6}", found[name]), name


def test_a_missing_token_is_named():
    css = ":root { --paper: #ffffff; }\n@media print { :root { --rule: var(--x); } }"
    with pytest.raises(MissingToken) as caught:
        parse_tokens(css)
    assert "--paper-raised" in str(caught.value)


def test_only_the_first_top_level_root_block_is_read():
    css = (":root { --a: #000000; }\n@media print { :root { --a: #ffffff; } }\n"
           ":root { --a: #111111; }")
    assert parse_tokens(css, required=("a",)) == {"a": "#000000"}
    assert "--a" in root_block(css)


def test_the_font_files_match_their_recorded_hashes():
    readme = (FONTS / "README.txt").read_text(encoding="utf-8")
    recorded = dict((name, digest) for digest, name in
                    re.findall(r"^([0-9a-f]{64})  (\S+)$", readme, re.M))
    for name in TTF:
        digest = hashlib.sha256((FONTS / name).read_bytes()).hexdigest()
        assert recorded.get(name) == digest, name
    for name in LICENCES:
        assert "SIL Open Font License" in (FONTS / name).read_text(encoding="utf-8")


@pytest.mark.slow
def test_the_wheel_ships_the_report_fonts():
    shipped = {n.rsplit("/", 1)[1] for n in _wheel_names() if "/report_assets/fonts/" in n}
    for name in (*TTF, *LICENCES, "README.txt"):
        assert name in shipped, name
