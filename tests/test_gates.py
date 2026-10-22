"""Design gates for the web console that a generic hardcode lint cannot see.

The templates and the stylesheet share one token layer. These tests keep raw
values from creeping back in through the two doors a stylesheet linter does not
watch: inline style attributes in the templates, and colour literals written
straight into a rule instead of a token.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[1] / "src" / "dirsift" / "web"
TEMPLATES = sorted((WEB / "templates").glob("*.html"))
CSS = WEB / "static" / "dirsift.css"

STYLE_ATTR = re.compile(r"""\bstyle\s*=\s*(["'])(.*?)\1""", re.S)
STYLE_TAG = re.compile(r"<style\b", re.I)
COLOUR = re.compile(
    r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\s*\(",
)
PX = re.compile(r"(?<![\w.])-?\d*\.?\d+px\b")


def inline_declarations(html: str) -> list[tuple[str, str]]:
    """Every (property, value) pair set through a style attribute."""
    pairs = []
    for match in STYLE_ATTR.finditer(html):
        for part in match.group(2).split(";"):
            if not part.strip():
                continue
            prop, _, value = part.partition(":")
            pairs.append((prop.strip(), value.strip()))
    return pairs


def css_declarations(css: str) -> list[tuple[str, str, str]]:
    """Every (enclosing prelude, property, value) in a flat or @media nested sheet."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    out = []
    preludes: list[str] = []
    chunk = ""
    for char in css:
        if char == "{":
            preludes.append(chunk.strip())
            chunk = ""
        elif char == "}":
            prelude = " ".join(preludes)
            for part in chunk.split(";"):
                prop, sep, value = part.partition(":")
                if sep and prop.strip():
                    out.append((prelude, prop.strip(), value.strip()))
            chunk = ""
            if preludes:
                preludes.pop()
        elif char == ";" and not preludes:
            chunk = ""  # a top level at-rule such as @import
        else:
            chunk += char
    return out


def test_the_checkers_see_what_they_are_for() -> None:
    sample = """
    :root { --ink: #fff; --shade: rgb(0 0 0 / 50%); --hair: 1px; }
    .a { color: #abc; border: 1px solid var(--ink); }
    @media (max-width: 720px) { .b { background: hsl(0 0% 0%); } }
    """
    found = css_declarations(sample)
    assert (".a", "color", "#abc") in found
    raw_colours = [p for _, p, v in found if COLOUR.search(v) and not p.startswith("--")]
    assert raw_colours == ["color", "background"]
    raw_px = [p for _, p, v in found if PX.search(v) and not p.startswith("--")]
    assert raw_px == ["border"]
    assert inline_declarations('<p style="margin: 0; --fill: 3%">') == [
        ("margin", "0"),
        ("--fill", "3%"),
    ]


def test_templates_exist() -> None:
    assert len(TEMPLATES) >= 10


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_templates_set_only_custom_properties_inline(template: Path) -> None:
    """Layout lives in classes. An inline style may only hand a server computed
    number to the stylesheet, as a custom property the stylesheet then reads."""
    html = template.read_text(encoding="utf-8")
    assert not STYLE_TAG.search(html), f"{template.name} carries a <style> block"
    offenders = [p for p, _ in inline_declarations(html) if not p.startswith("--")]
    assert offenders == [], f"{template.name} sets {offenders} inline; use a class"


def test_inline_custom_properties_are_read_by_the_stylesheet() -> None:
    css = CSS.read_text(encoding="utf-8")
    for template in TEMPLATES:
        for prop, _ in inline_declarations(template.read_text(encoding="utf-8")):
            assert f"var({prop}" in css, f"{template.name} sets {prop}, nothing reads it"


def test_the_run_page_sets_nothing_inline() -> None:
    """The case file draws no bars: every width it needs comes from a class. The
    one inline door left (a server computed --fill) stays open for later use."""
    html = (WEB / "templates" / "run.html").read_text(encoding="utf-8")
    props = [p for p, _ in inline_declarations(html)]
    assert set(props) <= {"--fill"}


def test_colours_are_written_only_as_tokens() -> None:
    raw = [
        f"{prelude} {{ {prop}: {value} }}"
        for prelude, prop, value in css_declarations(CSS.read_text(encoding="utf-8"))
        if COLOUR.search(value) and not prop.startswith("--")
    ]
    assert raw == [], "colour literal outside a token definition"


def test_pixel_lengths_are_written_only_as_tokens() -> None:
    """Scoped to px on purpose: borders, radii and blurs are where a stray pixel
    value drifts from the scale. rem, ch and percentage layout lengths are left
    to the token pass that reshapes the scale."""
    raw = [
        f"{prelude} {{ {prop}: {value} }}"
        for prelude, prop, value in css_declarations(CSS.read_text(encoding="utf-8"))
        if PX.search(value) and not prop.startswith("--")
    ]
    assert raw == [], "pixel length outside a token definition"


# The visual wave gates (G1 to G6)
#
# One accent: the ground is a deep blue dark, the interface stays quiet, and the
# single cyan accent lands only on the evidence. These gates keep that language
# from eroding the way the sprawling dark-SaaS look did: no glow or gradient, no
# shadow except the one overlay, the accent only where it belongs, one type
# family, and nothing fetched over the network. The accent token keeps its lamp
# name from the earlier layer; only its value changed, so these gates hold.

FONTS = WEB / "static" / "fonts"
URL_IN_VALUE = re.compile(r"""url\(\s*["']?([^"')]+)["']?\s*\)""")
FONT_FACE_URL = re.compile(
    r"@font-face\s*\{[^}]*?url\(\s*[\"']?([^\"')]+)[\"']?\s*\)[^}]*?\}", re.S
)
GRADIENTS = ("linear-gradient", "radial-gradient", "conic-gradient")

# G3: the only rules allowed to paint with the lamp token. A selector earns a
# place here because the thing it styles is evidence, not chrome. A selector
# matches whole: ".driver" allows ".driver.is-lead" and ".driver .lead-tag",
# never ".driver-score", which needs a line and a reason of its own. If this
# list grows, the diff says so and the reason is on the record.
LAMP_SELECTORS = (
    ".button",  # the single filled primary action on a page (Start scan)
    ".is-selected",  # the open file row's 2px edge in the listing
    "pre.source",  # an indicator mark in the contents, and its line number
    ".driver",  # the lead driver card, its lead tag, and the driver dot on a row
    ".driver-score",  # the likely-driver score on a driver card
    ".driver-badge",  # the driver score badge on a listing row
    ".driver-node",  # a likely driver's node in the drivers figure
    # In the case file layout the accent also marks the
    # one choice a control holds right now, because that choice decides which
    # evidence is on screen. Nothing decorative is added.
    ".spy",  # navigation: the section being read
    ".facet",  # the one indicator kind the timeline is showing
    ".pick",  # the files picked for a YARA rule
    ".prod",  # the detection format whose preview is open
    ".tl",  # the timeline dot on an indicator worth reading first
    # The mark: the sift band through the D is the one accent the logo carries,
    # the same cut on every page, so it is identity, not decoration.
    ".brand-mark",  # the sift band in the logo at the top left
)
LAMP_TOKEN = "var(--lamp"


def _allowed(prelude: str) -> bool:
    """True when the prelude names an allowed selector whole, not as a prefix."""
    return any(
        re.search(re.escape(sel) + r"(?![\w-])", prelude) for sel in LAMP_SELECTORS
    )


def lamp_offenders(css: str) -> list[str]:
    """Every declaration that reads a lamp token outside the allowed selectors."""
    offenders = []
    for prelude, prop, value in css_declarations(css):
        if prop.startswith("--"):
            continue  # the token layer defines the lamp; it does not apply it
        if LAMP_TOKEN in value and not _allowed(prelude):
            offenders.append(f"{prelude} {{ {prop}: {value} }}")
    return offenders


def _css() -> str:
    return CSS.read_text(encoding="utf-8")


def test_g1_no_gradients_or_blur() -> None:
    """No glow, gradient, or blur anywhere: the surfaces are flat colour."""
    offenders = []
    for prelude, prop, value in css_declarations(_css()):
        if prop.startswith("--"):
            continue
        if any(g in value for g in GRADIENTS):
            offenders.append(f"{prelude} {{ {prop}: {value} }}")
        if prop == "backdrop-filter":
            offenders.append(f"{prelude} {{ {prop}: {value} }}")
        if prop == "filter" and "blur(" in value:
            offenders.append(f"{prelude} {{ {prop}: {value} }}")
    assert offenders == [], f"gradient or blur present: {offenders}"


def test_g2_box_shadow_is_only_focus_or_the_one_overlay() -> None:
    """The only shadows are the focus ring and a single overlay, and the overlay
    rides only on the toast."""
    bad = []
    overlay_selectors = []
    for prelude, prop, value in css_declarations(_css()):
        if prop != "box-shadow":
            continue
        v = value.strip()
        if not (v.startswith("var(--focus") or v.startswith("var(--shadow-overlay)")):
            bad.append(f"{prelude} {{ box-shadow: {v} }}")
        if "var(--shadow-overlay)" in v:
            overlay_selectors.append(prelude)
    assert bad == [], f"a box-shadow that is neither focus nor the overlay: {bad}"
    stray = [p for p in overlay_selectors if ".toast" not in p]
    assert stray == [], f"the overlay shadow used outside the toast: {stray}"


def test_g3_the_lamp_burns_only_on_the_evidence() -> None:
    """Every rule that reads a lamp token sits on an allowed selector."""
    offenders = lamp_offenders(_css())
    assert offenders == [], f"the lamp burns off the evidence: {offenders}"


@pytest.mark.parametrize(
    "rule",
    [
        ".title { color: var(--lamp) }",
        ".button-row { border-color: var(--lamp) }",
        ".driver-tag { background: var(--lamp-wash) }",
        ".sec-n { color: var(--lamp) }",
        ".spyglass a { color: var(--lamp) }",
    ],
)
def test_g3_rejects_a_selector_that_only_shares_a_prefix(rule: str) -> None:
    """The gate itself: a near name of an allowed selector does not get through."""
    assert lamp_offenders(rule) != []


def test_g3_lets_an_allowed_selector_through_with_its_modifiers() -> None:
    css = (
        ".driver.is-lead { border-color: var(--lamp) }\n"
        '.facet[aria-pressed="true"] { color: var(--lamp) }'
    )
    assert lamp_offenders(css) == []


def test_g3_the_include_pills_stay_neutral() -> None:
    """Every include pill on the Detections form starts checked, so the lamp on a
    checked pill would burn a whole row at once. Only the one active timeline
    facet carries it."""
    burning = [
        prelude
        for prelude, prop, value in css_declarations(_css())
        if LAMP_TOKEN in value and not prop.startswith("--") and "input:checked" in prelude
        and ".facet" in prelude
    ]
    assert burning == [], burning


def test_g4_space_grotesk_is_gone_and_every_face_file_exists() -> None:
    """The display face is retired from the stylesheet, the templates and the
    vendored files, and every @font-face points at a file that is actually here."""
    css = _css()
    assert "space grotesk" not in css.lower()
    assert "space-grotesk" not in css.lower()
    for template in TEMPLATES:
        text = template.read_text(encoding="utf-8").lower()
        assert "space grotesk" not in text and "space-grotesk" not in text, template.name
    stale = [p.name for p in FONTS.glob("*") if "space-grotesk" in p.name.lower()]
    assert stale == [], f"a Space Grotesk file is still vendored: {stale}"

    faces = FONT_FACE_URL.findall(css)
    assert faces, "no @font-face url found"
    for url in faces:
        assert url.startswith("/static/"), url
        target = WEB / "static" / url[len("/static/"):]
        assert target.exists(), f"@font-face points at a missing file: {url}"


def test_g5_nothing_is_loaded_over_the_network() -> None:
    """Air gap: no stylesheet, script or url() reaches out to http(s). Outbound
    <a> links (Open in browser, VirusTotal) do not load a resource, so they do
    not count."""
    css = _css()
    for url in URL_IN_VALUE.findall(css):
        assert not url.lower().startswith(("http://", "https://")), f"css url(): {url}"
    link = re.compile(r"""<link\b[^>]*\bhref\s*=\s*["']https?://""", re.I)
    script = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']https?://""", re.I)
    url_http = re.compile(r"""url\(\s*["']?https?://""", re.I)
    for template in TEMPLATES + [WEB / "templates" / "base.html"]:
        text = template.read_text(encoding="utf-8")
        assert not link.search(text), f"{template.name} loads a remote stylesheet"
        assert not script.search(text), f"{template.name} loads a remote script"
        assert not url_http.search(text), f"{template.name} has a remote url()"


@functools.lru_cache(maxsize=1)
def _wheel_names() -> tuple[str, ...]:
    """Build the wheel once for every gate that reads what it ships."""
    import subprocess
    import tempfile
    import zipfile

    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as out:
        try:
            built = subprocess.run(
                ["uv", "build", "--wheel", "--offline", "-o", out],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"wheel build unavailable: {exc}")
        if built.returncode != 0:
            pytest.skip(f"wheel build failed offline: {built.stderr.strip()[-200:]}")
        wheels = list(Path(out).glob("*.whl"))
        assert wheels, "no wheel produced"
        return tuple(zipfile.ZipFile(wheels[0]).namelist())


@pytest.mark.slow
def test_g6_the_wheel_ships_the_fonts() -> None:
    """Build the wheel and prove the vendored faces and their licences travel
    with it, so an offline install still draws in the right type."""
    names = _wheel_names()
    shipped = {n for n in names if "/web/static/fonts/" in n}
    woff2 = {n.rsplit("/", 1)[1] for n in shipped if n.endswith(".woff2")}
    licences = {n.rsplit("/", 1)[1] for n in shipped if n.endswith(".txt")}
    assert "ibm-plex-sans-latin.woff2" in woff2, woff2
    assert "ibm-plex-sans-latin-ext.woff2" in woff2, woff2
    assert "jetbrains-mono-latin.woff2" in woff2, woff2
    assert "jetbrains-mono-latin-ext.woff2" in woff2, woff2
    assert "IBM-PLEX-SANS-OFL.txt" in licences, licences
    assert "JETBRAINS-MONO-OFL.txt" in licences, licences
    assert not any("space-grotesk" in n.lower() for n in shipped), shipped


@pytest.mark.slow
def test_g7_the_wheel_ships_the_favicon() -> None:
    """The tab icon travels with the package, so an offline install has it."""
    static = {n.rsplit("/", 1)[1] for n in _wheel_names() if "/web/static/" in n}
    assert "favicon.svg" in static, static
    assert "favicon-32.png" in static, static


# The mark. The favicon is the one file that holds its own colours: a browser
# draws it outside the page, where no token reaches, so it carries the ink and
# lamp values for a light and a dark tab bar and switches on the scheme. The
# README lockups are the same case (GitHub shows them as images). Everything
# the console draws with the mark takes its colour from the tokens.

FAVICON = WEB / "static" / "favicon.svg"
DOCS = Path(__file__).resolve().parents[1] / "docs"
LOCKUPS = (DOCS / "dirsift-lockup-dark.svg", DOCS / "dirsift-lockup-light.svg")
MARK_COLOURS = {"#070b12", "#0a7aab", "#e9eefa", "#56c7f2"}


def test_the_favicon_holds_only_the_marks_own_colours() -> None:
    svg = FAVICON.read_text(encoding="utf-8")
    colours = {c.lower() for c in re.findall(r"#[0-9a-fA-F]{6}\b", svg)}
    assert colours and colours <= MARK_COLOURS, colours
    assert "prefers-color-scheme: dark" in svg
    assert 'viewBox="0 0 16 16"' in svg


def test_the_readme_lockups_are_outlines_only() -> None:
    """GitHub loads no web font for an image, so the wordmark is drawn, not typed."""
    for lockup in LOCKUPS:
        svg = lockup.read_text(encoding="utf-8")
        assert "<text" not in svg and "font-family" not in svg, lockup.name
        colours = {c.lower() for c in re.findall(r"#[0-9a-fA-F]{6}\b", svg)}
        assert colours <= MARK_COLOURS, (lockup.name, colours)


def test_the_readme_opens_on_the_lockup_for_both_themes() -> None:
    readme = (DOCS.parent / "README.md").read_text(encoding="utf-8")
    head = readme.split("[![CI]", 1)[0]
    assert "<picture>" in head
    assert 'media="(prefers-color-scheme: dark)" srcset="docs/dirsift-lockup-dark.svg"' in head
    assert 'src="docs/dirsift-lockup-light.svg"' in head
    assert 'alt="DirSift"' in head


def test_the_brand_mark_takes_its_colour_from_tokens() -> None:
    fills = [
        (prelude, value)
        for prelude, prop, value in css_declarations(_css())
        if ".brand-mark" in prelude and prop == "fill"
    ]
    assert fills, "the mark has no fill rules"
    assert all(value.startswith("var(--") for _, value in fills), fills


def test_the_focus_ring_shows_outside_its_gap() -> None:
    """The ring is a gap in the ground colour with the ink ring outside it. Box
    shadows paint the first layer on top, so the outer layer has to spread
    further than the gap, or the gap covers the ring and focus is invisible."""
    tokens = {prop: value for _, prop, value in css_declarations(CSS.read_text("utf-8"))}
    layers = [layer.split() for layer in tokens["--focus-ring"].split(",")]
    spreads = [float(layer[3].removesuffix("px")) for layer in layers]
    assert len(spreads) == 2
    assert spreads[1] > spreads[0]