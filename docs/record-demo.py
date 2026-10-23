"""Records the demo video and the short preview animation for the README.

Usage, from the repository root:

    uv run --with playwright python docs/record-demo.py
    uv run --with playwright python docs/record-demo.py --ffmpeg path/to/ffmpeg

Writes docs/demo.mp4, every part behind a short title card. Needs an ffmpeg
build with libx264 and a Playwright Chromium (``playwright install chromium``).

Nothing here touches a real host. The target is the folder built by
docs/make-demo-target.py, served on 127.0.0.1; the console runs against a
throwaway runs folder, so the dashboard shows only the demo run.

How it is put together:

  * The terminal parts are real commands. Each one runs once, its output is
    captured line by line with the time it arrived, and a page that looks like
    a terminal plays it back at that pace.
  * The console parts are the real console in Chromium, captured with the
    DevTools screencast, which keeps text sharp where a compressed browser
    recording would blur it.
  * Title cards are rendered from HTML in the console's own font and colours.
  * ffmpeg cuts, joins and encodes.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from string import Template

from playwright.async_api import Page, async_playwright

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
ASSETS = DOCS / "demo-assets"
STATIC = REPO / "src" / "dirsift" / "web" / "static"
TARGET_DIR = Path(tempfile.gettempdir()) / "dirsift-demo-target"

WIDTH, HEIGHT = 1440, 900
FPS = 30
STAGE = "http://stage.demo/"

#: The console palette, read from dirsift.css so the cards follow it.
TOKENS = ("ground", "surface-1", "surface-2", "line", "line-strong", "ink", "ink-2",
          "lamp", "ok", "caution", "alert")

#: One card before every part: number, title, one line under it.
CARDS = [
    ("01", "Scan from the terminal",
     "dirsift scan walks only what the listing links, one request at a time."),
    ("02", "The same scan in the console",
     "Start it from the dashboard and watch the walk as it goes."),
    ("03", "Case file",
     "Who served it, which files drive the rest, and how they name each other."),
    ("04", "Inventory and preview",
     "Files grouped by what their first bytes say. Read each head, step with j and k."),
    ("05", "Indicators",
     "Pulled from the file heads, defanged, filtered by kind."),
    ("06", "YARA from your picks",
     "Tick the files; each rule keys on what that file carried, not on its hash."),
    ("07", "Rule packs: twenty five formats",
     "SIEM hunts, block lists, IDS and DNS, sharing. One saved run, every tool you run."),
    ("08", "Report",
     "PDF or Markdown, with the TLP label you choose for each download."),
    ("09", "The CLI, offline",
     "detections, stix and report read the saved run and send nothing."),
]

#: The rule pack chapter walks the families in the console's order. The caption
#: names the family and the format on screen; the console itself is unchanged.
SHOWCASE = [
    ("siem", "SIEM hunts"),
    ("blocklist", "Block lists"),
    ("network", "IDS and DNS"),
    ("share", "Sharing"),
    ("existing", "Run exports"),
]
#: Within a family, the hunts most analysts run come first.
SHOWCASE_FIRST = ["splunk", "kql", "elastic-esql", "elastic-rules", "secops-yaral",
                  "qradar-aql", "logscale-cql", "sigma"]

BANNER = r"""
 ____  _      ____  _  __ _
|  _ \(_)_ __/ ___|(_)/ _| |_
| | | | | '__\___ \| | |_| __|
| |_| | | |   ___) | |  _| |_
|____/|_|_|  |____/|_|_|  \__|
  demo recorder
"""


# small helpers


def free(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


def wait_port(port: int, seconds: float = 20) -> None:
    end = time.time() + seconds
    while time.time() < end:
        if not free(port):
            return
        time.sleep(0.2)
    raise SystemExit(f"nothing answered on 127.0.0.1:{port}")


def tokens() -> dict[str, str]:
    css = (STATIC / "dirsift.css").read_text(encoding="utf-8")
    found = {}
    for name in TOKENS:
        match = re.search(r"--" + re.escape(name) + r":\s*(#[0-9a-fA-F]{3,8})", css)
        if match:
            found[name] = match.group(1)
    return found


def run(cmd: list[str], **kw) -> None:
    subprocess.run(cmd, check=True, **kw)


# terminal capture: run a real command, keep each line and when it arrived

#: Rich decides a Windows pipe is a legacy console and drops colour. The
#: capture is played back in a page that reads ANSI, so tell it otherwise.
CLI = (
    "import sys, rich.console as rc; rc.detect_legacy_windows = lambda: False; "
    "from dirsift.cli import app; app(prog_name='dirsift')"
)

SGR = re.compile(r"\x1b\[([0-9;]*)m")
OTHER_ESC = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
COLOURS = {30: "k", 31: "r", 32: "g", 33: "y", 34: "b", 35: "m", 36: "c", 37: "w",
           90: "k", 91: "r", 92: "g", 93: "y", 94: "b", 95: "m", 96: "c", 97: "w"}


def ansi_to_html(line: str) -> str:
    """One line of SGR coloured text as HTML spans. Other escapes are dropped."""
    out, classes, pos = [], set(), 0
    line = OTHER_ESC.sub(lambda m: m.group(0) if m.group(0).endswith("m") else "", line)
    for match in SGR.finditer(line):
        if match.start() > pos:
            out.append(span(line[pos:match.start()], classes))
        codes = [int(c) for c in match.group(1).split(";") if c] or [0]
        i = 0
        while i < len(codes):
            code = codes[i]
            if code == 0:
                classes = set()
            elif code == 1:
                classes.add("bo")
            elif code == 2:
                classes.add("di")
            elif code == 22:
                classes -= {"bo", "di"}
            elif code in COLOURS:
                classes = {c for c in classes if not c.startswith("f")} | {"f" + COLOURS[code]}
            elif code == 39:
                classes = {c for c in classes if not c.startswith("f")}
            elif code in (38, 48):
                i += 2 if i + 1 < len(codes) and codes[i + 1] == 5 else 4
            i += 1
        pos = match.end()
    out.append(span(line[pos:], classes))
    return "".join(out)


def span(text: str, classes: set[str]) -> str:
    if not text:
        return ""
    safe = html.escape(text)
    return f'<span class="{" ".join(sorted(classes))}">{safe}</span>' if classes else safe


def capture(args: list[str], cwd: Path, banner: bool) -> list[list]:
    """Run ``dirsift *args`` and return [[seconds since start, html line], ...]."""
    env = dict(os.environ, FORCE_COLOR="1", COLUMNS="112", PYTHONUNBUFFERED="1",
               PYTHONIOENCODING="utf-8")
    env.pop("NO_COLOR", None)
    if banner:
        env.pop("DIRSIFT_NO_BANNER", None)
    else:
        env["DIRSIFT_NO_BANNER"] = "1"
    start = time.monotonic()
    proc = subprocess.Popen(
        [sys.executable, "-c", CLI, *args], cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    lines = []
    assert proc.stdout is not None
    for raw in iter(proc.stdout.readline, b""):
        text = raw.decode("utf-8", "replace").rstrip("\r\n").rstrip()
        lines.append([round(time.monotonic() - start, 3), ansi_to_html(text)])
    proc.wait()
    if proc.returncode:
        raise SystemExit("dirsift " + " ".join(args) + " failed")
    return lines


# pages: the terminal stage and the title cards


def fill(name: str, t: dict[str, str], **extra: str) -> str:
    """One of the pages in docs/demo-assets, with the console tokens filled in."""
    values = {key.replace("-", "_"): value for key, value in t.items()}
    values.update(width=str(WIDTH), height=str(HEIGHT), **extra)
    return Template((ASSETS / name).read_text(encoding="utf-8")).substitute(values)


def card_html(t: dict[str, str], number: str, title: str, line: str) -> str:
    mark = (DOCS / "dirsift-lockup-dark.svg").read_text(encoding="utf-8")
    mark = re.sub(r"<title>.*?</title>", "", mark)
    number_html = f'<p class="n">{html.escape(number)}</p>' if number else ""
    return fill("card.html", t, mark=mark, number=number_html,
                title=html.escape(title), line=html.escape(line))


async def route_stage(page: Page, files: dict[str, bytes]) -> None:
    async def handle(route):
        path = route.request.url[len(STAGE):].split("?", 1)[0]
        if path in files:
            kind = "text/html" if path.endswith(".html") else (
                "font/woff2" if path.endswith(".woff2") else "image/png")
            await route.fulfill(status=200, body=files[path], headers={"content-type": kind})
        else:
            await route.fulfill(status=404, body=b"")
    await page.route(STAGE + "**", handle)


# the screencast: every frame Chromium paints, with its wall clock time


class Screencast:
    def __init__(self, page: Page, out: Path):
        self.page, self.out, self.frames, self.marks = page, out, [], {}
        out.mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        self.cdp = await self.page.context.new_cdp_session(self.page)
        self.cdp.on("Page.screencastFrame", self._frame)
        await self.cdp.send("Page.startScreencast", {
            "format": "jpeg", "quality": 95, "maxWidth": WIDTH, "maxHeight": HEIGHT,
            "everyNthFrame": 1,
        })

    def _frame(self, event) -> None:
        path = self.out / f"f{len(self.frames):05d}.jpg"
        path.write_bytes(base64.b64decode(event["data"]))
        self.frames.append((event["metadata"]["timestamp"], path))
        asyncio.ensure_future(self.cdp.send("Page.screencastFrameAck",
                                            {"sessionId": event["sessionId"]}))

    def mark(self, name: str) -> None:
        self.marks[name] = time.time()

    async def stop(self) -> None:
        await asyncio.sleep(0.5)
        await self.cdp.send("Page.stopScreencast")
        await asyncio.sleep(0.3)


def cut(cast: Screencast, start: float, end: float, out: Path, ffmpeg: str,
        speed: float = 1.0) -> None:
    """Encode the frames painted between two wall clock times as one clip."""
    frames = sorted(cast.frames)
    before = [f for f in frames if f[0] <= start]
    inside = [f for f in frames if start < f[0] < end]
    chosen = ([before[-1]] if before else []) + inside
    if not chosen:
        raise SystemExit("no frames for " + out.name)
    listing = []
    times = [max(start, f[0]) for f in chosen] + [end]
    for (_, path), t0, t1 in zip(chosen, times, times[1:], strict=False):
        listing.append(f"file '{path.as_posix()}'\nduration {max(t1 - t0, 0.001):.4f}")
    listing.append(f"file '{chosen[-1][1].as_posix()}'")
    concat = out.with_suffix(".txt")
    concat.write_text("\n".join(listing) + "\n", encoding="utf-8")
    run([ffmpeg, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(concat),
         "-vf", f"setpts=PTS/{speed},fps={FPS},scale={WIDTH}:{HEIGHT},format=yuv420p",
         *ENCODE, str(out)])


ENCODE = ["-c:v", "libx264", "-preset", "slow", "-crf", "24", "-tune", "stillimage",
          "-r", str(FPS), "-video_track_timescale", "15360", "-an"]


def card_clip(png: Path, out: Path, ffmpeg: str, seconds: float = 1.5) -> None:
    fade = f"fade=in:st=0:d=0.25,fade=out:st={seconds - 0.3:.2f}:d=0.3"
    run([ffmpeg, "-y", "-loglevel", "error", "-loop", "1", "-t", f"{seconds}", "-i", str(png),
         "-vf", f"fps={FPS},{fade},format=yuv420p", *ENCODE, str(out)])


# the console: cursor, spotlight, smooth movement




class Driver:
    def __init__(self, page: Page):
        self.page = page
        self.x, self.y = WIDTH / 2, HEIGHT / 2

    async def wait(self, ms: int) -> None:
        await self.page.wait_for_timeout(ms)

    async def scroll_to(self, selector: str, offset: int = 120, ms: int = 1100) -> None:
        await self.page.evaluate(
            """([sel, off]) => { const el = document.querySelector(sel);
                 const top = el.getBoundingClientRect().top + window.scrollY - off;
                 window.scrollTo({top, behavior: "smooth"}); }""",
            [selector, offset],
        )
        await self.wait(ms)

    async def scroll_by(self, dy: int, ms: int = 1000) -> None:
        await self.page.evaluate(f"window.scrollBy({{top: {dy}, behavior: 'smooth'}})")
        await self.wait(ms)

    async def move(self, selector: str, steps: int = 22) -> tuple[float, float]:
        await self.page.wait_for_load_state("networkidle")
        box = await self.page.locator(selector).first.bounding_box()
        if box is None:
            raise SystemExit("not on screen: " + selector)
        if box["y"] < 150 or box["y"] + box["height"] > HEIGHT - 40:
            # Out of view, or under the sticky section bar: bring it to the middle.
            await self.page.evaluate(f"window.scrollBy({{top: {box['y'] - HEIGHT / 2:.0f}, "
                                     "behavior: 'smooth'})")
            await self.wait(900)
            box = await self.page.locator(selector).first.bounding_box()
            assert box is not None
        x, y = box["x"] + min(box["width"] / 2, 60), box["y"] + box["height"] / 2
        await self.page.mouse.move(x, y, steps=steps)
        self.x, self.y = x, y
        await self.wait(180)
        return x, y

    async def ring(self, selector: str) -> None:
        await self.page.locator(selector).first.evaluate(
            """(el) => { const p = el.style.boxShadow; el.style.boxShadow = "0 0 0 3px #56c7f2";
                 setTimeout(() => { el.style.boxShadow = p; }, 600); }"""
        )

    async def click(self, selector: str, after: int = 700) -> None:
        await self.move(selector)
        await self.ring(selector)
        await self.wait(260)
        await self.page.mouse.click(self.x, self.y)
        await self.wait(after)

    async def type(self, selector: str, text: str) -> None:
        await self.click(selector, after=200)
        await self.page.locator(selector).first.fill("")
        await self.page.keyboard.type(text, delay=38)
        await self.wait(300)

    async def key(self, name: str, after: int = 900) -> None:
        await self.page.keyboard.press(name)
        await self.wait(after)


async def caption(page: Page, text: str | None) -> None:
    """A recording-only caption at the foot of the frame; None removes it."""
    await page.evaluate(
        """(text) => {
             let el = document.getElementById("demo-caption");
             if (!text) { if (el) el.remove(); return; }
             if (!el) {
               el = document.createElement("div");
               el.id = "demo-caption";
               el.style.cssText = "position:fixed;left:50%;bottom:28px;" +
                 "transform:translateX(-50%);z-index:9999;padding:10px 18px;" +
                 "border-radius:10px;font:600 17px/1.2 " +
                 "'JetBrains Mono',monospace;letter-spacing:.02em;color:var(--ink);" +
                 "background:var(--surface-2);border:1px solid var(--lamp);" +
                 "box-shadow:0 8px 28px rgba(0,0,0,.45);pointer-events:none";
               document.body.appendChild(el);
             }
             el.textContent = text;
           }""",
        text,
    )


async def preview_ready(page: Page) -> None:
    """Wait until the rule pack panel has swapped and its preview has loaded."""
    try:
        await page.wait_for_function(
            """() => { const p = document.querySelector('#det-panel');
                 const b = p && p.querySelector('.rule-body');
                 return b && !p.classList.contains('htmx-request')
                          && !b.querySelector('p.empty'); }""",
            timeout=6000,
        )
    except Exception:
        # A format with nothing to carry keeps its placeholder; move on.
        pass
    await page.wait_for_timeout(250)


async def showcase(page: Page, d: Driver, cast: Screencast) -> None:
    """Every family, every format, each with its preview on screen."""
    for key, title in SHOWCASE:
        group = f'#det-panel label.dgroup:has(input[value="{key}"])'
        if not await page.locator(group).count():
            continue
        await d.move(group)
        await caption(page, title)
        await d.click(group, after=300)
        await preview_ready(page)
        # Once per family: the format chips near the top, the file under them.
        # Just below the sticky bar, so the clicks that follow need no scroll.
        await d.scroll_to("#det-panel .tgt-nav", offset=165, ms=800)
        ids = await page.locator("#det-panel label.prod input").evaluate_all(
            "els => els.map(e => e.value)")
        ids.sort(key=lambda tid: (SHOWCASE_FIRST.index(tid) if tid in SHOWCASE_FIRST
                                  else len(SHOWCASE_FIRST)))
        current = await page.locator("#det-panel label.prod input:checked").first.get_attribute(
            "value")
        for tid in ids:
            label = (await page.locator(
                f'#det-panel label.prod:has(input[value="{tid}"])').first.inner_text()).strip()
            if tid != current:
                await d.move(f'#det-panel label.prod:has(input[value="{tid}"])')
                await caption(page, f"{title}  ·  {label}")
                await d.click(f'#det-panel label.prod:has(input[value="{tid}"])', after=200)
                await preview_ready(page)
                current = tid
            await caption(page, f"{title}  ·  {label}")
            await d.wait(1350)
    await caption(page, None)


async def console_take(page: Page, cast: Screencast, base: str, target: str) -> None:
    d = Driver(page)
    await page.goto(base + "/", wait_until="networkidle")
    await page.mouse.move(d.x, d.y)
    await d.wait(400)
    await cast.start()
    await d.wait(500)

    # 02 the scan, from the dashboard
    cast.mark("02")
    await d.wait(500)
    await d.type("#url", target)
    await d.click("#delay", after=150)
    await page.locator("#delay").fill("")
    await page.keyboard.type("0.2", delay=90)
    await d.wait(300)
    await d.click('label:has(input[name="allow_private"])', after=500)
    await d.click('form[action="/scan"] button[type="submit"]', after=300)
    cast.mark("job")
    await page.wait_for_url(re.compile(r"/runs/"), timeout=120000)
    cast.mark("job-done")
    await page.wait_for_load_state("networkidle")
    await d.wait(1000)

    # 03 the case file: identity, drivers and the names graph
    cast.mark("03")
    await d.wait(500)
    await d.move(".identity", steps=18)
    await d.wait(900)
    await d.scroll_to("#drivers", ms=1300)
    await d.move("#drivers .driver-score", steps=18)
    await d.wait(700)
    await d.move("#drivers figure.graph", steps=26)
    await d.wait(1400)

    # 04 inventory and the preview window, j and k
    cast.mark("04")
    await d.scroll_to("#files", ms=1300)
    await d.click('#files summary:has-text("Scripts")', after=700)
    await d.click('#files a.link-button:has-text("install.bat")', after=1700)
    await d.key("j", 1300)
    await d.key("j", 1300)
    await d.key("k", 1200)
    await d.key("Escape", 900)

    # 05 indicators
    cast.mark("05")
    await d.scroll_to("#indicators", ms=1300)
    await d.click('[data-facets] button:has-text("url")', after=1200)
    await d.click('[data-facets] button:has-text("secret")', after=1200)
    await d.click('[data-facets] button:has-text("all")', after=900)

    # 06 detections: pick files for YARA
    cast.mark("06")
    await d.scroll_to("#detections", ms=1300)
    await d.click('label.pick:has-text("install.bat")', after=500)
    await d.click('label.pick:has-text("config.json")', after=1300)
    await d.scroll_to("#yara-out", offset=260, ms=1500)
    await d.wait(900)

    # 07 the rule pack: every family and every format
    cast.mark("07")
    await d.scroll_to("#det-panel", offset=170, ms=1300)
    await caption(page, "Rule packs  ·  let the demo's documentation addresses in")
    # Documentation addresses count as reserved, so let them in first: until
    # then most formats have nothing to carry from this demo folder.
    await d.click('#det-panel label.inline:has-text("leave out private")', after=300)
    await preview_ready(page)
    # The kinds that were disabled a moment ago were not sent with the form, so
    # they come back unticked: tick every kind this run carries.
    for kind in ("ipv4", "ipv6", "domain", "url", "email"):
        box = page.locator(f'#det-panel label.facet input[value="{kind}"]')
        if await box.count() and await box.is_enabled() and not await box.is_checked():
            await d.click(f'#det-panel label.facet:has(input[value="{kind}"])', after=250)
            await preview_ready(page)
    await showcase(page, d, cast)
    await d.move("#det-panel [data-zip]")
    await d.ring("#det-panel [data-zip]")
    await d.wait(1100)

    # 08 the report window: PDF or Markdown, and the TLP
    cast.mark("08")
    await page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
    await d.wait(1000)
    await d.click("[data-report-open]", after=900)
    await d.click('label.choice:has-text("Markdown")', after=800)
    await d.click('label.choice:has-text("PDF")', after=700)
    await d.move("#report-tlp")
    await page.select_option("#report-tlp", "GREEN")
    await d.wait(1200)
    await page.select_option("#report-tlp", "CLEAR")
    await d.wait(1200)
    await d.move("[data-report-download]")
    await d.ring("[data-report-download]")
    await d.wait(800)
    cast.mark("end")
    await cast.stop()


async def terminal_take(page: Page, cast: Screencast, steps: list[dict]) -> None:
    await page.goto(STAGE + "stage.html", wait_until="networkidle")
    await page.evaluate("document.fonts.ready")
    await cast.start()
    await page.wait_for_timeout(500)
    cast.mark("start")
    await page.evaluate("(s) => window.play(s)", steps)
    cast.mark("end")
    await cast.stop()


# main


async def record(args, work: Path) -> None:
    ffmpeg = args.ffmpeg
    t = tokens()
    cli = work / "cli"
    cli.mkdir(parents=True, exist_ok=True)
    target = f"http://127.0.0.1:{args.target_port}/"
    base = f"http://127.0.0.1:{args.console_port}"

    print("[*] terminal: capturing the real commands")
    scan = capture(["scan", target, "--allow-private", "--delay", "0.2", "--json", "run.json"],
                   cli, banner=True)
    det_list = capture(["detections", "run.json", "--list"], cli, banner=False)
    stix = capture(["stix", "run.json", "-o", "run.stix.json"], cli, banner=False)
    report = capture(["report", "run.json", "-o", "report.pdf", "--tlp", "GREEN"], cli,
                     banner=False)

    # The first two pages of the PDF the last command wrote, side by side.
    import pypdfium2
    from PIL import Image
    pdf = pypdfium2.PdfDocument(str(cli / "report.pdf"))
    pages = [pdf[i].render(scale=1.36).to_pil() for i in range(min(2, len(pdf)))]
    pdf.close()
    gap = 32
    sheet = Image.new("RGB", (sum(pg.width for pg in pages) + gap * (len(pages) - 1),
                              max(pg.height for pg in pages)), t["ground"])
    x = 0
    for pg in pages:
        sheet.paste(pg, (x, 0))
        x += pg.width + gap
    sheet.save(work / "report-page.png")

    files = {
        "stage.html": fill("stage.html", t).encode("utf-8"),
        **{"fonts/" + font: (STATIC / "fonts" / font).read_bytes()
           for font in ("ibm-plex-sans-latin.woff2", "jetbrains-mono-latin.woff2")},
        "report-page.png": (work / "report-page.png").read_bytes(),
    }
    for i, (number, title, line) in enumerate(CARDS):
        files[f"card{i}.html"] = card_html(t, number, title, line).encode("utf-8")
    files["intro.html"] = card_html(
        t, "", "Triage an open directory",
        "Walk it, classify what is there, find the file that drives the rest. "
        "Everything here is a harmless demo folder on documentation addresses.").encode("utf-8")
    files["outro.html"] = card_html(
        t, "", "Scan once, read it offline",
        "Reads only what the server lists. No guessed paths, no credentials, no writes.",
    ).encode("utf-8")

    clips = work / "clips"
    clips.mkdir(exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch()

        async def fresh():
            context = await browser.new_context(
                viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=1,
                color_scheme="dark", reduced_motion="no-preference")
            page = await context.new_page()
            await route_stage(page, files)
            return context, page

        print("[*] cards")
        context, page = await fresh()
        for name in [f"card{i}" for i in range(len(CARDS))] + ["intro", "outro"]:
            await page.goto(STAGE + name + ".html", wait_until="networkidle")
            await page.evaluate("document.fonts.ready")
            await page.screenshot(path=str(work / f"{name}.png"))
        await context.close()

        print("[*] terminal take: banner and scan")
        context, page = await fresh()
        cast1 = Screencast(page, work / "t1")
        await terminal_take(page, cast1, [
            {"cmd": f"dirsift scan {target} --allow-private --delay 0.2 --json run.json",
             "lines": scan, "hold": 1400, "typing": 26},
        ])
        await context.close()

        print("[*] console take")
        context, page = await fresh()
        await context.add_init_script(path=str(ASSETS / "cursor.js"))
        cast2 = Screencast(page, work / "c")
        await console_take(page, cast2, base, target)
        await context.close()

        print("[*] terminal take: offline CLI")
        context, page = await fresh()
        cast3 = Screencast(page, work / "t3")
        await terminal_take(page, cast3, [
            {"cmd": "dirsift detections run.json --list", "lines": det_list, "hold": 2000,
             "typing": 26},
            {"cmd": "dirsift stix run.json -o run.stix.json", "lines": stix, "hold": 2200,
             "typing": 26},
            {"cmd": "dirsift report run.json -o report.pdf --tlp GREEN", "lines": report,
             "hold": 1100, "typing": 26},
            {"image": STAGE + "report-page.png", "hold": 2800},
        ])
        await context.close()
        await browser.close()

    print("[*] cutting and joining")
    order: list[Path] = []

    def card(name: str, seconds: float = 1.4) -> None:
        out = clips / f"{len(order):02d}-{name}.mp4"
        card_clip(work / f"{name}.png", out, ffmpeg, seconds)
        order.append(out)

    def piece(cast: Screencast, a: str, b: str, name: str, speed: float = 1.0) -> None:
        out = clips / f"{len(order):02d}-{name}.mp4"
        cut(cast, cast.marks[a], cast.marks[b], out, ffmpeg, speed)
        order.append(out)

    card("intro", 2.3)
    card("card0")
    piece(cast1, "start", "end", "terminal-scan")
    card("card1")
    piece(cast2, "02", "job", "console-02")
    # The walk itself is waiting on the target; it plays a little faster.
    piece(cast2, "job", "job-done", "console-02-walk", speed=1.6)
    piece(cast2, "job-done", "03", "console-02-done")
    for i, (a, b) in enumerate([("03", "04"), ("04", "05"), ("05", "06"), ("06", "07"),
                                ("07", "08"), ("08", "end")], start=2):
        card(f"card{i}")
        piece(cast2, a, b, f"console-{a}")
    card("card8")
    piece(cast3, "start", "end", "terminal-cli")
    card("outro", 2.0)

    concat = work / "all.txt"
    concat.write_text("".join(f"file '{c.as_posix()}'\n" for c in order), encoding="utf-8")
    mp4 = DOCS / "demo.mp4"
    run([ffmpeg, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(concat),
         "-c", "copy", "-movflags", "+faststart", str(mp4)])

    marks = {"terminal": cast1.marks, "console": cast2.marks, "cli": cast3.marks,
             "clips": [c.name for c in order]}
    (work / "marks.json").write_text(json.dumps(marks, indent=2), encoding="utf-8")
    print("[+]", mp4, round(mp4.stat().st_size / 1024 / 1024, 2), "MB")


def main() -> None:
    print(BANNER)
    parser = argparse.ArgumentParser(description="Record docs/demo.mp4.")
    parser.add_argument("--ffmpeg", default=shutil.which("ffmpeg") or "ffmpeg")
    parser.add_argument("--console-port", type=int, default=8801)
    parser.add_argument("--target-port", type=int, default=8806)
    parser.add_argument("--work", type=Path, default=None,
                        help="Keep the frames and clips here. Default: a new temporary folder.")
    args = parser.parse_args()

    for port in (args.console_port, args.target_port):
        if not free(port):
            raise SystemExit(f"127.0.0.1:{port} is taken; pick another with the port flags")

    work = args.work or Path(tempfile.mkdtemp(prefix="dirsift-demo-"))
    work.mkdir(parents=True, exist_ok=True)
    runs = work / "runs"
    runs.mkdir(exist_ok=True)
    print("[*] work folder:", work)

    run([sys.executable, str(DOCS / "make-demo-target.py")], stdout=subprocess.DEVNULL)
    servers = [
        subprocess.Popen([sys.executable, "-m", "http.server", str(args.target_port),
                          "--bind", "127.0.0.1", "--directory", str(TARGET_DIR)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen([sys.executable, "-m", "dirsift", "web", "--port",
                          str(args.console_port), "--runs", str(runs)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         env=dict(os.environ, DIRSIFT_NO_BANNER="1")),
    ]
    try:
        wait_port(args.target_port)
        wait_port(args.console_port)
        asyncio.run(record(args, work))
    finally:
        for server in servers:
            server.terminate()
            server.wait()


if __name__ == "__main__":
    main()
