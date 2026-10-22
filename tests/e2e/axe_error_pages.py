"""Accessibility checks for the error and "gone" pages the N1 wave templated.

Five return points used to answer with a bare body (a lone heading, or the
single word "gone") that failed axe on document-title, html-has-lang and the
main landmark. They now draw through base.html or land in a panel the live page
already shows. This drives a real browser and runs axe-core over each one, so
the claim "every page is clean, no exemption" is checked rather than asserted.

Like preview_nav_e2e.py this is not part of the normal test run: the package
stays air gapped and ships no browser engine or axe build. Run it by hand when
the error wiring or the templates change.

    uv run --with playwright python tests/e2e/axe_error_pages.py
    uv run --with playwright playwright install chromium   # first time only

axe-core is loaded at run time from a CDN (the same network step as installing
the browser). Point DIRSIFT_AXE_JS at a local axe.min.js to run fully offline.

It starts its own server on 127.0.0.1:8801 against a throwaway run, so nothing
else needs to be up and no real target is touched. Exit code is 0 when every
page is clean of serious and critical findings.

Pages covered:
  * E1  a job that is not tracked          GET /jobs/<gone>          (full page)
  * E3  a run visited directly, not there  GET /runs/<gone>          (full page)
  * E2  the scan page after the job is gone (the real gone fragment, swapped in
        by htmx on a 404, inside the live region)                    (fragment)
  * E4  a run gone, asked over htmx         GET /runs/<gone>/file     (panel)

E5 (refused) is left out on purpose: that handler is not reached synchronously
in a normal request (the scan runs in a thread and catches the scope error
there), so there is no live route to load. Its structural guarantee is the
base.html shell it now extends, checked in tests/test_web.py.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from dirsift.models import Entry, ScanResult  # noqa: E402
from dirsift.web import create_app  # noqa: E402

HOST = "127.0.0.1"
PORT = 8801
BASE = f"http://{HOST}:{PORT}"
ROOT = "http://127.0.0.1:8080/"
AXE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.14.0/axe.min.js"
WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]


def build_run(runs_dir: Path) -> str:
    """One listed file, enough for a real run page to draw its panels."""
    result = ScanResult(
        root_url=ROOT,
        listing_flavor="python",
        entries=[Entry(url=ROOT + "run.bat", name="run.bat", depth=1, fetched_bytes=20)],
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


def load_axe(page) -> None:
    local = os.environ.get("DIRSIFT_AXE_JS")
    if local:
        page.add_script_tag(path=local)
    else:
        page.add_script_tag(url=AXE_CDN)
    page.wait_for_function("() => !!window.axe")


def serious_or_critical(page) -> list[str]:
    """The ids of the axe violations that are serious or critical, if any."""
    result = page.evaluate(
        "async (tags) => await axe.run(document, {runOnly: {type: 'tag', values: tags}})",
        WCAG,
    )
    return [
        v["id"]
        for v in result["violations"]
        if v.get("impact") in ("serious", "critical")
    ]


def axe_clean(page, label: str, checks: Checks) -> None:
    load_axe(page)
    hits = serious_or_critical(page)
    checks.ok(f"{label}: axe serious/critical is 0", not hits)
    if hits:
        print(f"        {label} violations: {', '.join(hits)}")


def check_full_page(context, path: str, label: str, title: str, checks: Checks) -> None:
    """E1 and E3: a direct visit to something that is not there is a full page."""
    response = context.request.get(f"{BASE}{path}")
    checks.ok(f"{label}: 404", response.status == 404)
    page = context.new_page()
    page.goto(f"{BASE}{path}")
    checks.ok(f"{label}: title is '{title}'", page.title() == title)
    checks.ok(f"{label}: one h1", page.locator("h1").count() == 1)
    checks.ok(f"{label}: the main landmark is present", page.locator("main").count() == 1)
    checks.ok(f"{label}: a way back to the dashboard", page.locator("a.backlink").count() == 1)
    axe_clean(page, label, checks)
    page.close()


def check_gone_scan(context, checks: Checks) -> None:
    """E2: the scan page after the job is gone. The real gone fragment is served
    on a 404 and swapped in by htmx, so the live region is kept and the polling
    stops (the fragment carries no trigger)."""
    gone_body = context.request.get(f"{BASE}/jobs/zzz/status").text()
    page = context.new_page()
    polls: list[str] = []
    page.on(
        "request",
        lambda r: polls.append(r.url) if r.url.endswith("/status") else None,
    )
    # Every status poll on this page answers with the real gone fragment.
    page.route(
        "**/jobs/**/status",
        lambda route: route.fulfill(
            status=404, content_type="text/html; charset=utf-8", body=gone_body
        ),
    )
    started = context.request.post(
        f"{BASE}/scan", form={"url": "http://127.0.0.1:9/"}, max_redirects=0
    )
    page.goto(f"{BASE}{started.headers['location']}")
    page.wait_for_selector(".job-live .notice")  # the gone fragment is in

    live_region = page.locator(".job-live[aria-live]")
    checks.ok("E2 gone: the live region is still in the page", live_region.count() == 1)
    still_polling = page.eval_on_selector(
        ".job-live", "el => !!el.querySelector('[hx-get]')"
    )
    checks.ok("E2 gone: no further poll is scheduled", not still_polling)
    before = len(polls)
    page.wait_for_timeout(2500)
    checks.ok("E2 gone: polling has stopped (no new /status in 2.5s)", len(polls) == before)
    checks.ok(
        "E2 gone: the single word 'gone' is replaced by a sentence",
        "no longer tracked" in page.inner_text(".job-live"),
    )
    axe_clean(page, "E2 gone", checks)
    page.close()


def check_gone_run_panel(context, run_name: str, checks: Checks) -> None:
    """E4: a run that is not on disk, asked for over htmx, lands in the preview
    panel on the run page. The panel is fetched the way htmx would and placed
    where htmx would put it, then axe runs over the whole run page."""
    panel = context.request.get(
        f"{BASE}/runs/ghost/file",
        params={"url": ROOT + "x"},
        headers={"HX-Request": "true"},
    )
    checks.ok("E4 run gone: 404 over htmx", panel.status == 404)
    body = panel.text()
    is_panel = 'class="preview"' in body and "<html" not in body
    checks.ok("E4 run gone: a preview-shaped panel, not a page", is_panel)

    page = context.new_page()
    page.goto(f"{BASE}/runs/{run_name}")
    # On a narrow screen the preview is a sheet and starts hidden, so wait for it
    # to be attached, not visible, and read its text the same way.
    page.wait_for_selector("#preview", state="attached")
    page.evaluate("(html) => { document.querySelector('#preview').outerHTML = html; }", body)
    page.wait_for_selector(".preview-name", state="attached")
    heading = page.text_content(".preview-name") or ""
    checks.ok("E4 run gone: the panel names the miss", "Run not found" in heading)
    axe_clean(page, "E4 run gone", checks)
    page.close()


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="dirsift-axe-"))
    run_name = build_run(tmp)
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

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            for width, height, tag in ((1440, 900, "wide"), (414, 896, "narrow")):
                context = browser.new_context(viewport={"width": width, "height": height})
                print(f"{tag} ({width}x{height}):")
                check_full_page(
                    context, "/jobs/does-not-exist",
                    f"[{tag}] E1 no such job", "scan not found", checks,
                )
                check_full_page(
                    context, "/runs/does-not-exist",
                    f"[{tag}] E3 no such run", "run not found", checks,
                )
                check_gone_scan(context, checks)
                check_gone_run_panel(context, run_name, checks)
                context.close()
            browser.close()
    except Exception as exc:  # noqa: BLE001 - a setup failure is a clean skip, not a pass
        print(f"could not drive the browser or load axe: {type(exc).__name__}: {exc}")
        server.should_exit = True
        return 2

    server.should_exit = True
    print(f"\n{checks.passes} passed, {len(checks.failures)} failed")
    for label in checks.failures:
        print(f"  FAIL  {label}")
    return 1 if checks.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
