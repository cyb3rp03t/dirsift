"""Local triage UI.

Runs on localhost and nowhere else by default. The browser is the right shape
for this job because triage is reading: you want the listing, the clusters and
a file's contents side by side, and you want to click between them without
rerunning anything.

The UI never fetches from a target on its own. A scan starts only when you
press the button, runs in a background thread, and every view after that is
served out of the saved run. htmx is vendored into the package rather than
pulled from a CDN, so this works on an air-gapped analysis box.
"""

from __future__ import annotations

import difflib
import json
import re
import threading
import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlencode

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from .. import detections
from ..analyze import analyze
from ..asn import default_table
from ..classify import mismatch
from ..diagnose import explain
from ..enrich import MissingKey, api_key_from_env, lookup_hash
from ..extract import SecretMask, defang
from ..fetcher import PrivateTargetError, ScopeError
from ..models import Entry, Ioc, ScanResult
from ..report import human_size, render_markdown
from ..rules import build_rules
from ..walker import ScanOptions, scan

HERE = Path(__file__).parent


@dataclass
class Job:
    id: str
    url: str
    state: str = "queued"  # queued, running, done, failed
    stage: str = ""
    detail: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    run_name: str | None = None
    error: str | None = None
    listings: int = 0
    peeks: int = 0


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, url: str) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], url=url)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def all(self) -> list[Job]:
        return sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)


def _slug(url: str) -> str:
    safe = "".join(c if c.isalnum() else "-" for c in url).strip("-")
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{safe[:60]}"


def _failure_message(exc: Exception) -> str:
    """What a failed job says. The form has a checkbox where the CLI has a flag."""
    if isinstance(exc, PrivateTargetError):
        return (
            f"{defang(exc.host)} is a private or loopback address. "
            'Tick "allow private" and scan again if that is deliberate.'
        )
    return f"{type(exc).__name__}: {exc}"


#: What a run's name may look like: the stem of a file in the runs folder.
#: No separator of either platform, and nothing that starts with a dot, so a
#: name can never climb out of that folder.
RUN_NAME = re.compile(r"\w[\w .-]*")


class NoSuchRun(Exception):
    """A run name that is not a run in this folder."""


#: A digest someone pastes: md5, sha1 or sha256, nothing else.
HASH = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
DIGEST_IN_FORM = Form(default="")

#: Selected files arrive as a repeated field, from the form and from the link.
PICKED_IN_FORM = Form(default=[])
PICKED_IN_QUERY = Query(default=[])

#: Repeated query fields for the detection routes.
TYPES_IN_QUERY = Query(default=[])

#: What a live download carries besides the file: never cached, never sniffed
#: into something a browser would render.
LIVE_HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

#: Bytes per row in the hex view.
HEX_COLUMNS = 16

#: The sections of a run page, in tab order. The first is shown when none is asked for.
RUN_TABS = ("files", "indicators", "families", "notes", "settings")

#: The full-page error views. Each is rendered through error.html, which extends
#: base.html, so the language, the title, a single h1 and the main landmark come
#: from the shell rather than from a bare response. The quote is filled in only
#: for a refusal, where it carries a URL a target's listing supplied.
ERROR_NO_SUCH_JOB = {
    "title": "scan not found",
    "heading": "This scan is no longer tracked.",
    "body": (
        "Scans are tracked in memory while the console runs. This one has "
        "finished, or the console restarted. Finished runs are on the dashboard."
    ),
}
ERROR_NO_SUCH_RUN = {
    "title": "run not found",
    "heading": "No run by that name.",
    "body": (
        "This run is not in the runs folder. It may have been renamed or "
        "removed. The dashboard lists every run on disk."
    ),
}
ERROR_REFUSED = {
    "title": "refused",
    "heading": "That link was out of scope.",
    "body": (
        "A link in the listing pointed outside the scan's scope, so it was "
        "not followed."
    ),
}


def _hex_rows(head_hex: str | None) -> list[dict[str, str]]:
    """The first bytes as offset, hex pairs and printable ASCII.

    These bytes were already fetched during the scan. Rendering them here costs
    nothing on the wire and saves opening the sample somewhere else just to see
    whether the header matches the name.
    """
    if not head_hex:
        return []
    data = bytes.fromhex(head_hex)
    rows = []
    for offset in range(0, len(data), HEX_COLUMNS):
        chunk = data[offset : offset + HEX_COLUMNS]
        rows.append(
            {
                "offset": format(offset, "08x"),
                "hex": " ".join(format(byte, "02x") for byte in chunk),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
            }
        )
    return rows


def _source_html(text: str | None, iocs: list[Ioc]) -> Markup:
    """The file's own bytes, escaped, with its indicators marked and lines numbered.

    The contents are evidence, so nothing is rewritten: the text is escaped so a
    page full of script tags is shown rather than run, and the only thing added
    is a mark around the values the extractor already found.
    """
    if not text:
        return Markup("")
    escaped = str(escape(text))
    values = sorted(
        {str(escape(ioc.value)) for ioc in iocs if ioc.value}, key=len, reverse=True
    )
    if values:
        pattern = re.compile("|".join(re.escape(value) for value in values))
        escaped = pattern.sub(lambda hit: "<mark>" + hit.group(0) + "</mark>", escaped)
    numbered = [
        '<span class="line" data-line="' + str(number) + '">' + line + "</span>"
        for number, line in enumerate(escaped.split(chr(10)), start=1)
    ]
    return Markup(chr(10).join(numbered))


def _diff_rows(left: Entry, right: Entry) -> list[dict[str, str]]:
    """A unified diff of the text DirSift kept for two versions of one file."""
    if not left.text_preview or not right.text_preview:
        return []
    rows = []
    for line in difflib.unified_diff(
        left.text_preview.split(chr(10)),
        right.text_preview.split(chr(10)),
        fromfile=left.name,
        tofile=right.name,
        lineterm="",
    ):
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            kind = "meta"
        elif line.startswith("+"):
            kind = "add"
        elif line.startswith("-"):
            kind = "del"
        else:
            kind = "same"
        rows.append({"kind": kind, "text": line})
    return rows


def _preview(
    result: ScanResult, entry: Entry, name: str, note: str | None = None
) -> dict[str, object]:
    """Everything the preview panel knows about one file, gathered in one place."""
    return {
        "name": name,
        "entry": entry,
        "mismatch": mismatch(entry),
        # The list names a secret instead of quoting it; the contents tab is the
        # file itself, raw on purpose.
        "iocs": [
            ioc.model_copy(update={"defanged": _mask(result).indicator(ioc)})
            for ioc in result.iocs
            if ioc.found_in(entry.url)
        ],
        "referenced_by": [
            other
            for other in result.files
            if other.url != entry.url
            and any(ref.lower() == entry.name.lower() for ref in other.references)
        ],
        "siblings": [
            other
            for other in result.files
            if entry.cluster and other.cluster == entry.cluster and other.url != entry.url
        ],
        "hex_rows": _hex_rows(entry.head_hex),
        "source_html": _source_html(entry.text_preview, result.iocs),
        "verdict_ready": api_key_from_env() is not None,
        "note": note,
    }


#: The live values and the secret mask of the run drawn last, so a page with a
#: hundred context lines walks the run's indicators once and not a hundred times.
_shown_cache: tuple[object, list[str], SecretMask] = (None, [], SecretMask([]))


def _shown_for(result: ScanResult) -> tuple[list[str], SecretMask]:
    global _shown_cache
    cached, values, mask = _shown_cache
    if cached is not result:
        values, mask = detections.live_values(result), SecretMask(result.iocs)
        _shown_cache = (result, values, mask)
    return values, mask


def _mask(result: ScanResult) -> SecretMask:
    return _shown_for(result)[1]


def defang_shown(text: str | None, result: ScanResult) -> str:
    """A line from the target's own files, made safe to show on the run page.

    Context lines were defanged with the rules of the day the run was saved,
    so an older run can carry a live address in one. This defangs at display
    time with every live value the run holds plus the prose pass, so old and
    new runs read the same. A secret is named by its kind, length and digest,
    never quoted. The saved run is not changed.
    """
    if not text:
        return ""
    values, mask = _shown_for(result)
    return detections.defang_with(mask.text(text), values)


def create_app(runs_dir: Path = Path("runs"), lookup=lookup_hash) -> FastAPI:
    runs_dir = Path(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="DirSift", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters["human_size"] = human_size
    templates.env.filters["defang"] = defang
    templates.env.filters["explain"] = explain
    templates.env.filters["defang_shown"] = defang_shown
    jobs = JobStore()

    # The address table is half a million ranges and takes a few seconds to
    # read. Every run page places its addresses against it, so it is warmed
    # here instead of making the first page of the session wait for it. A
    # machine without the table gets an empty one back immediately.
    threading.Thread(target=default_table, daemon=True, name="asn-warm").start()

    # Helpers

    def list_runs() -> list[dict[str, object]]:
        out = []
        for path in sorted(runs_dir.glob("*.json"), reverse=True):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            out.append(
                {
                    "name": path.stem,
                    "url": payload.get("root_url", "?"),
                    "started_at": payload.get("started_at", ""),
                    "files": len([e for e in payload.get("entries", []) if not e.get("is_dir")]),
                    "dirs": len([e for e in payload.get("entries", []) if e.get("is_dir")]),
                    "iocs": len(payload.get("iocs", [])),
                    "flavor": payload.get("listing_flavor"),
                }
            )
        return out

    def run_path(name: str) -> Path:
        if not RUN_NAME.fullmatch(name):
            raise NoSuchRun(name)
        return runs_dir / f"{name}.json"

    def load_run(name: str) -> tuple[ScanResult, list]:
        try:
            text = run_path(name).read_text(encoding="utf-8")
            result = ScanResult.model_validate(json.loads(text))
        except (OSError, ValueError) as exc:
            raise NoSuchRun(name) from exc
        return analyze(result)

    def is_htmx(request: Request) -> bool:
        """htmx marks its own requests, so a 404 from one of them can land in the
        preview panel instead of replacing the whole page."""
        return bool(request.headers.get("hx-request"))

    def render_error(request: Request, context: dict, status_code: int):
        """A full-page error, drawn through base.html so the language, the title,
        the single h1 and the main landmark are there without a bare response."""
        return templates.TemplateResponse(
            request, "error.html", context, status_code=status_code
        )

    def run_scan(job: Job, options: ScanOptions) -> None:
        def progress(event: str, detail: str) -> None:
            job.stage, job.detail = event, detail
            if event == "listing":
                job.listings += 1
            else:
                job.peeks += 1

        options.progress = progress
        job.state = "running"
        try:
            result = scan(job.url, options)
            result, _ = analyze(result)
            name = _slug(job.url)
            (runs_dir / f"{name}.json").write_text(
                result.model_dump_json(indent=2), encoding="utf-8"
            )
            job.run_name = name
            job.state = "done"
        except Exception as exc:  # noqa: BLE001 - surfaced in the UI
            job.state = "failed"
            job.error = _failure_message(exc)

    # Routes

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        runs = list_runs()
        live = [job for job in jobs.all() if job.state in ("queued", "running")]
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "runs": runs,
                "jobs": jobs.all()[:8],
                "totals": {
                    "runs": len(runs),
                    "files": sum(int(run["files"]) for run in runs),
                    "iocs": sum(int(run["iocs"]) for run in runs),
                    "running": len(live),
                },
            },
        )

    @app.post("/verdict", response_class=HTMLResponse)
    def hash_verdict(request: Request, digest: str = DIGEST_IN_FORM):
        """Ask about a digest that arrived from somewhere other than a scan."""
        digest = digest.strip().lower()
        verdict = None
        note = None
        if not HASH.fullmatch(digest):
            note = "That is not a hash. Paste an md5, a sha1 or a sha256."
        else:
            try:
                verdict = lookup(digest, api_key=api_key_from_env())
            except MissingKey as exc:
                note = str(exc)
            except Exception as exc:  # noqa: BLE001 - surfaced in the panel
                note = f"The lookup failed: {type(exc).__name__}: {exc}"
        return templates.TemplateResponse(
            request, "_verdict.html", {"digest": digest, "verdict": verdict, "note": note}
        )

    @app.post("/scan")
    def start_scan(
        url: str = Form(...),
        depth: int = Form(2),
        delay: float = Form(1.0),
        peek: bool = Form(False),
        allow_private: bool = Form(False),
    ):
        job = jobs.create(url.strip())
        options = ScanOptions(
            depth=depth, delay=delay, peek=peek, allow_private=allow_private
        )
        try:
            ScanOptions(**options.as_dict())  # cheap validation
        except TypeError as exc:
            job.state, job.error = "failed", str(exc)
            return RedirectResponse(f"/jobs/{job.id}", status_code=303)

        threading.Thread(target=run_scan, args=(job, options), daemon=True).start()
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str):
        job = jobs.get(job_id)
        if job is None:
            return render_error(request, ERROR_NO_SUCH_JOB, status_code=404)
        return templates.TemplateResponse(request, "job.html", {"job": job})

    @app.get("/jobs/{job_id}/status", response_class=HTMLResponse)
    def job_status(request: Request, job_id: str):
        job = jobs.get(job_id)
        if job is None:
            # The polling box asked after the job was gone (the console
            # restarted). The fragment carries no trigger, so the swap stops the
            # polling, and it lands in the live region so it is announced.
            return templates.TemplateResponse(
                request, "_status_gone.html", {}, status_code=404
            )
        return templates.TemplateResponse(request, "_status.html", {"job": job})

    @app.get("/runs/{name}", response_class=HTMLResponse)
    def run_page(
        request: Request, name: str, file: str | None = None, tab: str | None = None
    ):
        result, candidates = load_run(name)
        entries = sorted(result.entries, key=lambda e: (e.depth, not e.is_dir, e.name))
        opened = next((e for e in result.entries if e.url == file), None) if file else None
        drivers = [c for c in candidates if c.score > 0]
        ioc_types: dict[str, int] = {}
        for ioc in result.iocs:
            ioc_types[ioc.ioc_type] = ioc_types.get(ioc.ioc_type, 0) + 1
        return templates.TemplateResponse(
            request,
            "run.html",
            {
                "name": name,
                "result": result,
                # A ?file= link means a preview, and the preview lives in the
                # files panel. Force files so the preview is never stranded in a
                # hidden panel (on a narrow screen that would lock the page).
                "tab": "files" if file else (tab if tab in RUN_TABS else RUN_TABS[0]),
                "candidates": drivers[:6],
                # Every scored file, for the badge on its listing row. The strip
                # shows a short list; the badges are not held to it.
                "driver_scores": {c.entry.url: int(round(c.score)) for c in drivers},
                "entries": entries,
                "by_kind": sorted(result.by_kind().items(), key=lambda kv: -len(kv[1])),
                "ioc_types": sorted(ioc_types.items(), key=lambda kv: -kv[1]),
                "mismatches": {
                    entry.url: note
                    for entry in result.files
                    if (note := mismatch(entry)) is not None
                },
                "preview": _preview(result, opened, name) if opened else None,
            },
        )

    def not_in_run(request: Request, name: str, url: str):
        """The panel a preview, a verdict or a comparison gets for a file the run
        never listed. It lands in the preview (a sheet on a narrow screen), so it
        reads like one: a heading, the address, a way back. Still a 404."""
        return templates.TemplateResponse(
            request, "_missing.html", {"name": name, "url": url}, status_code=404
        )

    @app.get("/runs/{name}/file", response_class=HTMLResponse)
    def file_preview(request: Request, name: str, url: str):
        result, _ = load_run(name)
        entry = next((e for e in result.entries if e.url == url), None)
        if entry is None:
            return not_in_run(request, name, url)
        return templates.TemplateResponse(request, "_file.html", _preview(result, entry, name))

    @app.post("/runs/{name}/verdict", response_class=HTMLResponse)
    def file_verdict(request: Request, name: str, url: str):
        """Ask a public scanner about one hash, on purpose, one file at a time."""
        result, _ = load_run(name)
        entry = next((e for e in result.entries if e.url == url), None)
        if entry is None:
            return not_in_run(request, name, url)

        note = None
        if not entry.sha256:
            note = "This file has no hash to ask about: only its head was read."
        else:
            try:
                entry.verdict = lookup(entry.sha256, api_key=api_key_from_env())
            except MissingKey as exc:
                note = str(exc)
            except Exception as exc:  # noqa: BLE001 - surfaced in the panel
                note = f"The lookup failed: {type(exc).__name__}: {exc}"
            else:
                run_path(name).write_text(
                    result.model_dump_json(indent=2), encoding="utf-8"
                )

        return templates.TemplateResponse(
            request, "_file.html", _preview(result, entry, name, note)
        )

    def _picked(result: ScanResult, urls: list[str]) -> list[Entry]:
        wanted = set(urls)
        return [entry for entry in result.entries if entry.url in wanted and not entry.is_dir]

    @app.post("/runs/{name}/yara", response_class=HTMLResponse)
    def build_yara(request: Request, name: str, pick: list[str] = PICKED_IN_FORM):
        """A rule from the files someone ticked in the listing."""
        result, _ = load_run(name)
        picked = _picked(result, pick)
        return templates.TemplateResponse(
            request,
            "_yara.html",
            {
                "name": name,
                "picked": picked,
                "rule": build_rules(result, picked, name) if picked else "",
                "query": urlencode([("pick", entry.url) for entry in picked]),
            },
        )

    @app.get("/runs/{name}/rule.yar", response_class=PlainTextResponse)
    def download_yara(name: str, pick: list[str] = PICKED_IN_QUERY):
        result, _ = load_run(name)
        picked = _picked(result, pick)
        rule = build_rules(result, picked, name) if picked else "// nothing was selected"
        return PlainTextResponse(
            rule,
            headers={"Content-Disposition": 'attachment; filename="' + name + '.yar"'},
        )

    # Detections
    #
    # Every route here reads the saved run and writes nothing. The preview is
    # defanged; only download and the zip carry live values, and both are sent
    # as attachments so a browser saves them instead of showing them.

    def detection_options(
        result: ScanResult,
        tlp: str | None,
        types: list[str],
        source: str | None,
        exclude_private: bool,
        exclude_protocol: bool,
        profile: str | None,
        pick: list[str],
    ) -> detections.Options:
        """The export options from the query. Raises BadOption or LookupError."""
        source = source or None
        if source is not None and not any(entry.url == source for entry in result.files):
            raise LookupError(source)
        wanted = set(pick)
        return detections.Options(
            tlp=detections.parse_tlp(tlp),
            types=detections.parse_types(types, detections.SHAREABLE),
            source=source,
            exclude_private=exclude_private,
            exclude_protocol=exclude_protocol,
            profile=detections.parse_profile(profile),
            pick=tuple(entry.url for entry in result.files if entry.url in wanted),
        )

    def options_query(options: detections.Options) -> str:
        pairs: list[tuple[str, str]] = [("tlp", options.tlp)]
        for kind in sorted(options.types or ()):
            pairs.append(("types", kind))
        if options.source:
            pairs.append(("source", options.source))
        pairs.append(("exclude_private", "true" if options.exclude_private else "false"))
        pairs.append(("exclude_protocol", "true" if options.exclude_protocol else "false"))
        pairs.append(("profile", options.profile))
        for url in options.pick:
            pairs.append(("pick", url))
        return urlencode(pairs)

    def detection_context(
        name: str, result: ScanResult, candidates, options: detections.Options
    ) -> dict:
        run = detections.Run(result=result, name=name, candidates=tuple(candidates))
        info = detections.summary(run, options)
        query = options_query(options)
        for target in info["targets"]:
            base = f"/runs/{name}/detections/{target['id']}"
            target["preview_url"] = f"{base}?{query}"
            target["download_url"] = f"{base}/download?{query}"
        # The type and file filters count over the whole run, so narrowing to
        # one type or one file never hides the others from the controls.
        everything = detections.collect(result, replace(options, source=None, types=None))
        per_path: dict[str, int] = {}
        for item in everything.indicators:
            for path in item.sources:
                per_path[path] = per_path.get(path, 0) + 1
        sources = []
        for entry in sorted(result.files, key=lambda e: e.url):
            path = unquote(entry.url.removeprefix(result.root_url)) or entry.name
            if per_path.get(path):
                sources.append({"url": entry.url, "path": path, "count": per_path[path]})
        return {
            "name": name,
            "run": run,
            "options": {
                "tlp": options.tlp,
                "types": sorted(options.types) if options.types is not None else None,
                "source": options.source,
                "exclude_private": options.exclude_private,
                "exclude_protocol": options.exclude_protocol,
                "profile": options.profile,
            },
            "tlp_levels": list(detections.TLP_LEVELS),
            "types": everything.counts(),
            "left_out": info["left_out"],
            "sources": sources,
            "targets": info["targets"],
            "zip_url": f"/runs/{name}/detections.zip?{query}",
        }

    def bad_option(exc: Exception):
        return PlainTextResponse(str(exc) + ".", status_code=400)

    def no_target():
        return PlainTextResponse("No such detection target.", status_code=404)

    def asked(request: Request, name: str, result: ScanResult, query: dict):
        """Options from the query, or the response that refuses them."""
        try:
            return detection_options(result, **query), None
        except detections.BadOption as exc:
            return None, bad_option(exc)
        except LookupError:
            return None, not_in_run(request, name, query.get("source") or "")

    @app.get("/runs/{name}/detections.json")
    def detections_list(
        request: Request,
        name: str,
        tlp: str | None = None,
        types: list[str] = TYPES_IN_QUERY,
        source: str | None = None,
        exclude_private: bool = True,
        exclude_protocol: bool = True,
        profile: str | None = None,
        pick: list[str] = PICKED_IN_QUERY,
    ):
        """The targets and their counts, for scripts and for the panel's own tests."""
        result, candidates = load_run(name)
        options, refusal = asked(request, name, result, {
            "tlp": tlp, "types": types, "source": source, "exclude_private": exclude_private,
            "exclude_protocol": exclude_protocol, "profile": profile, "pick": pick,
        })
        if refusal is not None:
            return refusal
        context = detection_context(name, result, candidates, options)
        context.pop("run")
        return JSONResponse({"run": context.pop("name"), **context})

    @app.get("/runs/{name}/detections", response_class=HTMLResponse)
    def detections_panel(
        request: Request,
        name: str,
        tlp: str | None = None,
        types: list[str] = TYPES_IN_QUERY,
        source: str | None = None,
        exclude_private: bool = True,
        exclude_protocol: bool = True,
        profile: str | None = None,
        pick: list[str] = PICKED_IN_QUERY,
    ):
        """The rule pack panel: targets, counts, filters, and what was left out."""
        result, candidates = load_run(name)
        options, refusal = asked(request, name, result, {
            "tlp": tlp, "types": types, "source": source, "exclude_private": exclude_private,
            "exclude_protocol": exclude_protocol, "profile": profile, "pick": pick,
        })
        if refusal is not None:
            return refusal
        context = detection_context(name, result, candidates, options)
        context.pop("run")
        if is_htmx(request):
            return templates.TemplateResponse(request, "_detections.html", context)
        # Without the script the run page links here and the filter form
        # submits here, so a plain request gets a whole page around the panel.
        context["root"] = defang(result.root_url)
        return templates.TemplateResponse(request, "detections_page.html", context)

    @app.get("/runs/{name}/detections.zip")
    def detections_zip(
        request: Request,
        name: str,
        tlp: str | None = None,
        types: list[str] = TYPES_IN_QUERY,
        source: str | None = None,
        exclude_private: bool = True,
        exclude_protocol: bool = True,
        profile: str | None = None,
        pick: list[str] = PICKED_IN_QUERY,
        targets: str | None = None,
    ):
        """Every target in one archive, live, with a manifest."""
        result, candidates = load_run(name)
        options, refusal = asked(request, name, result, {
            "tlp": tlp, "types": types, "source": source, "exclude_private": exclude_private,
            "exclude_protocol": exclude_protocol, "profile": profile, "pick": pick,
        })
        if refusal is not None:
            return refusal
        if targets:
            wanted = [part.strip() for part in targets.split(",") if part.strip()]
            if any(part not in detections.TARGETS for part in wanted):
                return no_target()
            chosen = [detections.TARGETS[part] for part in wanted]
        else:
            chosen = list(detections.TARGETS.values())
        run = detections.Run(result=result, name=name, candidates=tuple(candidates))
        return Response(
            detections.zip_bytes(run, options, chosen),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{detections.zip_name(run)}"',
                **LIVE_HEADERS,
            },
        )

    @app.get("/runs/{name}/detections/{target}", response_class=HTMLResponse)
    def detection_preview(
        request: Request,
        name: str,
        target: str,
        tlp: str | None = None,
        types: list[str] = TYPES_IN_QUERY,
        source: str | None = None,
        exclude_private: bool = True,
        exclude_protocol: bool = True,
        profile: str | None = None,
        pick: list[str] = PICKED_IN_QUERY,
        format: str | None = None,  # noqa: A002 - the public name of the query field
    ):
        """One target, defanged. HTML for the panel, or text with format=text."""
        result, candidates = load_run(name)
        chosen = detections.TARGETS.get(target)
        if chosen is None:
            return no_target()
        options, refusal = asked(request, name, result, {
            "tlp": tlp, "types": types, "source": source, "exclude_private": exclude_private,
            "exclude_protocol": exclude_protocol, "profile": profile, "pick": pick,
        })
        if refusal is not None:
            return refusal
        context = detection_context(name, result, candidates, options)
        run = context.pop("run")
        text = detections.preview(chosen, run, options)
        if format == "text":
            return PlainTextResponse(text, headers={"Cache-Control": "no-store"})
        record = next(item for item in context["targets"] if item["id"] == target)
        note = None
        if chosen.needs_pick and not options.pick:
            note = "Pick files in the listing to build rules from."
        return templates.TemplateResponse(
            request,
            "_detection.html",
            {
                "name": name,
                "target": record,
                "preview": text,
                "options": context["options"],
                "left_out": record["left_out"],
                "assumes": record["assumes"],
                "empty": record["count"] == 0 and not chosen.needs_pick,
                "note": note,
            },
        )

    @app.get("/runs/{name}/detections/{target}/download")
    def detection_download(
        request: Request,
        name: str,
        target: str,
        tlp: str | None = None,
        types: list[str] = TYPES_IN_QUERY,
        source: str | None = None,
        exclude_private: bool = True,
        exclude_protocol: bool = True,
        profile: str | None = None,
        pick: list[str] = PICKED_IN_QUERY,
    ):
        """One target as the file itself: live values, saved rather than shown."""
        result, candidates = load_run(name)
        chosen = detections.TARGETS.get(target)
        if chosen is None:
            return no_target()
        options, refusal = asked(request, name, result, {
            "tlp": tlp, "types": types, "source": source, "exclude_private": exclude_private,
            "exclude_protocol": exclude_protocol, "profile": profile, "pick": pick,
        })
        if refusal is not None:
            return refusal
        run = detections.Run(result=result, name=name, candidates=tuple(candidates))
        return Response(
            detections.render(chosen, run, options),
            media_type=chosen.media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{detections.filename(run, chosen)}"',
                **LIVE_HEADERS,
            },
        )

    @app.get("/runs/{name}/diff", response_class=HTMLResponse)
    def file_diff(request: Request, name: str, a: str, b: str):
        """Two versions of the same artefact, side by side in one panel."""
        result, _ = load_run(name)
        left = next((e for e in result.entries if e.url == a), None)
        right = next((e for e in result.entries if e.url == b), None)
        if left is None or right is None:
            return not_in_run(request, name, a if left is None else b)
        return templates.TemplateResponse(
            request,
            "_diff.html",
            {"name": name, "left": left, "right": right, "rows": _diff_rows(left, right)},
        )

    @app.get("/runs/{name}/report.md", response_class=PlainTextResponse)
    def run_markdown(name: str):
        result, candidates = load_run(name)
        return render_markdown(result, candidates)

    @app.get("/runs/{name}/iocs.txt", response_class=PlainTextResponse)
    def run_iocs(name: str):
        result, _ = load_run(name)
        mask = SecretMask(result.iocs)
        return "\n".join(mask.indicator(ioc) for ioc in result.iocs)

    @app.get("/runs/{name}/hashes.txt", response_class=PlainTextResponse)
    def run_hashes(name: str):
        """sha256, md5 and path, for the files that were read whole."""
        result, _ = load_run(name)
        rows = [
            f"{entry.sha256}  {entry.md5 or '-'}  "
            f"{entry.url.removeprefix(result.root_url) or entry.name}"
            for entry in result.files
            if entry.sha256
        ]
        return "\n".join(rows)

    @app.exception_handler(NoSuchRun)
    def no_such_run(request: Request, exc: NoSuchRun):
        # The same miss reaches here two ways: a preview, a verdict or a compare
        # fetched over htmx (the panel lands in the preview, a sheet on a narrow
        # screen), or a direct visit to the run page. The name is never echoed,
        # so a name that is not a run name reads the same as one that is gone.
        if is_htmx(request):
            return templates.TemplateResponse(
                request, "_gone_run.html", {}, status_code=404
            )
        return render_error(request, ERROR_NO_SUCH_RUN, status_code=404)

    @app.exception_handler(ScopeError)
    def scope_error(request: Request, exc: ScopeError):
        # The message quotes a URL a target's listing supplied: hostile input.
        # It is passed raw; the template's autoescape quotes it once, so there is
        # no second escape to turn the markup back into visible text twice.
        return render_error(
            request, {**ERROR_REFUSED, "quote": str(exc)}, status_code=400
        )

    return app
