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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from ..analyze import analyze
from ..classify import mismatch
from ..enrich import MissingKey, api_key_from_env, lookup_hash
from ..extract import defang
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


#: A digest someone pastes: md5, sha1 or sha256, nothing else.
HASH = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
DIGEST_IN_FORM = Form(default="")

#: Selected files arrive as a repeated field, from the form and from the link.
PICKED_IN_FORM = Form(default=[])
PICKED_IN_QUERY = Query(default=[])

#: Bytes per row in the hex view.
HEX_COLUMNS = 16


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
        "iocs": [ioc for ioc in result.iocs if ioc.source_url == entry.url],
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


def create_app(runs_dir: Path = Path("runs"), lookup=lookup_hash) -> FastAPI:
    runs_dir = Path(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="DirSift", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    templates.env.filters["human_size"] = human_size
    templates.env.filters["defang"] = defang
    jobs = JobStore()

    # -- helpers -----------------------------------------------------------

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

    def load_run(name: str) -> tuple[ScanResult, list]:
        path = runs_dir / f"{name}.json"
        result = ScanResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
        return analyze(result)

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

    # -- routes ------------------------------------------------------------

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
            return HTMLResponse("<h1>no such job</h1>", status_code=404)
        return templates.TemplateResponse(request, "job.html", {"job": job})

    @app.get("/jobs/{job_id}/status", response_class=HTMLResponse)
    def job_status(request: Request, job_id: str):
        job = jobs.get(job_id)
        if job is None:
            return HTMLResponse("gone", status_code=404)
        return templates.TemplateResponse(request, "_status.html", {"job": job})

    @app.get("/runs/{name}", response_class=HTMLResponse)
    def run_page(request: Request, name: str, file: str | None = None):
        try:
            result, candidates = load_run(name)
        except (OSError, ValueError):
            return HTMLResponse("<h1>no such run</h1>", status_code=404)
        entries = sorted(result.entries, key=lambda e: (e.depth, not e.is_dir, e.name))
        opened = next((e for e in result.entries if e.url == file), None) if file else None
        ioc_types: dict[str, int] = {}
        for ioc in result.iocs:
            ioc_types[ioc.ioc_type] = ioc_types.get(ioc.ioc_type, 0) + 1
        return templates.TemplateResponse(
            request,
            "run.html",
            {
                "name": name,
                "result": result,
                "candidates": [c for c in candidates if c.score > 0][:6],
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

    @app.get("/runs/{name}/file", response_class=HTMLResponse)
    def file_preview(request: Request, name: str, url: str):
        result, _ = load_run(name)
        entry = next((e for e in result.entries if e.url == url), None)
        if entry is None:
            return HTMLResponse("<p>not in this run</p>", status_code=404)
        return templates.TemplateResponse(request, "_file.html", _preview(result, entry, name))

    @app.post("/runs/{name}/verdict", response_class=HTMLResponse)
    def file_verdict(request: Request, name: str, url: str):
        """Ask a public scanner about one hash, on purpose, one file at a time."""
        result, _ = load_run(name)
        entry = next((e for e in result.entries if e.url == url), None)
        if entry is None:
            return HTMLResponse("<p>not in this run</p>", status_code=404)

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
                (runs_dir / f"{name}.json").write_text(
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

    @app.get("/runs/{name}/diff", response_class=HTMLResponse)
    def file_diff(request: Request, name: str, a: str, b: str):
        """Two versions of the same artefact, side by side in one panel."""
        result, _ = load_run(name)
        left = next((e for e in result.entries if e.url == a), None)
        right = next((e for e in result.entries if e.url == b), None)
        if left is None or right is None:
            return HTMLResponse("<p>not in this run</p>", status_code=404)
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
        return "\n".join(ioc.defanged for ioc in result.iocs)

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

    @app.exception_handler(ScopeError)
    def scope_error(request: Request, exc: ScopeError):
        return HTMLResponse(f"<h1>refused</h1><p>{exc}</p>", status_code=400)

    return app
