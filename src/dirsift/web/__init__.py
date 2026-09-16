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

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..analyze import analyze
from ..extract import defang
from ..fetcher import PrivateTargetError, ScopeError
from ..models import ScanResult
from ..report import human_size, render_markdown
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


def create_app(runs_dir: Path = Path("runs")) -> FastAPI:
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
        return templates.TemplateResponse(
            request, "index.html", {"runs": list_runs(), "jobs": jobs.all()[:8]}
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
    def run_page(request: Request, name: str):
        try:
            result, candidates = load_run(name)
        except (OSError, ValueError):
            return HTMLResponse("<h1>no such run</h1>", status_code=404)
        entries = sorted(result.entries, key=lambda e: (e.depth, not e.is_dir, e.name))
        return templates.TemplateResponse(
            request,
            "run.html",
            {
                "name": name,
                "result": result,
                "candidates": [c for c in candidates if c.score > 0][:6],
                "entries": entries,
                "by_kind": sorted(result.by_kind().items(), key=lambda kv: -len(kv[1])),
            },
        )

    @app.get("/runs/{name}/file", response_class=HTMLResponse)
    def file_preview(request: Request, name: str, url: str):
        result, _ = load_run(name)
        entry = next((e for e in result.entries if e.url == url), None)
        if entry is None:
            return HTMLResponse("<p>not in this run</p>", status_code=404)
        return templates.TemplateResponse(request, "_file.html", {"entry": entry})

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
