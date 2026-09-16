"""Command line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .analyze import analyze
from .banner import banner
from .extract import defang
from .fetcher import ScopeError
from .models import ScanResult
from .report import human_size, render_markdown
from .walker import ScanOptions, scan


def _force_utf8_stdio() -> None:
    """Make stdout and stderr carry UTF-8 whatever the console is set to.

    On Windows the console defaults to the system code page (cp1254 on a
    Turkish install), and the moment a scan turns up a filename outside it the
    whole report dies with a UnicodeEncodeError. Attacker filenames are
    routinely non-ASCII, sometimes deliberately so, and the banner is box
    drawing characters throughout. Pipes and captured streams may not expose
    reconfigure, so failures here are not fatal.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


_force_utf8_stdio()

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Triage an open directory: walk it, classify it, find what drives it, "
    "and write the notes.",
)
console = Console()
err = Console(stderr=True)


def _summary(result: ScanResult, candidates) -> None:
    table = Table(title=f"{defang(result.root_url)}", title_style="bold", box=None, pad_edge=False)
    table.add_column("type", style="cyan")
    table.add_column("files", justify="right")
    table.add_column("size", justify="right")
    table.add_column("examples", style="dim", overflow="fold")
    for kind, entries in sorted(result.by_kind().items(), key=lambda kv: -len(kv[1])):
        total = sum(e.size or e.fetched_bytes or 0 for e in entries)
        sample = ", ".join(e.name for e in entries[:3])
        table.add_row(str(kind), str(len(entries)), human_size(total) if total else "-", sample)
    console.print(table)
    console.print()

    if result.clusters:
        console.print("[bold]version families[/]")
        for cluster in result.clusters[:8]:
            console.print(
                f"  [cyan]{cluster.label}[/]  {', '.join(cluster.variants)}  "
                f"[dim]({len(cluster.members)} files)[/]"
            )
        console.print()

    ranked = [c for c in candidates if c.score > 0][:4]
    if ranked:
        console.print("[bold]entry point candidates[/]")
        for candidate in ranked:
            console.print(f"  [yellow]{candidate.score:>5}[/]  {candidate.entry.name}")
            for reason in candidate.reasons[:3]:
                console.print(f"         [dim]{reason}[/]")
        console.print()

    if result.iocs:
        console.print(f"[bold]indicators[/] [dim]({len(result.iocs)} unique, defanged)[/]")
        for ioc in result.iocs[:12]:
            # Square brackets would be eaten as rich markup here.
            label = f" [dim]({ioc.label})[/]" if ioc.label else ""
            console.print(f"  [magenta]{ioc.ioc_type:<9}[/] {ioc.defanged}{label}")
        if len(result.iocs) > 12:
            console.print(f"  [dim]+{len(result.iocs) - 12} more, see the report[/]")
        console.print()

    console.print(
        f"[dim]{result.requests_made} requests, {human_size(result.bytes_fetched)} read, "
        f"{len(result.errors)} problems[/]"
    )


@app.command("scan")
def scan_cmd(
    url: Annotated[str, typer.Argument(help="Directory URL to triage.")],
    depth: Annotated[int, typer.Option("--depth", "-d", help="Subdirectory levels to walk.")] = 2,
    delay: Annotated[
        float, typer.Option("--delay", help="Seconds between requests. Floor is 0.2.")
    ] = 1.0,
    peek: Annotated[
        bool, typer.Option("--peek/--no-peek", help="Read the first bytes of each file.")
    ] = True,
    peek_bytes: Annotated[
        int, typer.Option("--peek-bytes", help="Bytes to read per file.")
    ] = 65_536,
    max_entries: Annotated[int, typer.Option("--max-entries", help="Stop after N rows.")] = 1000,
    max_requests: Annotated[
        int, typer.Option("--max-requests", help="Hard ceiling on requests.")
    ] = 600,
    timeout: Annotated[float, typer.Option("--timeout", help="Per-request timeout.")] = 20.0,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the markdown report here.")
    ] = None,
    save_json: Annotated[
        Path | None, typer.Option("--json", help="Save the raw run for later re-analysis.")
    ] = None,
    proxy: Annotated[
        str | None, typer.Option("--proxy", help="Route through a proxy, e.g. socks5://...")
    ] = None,
    verify_tls: Annotated[
        bool, typer.Option("--verify-tls/--no-verify-tls", help="Verify certificates.")
    ] = False,
    allow_private: Annotated[
        bool, typer.Option("--allow-private", help="Permit loopback and RFC1918 targets.")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress progress.")] = False,
) -> None:
    """Walk an open directory and triage what is in it."""
    banner(f"scan | depth {depth} | {delay}s between requests")

    def progress(event: str, detail: str) -> None:
        if not quiet:
            marker = "[cyan]>[/]" if event == "listing" else "[dim].[/]"
            err.print(f"  {marker} [dim]{detail}[/]", highlight=False)

    options = ScanOptions(
        depth=depth,
        delay=delay,
        peek=peek,
        peek_bytes=peek_bytes,
        max_entries=max_entries,
        max_requests=max_requests,
        timeout=timeout,
        proxy=proxy,
        verify_tls=verify_tls,
        allow_private=allow_private,
        progress=progress,
    )

    try:
        result = scan(url, options)
    except ScopeError as exc:
        err.print(f"[red]refused:[/] {exc}")
        raise typer.Exit(2) from exc
    except KeyboardInterrupt:
        err.print("[yellow]interrupted[/]")
        raise typer.Exit(130) from None

    result, candidates = analyze(result)

    if not quiet:
        err.print()
    _summary(result, candidates)

    if save_json:
        save_json.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[green]run saved[/] {save_json}")

    if out:
        out.write_text(render_markdown(result, candidates), encoding="utf-8")
        console.print(f"[green]report written[/] {out}")


@app.command("report")
def report_cmd(
    run: Annotated[Path, typer.Argument(help="A run saved with --json.")],
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write here instead of stdout.")
    ] = None,
    scaffold: Annotated[
        bool, typer.Option("--scaffold/--no-scaffold", help="Include the writeup scaffold.")
    ] = True,
) -> None:
    """Re-render a saved run. Touches nothing on the network."""
    banner(f"report | {run.name}")
    result = ScanResult.model_validate(json.loads(run.read_text(encoding="utf-8")))
    result, candidates = analyze(result)
    markdown = render_markdown(result, candidates, scaffold=scaffold)
    if out:
        out.write_text(markdown, encoding="utf-8")
        console.print(f"[green]report written[/] {out}")
    else:
        sys.stdout.write(markdown)


@app.command("iocs")
def iocs_cmd(
    run: Annotated[Path, typer.Argument(help="A run saved with --json.")],
    ioc_type: Annotated[
        str | None, typer.Option("--type", "-t", help="Only this type, e.g. ipv4.")
    ] = None,
    fanged: Annotated[
        bool, typer.Option("--fanged", help="Print live values. You asked for it.")
    ] = False,
) -> None:
    """Print just the indicators, one per line, for piping."""
    result = ScanResult.model_validate(json.loads(run.read_text(encoding="utf-8")))
    result, _ = analyze(result)
    for ioc in result.iocs:
        if ioc_type and ioc.ioc_type != ioc_type:
            continue
        sys.stdout.write((ioc.value if fanged else ioc.defanged) + "\n")


@app.command("web")
def web_cmd(
    host: Annotated[str, typer.Option("--host", help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Port.")] = 8000,
    runs_dir: Annotated[
        Path, typer.Option("--runs", help="Where saved runs live.")
    ] = Path("runs"),
) -> None:
    """Serve the triage UI on localhost."""
    import uvicorn

    banner(f"web | http://{host}:{port}")
    from .web import create_app

    uvicorn.run(create_app(runs_dir), host=host, port=port, log_level="warning")


def main() -> None:  # pragma: no cover
    app()
