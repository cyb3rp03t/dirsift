"""Command line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import httpx
import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from .analyze import analyze
from .asn import ENV_PATH, AsnTable, default_table
from .banner import banner
from .diagnose import explain
from .enrich import MissingKey, api_key_from_env, lookup_hash
from .extract import defang
from .fetcher import ScopeError
from .models import ScanResult
from .report import human_size, network_note, render_markdown
from .rules import build_rules
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


def _write(path: Path, text: str, label: str) -> None:
    """Write a result, making the folder it was told to write into."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        err.print(f"[red]could not write[/] {path}: {exc.strerror}")
        raise typer.Exit(code=2) from None
    console.print(f"[green]{label}[/] {path}")


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

    if result.target_ip:
        network = network_note(result.target_asn, result.target_as_name, result.target_country)
        console.print(
            f"[dim]served from {defang(result.target_ip)}"
            f"{f'  {network}' if network else ''}[/dim]"
        )
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
            network = network_note(ioc.asn, ioc.as_name, ioc.country)
            where = f" [dim]{network}[/]" if network else ""
            console.print(f"  [magenta]{ioc.ioc_type:<9}[/] {ioc.defanged}{label}{where}")
        if len(result.iocs) > 12:
            console.print(f"  [dim]+{len(result.iocs) - 12} more, see the report[/]")
        console.print()

    # A status code on its own sends people to a search engine. The first few
    # notes carry their meaning here, so a scan that came back with nothing can
    # be understood without opening the report.
    said: set[str] = set()
    for error in result.errors:
        meaning = explain(error.detail)
        if not meaning or meaning in said:
            continue
        said.add(meaning)
        console.print(f"[yellow]{error.stage}[/] {error.detail}")
        console.print(f"  [dim]{meaning}[/]")
        if len(said) == 3:
            break
    if said:
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

    # The walk has already been paid for in requests to somebody else's server.
    # Losing it because a folder further down the path does not exist yet would
    # be the worst trade in the tool, so the folder is made.
    if save_json:
        _write(save_json, result.model_dump_json(indent=2), "run saved")

    if out:
        _write(out, render_markdown(result, candidates), "report written")


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
    result, candidates = _load(run)
    markdown = render_markdown(result, candidates, scaffold=scaffold)
    if out:
        _write(out, markdown, "report written")
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
    result, _ = _load(run)
    for ioc in result.iocs:
        if ioc_type and ioc.ioc_type != ioc_type:
            continue
        sys.stdout.write((ioc.value if fanged else ioc.defanged) + "\n")


#: md5, sha1 or sha256 and nothing else.
HASH_CHARS = set("0123456789abcdef")


def _load(run: Path) -> tuple[ScanResult, list]:
    """A saved run, re-analysed, with its entry point candidates.

    Nothing here touches the network.

    The path is the thing a person gets wrong first, usually by pointing at a
    run that was never written. A stack trace answers none of that, so the
    two ways this fails are caught and said in a sentence.
    """
    try:
        text = run.read_text(encoding="utf-8")
    except FileNotFoundError:
        console.print(f"[bold]No run at[/bold] {run}")
        console.print("[dim]A run is written by scan with --json. Check the path.[/dim]")
        raise typer.Exit(code=2) from None
    except OSError as exc:
        console.print(f"[bold]Cannot read[/bold] {run}: {exc.strerror}")
        raise typer.Exit(code=2) from None

    try:
        result = ScanResult.model_validate(json.loads(text))
    except (json.JSONDecodeError, ValidationError) as exc:
        console.print(f"[bold]{run} is not a run DirSift wrote.[/bold]")
        console.print(f"[dim]{type(exc).__name__}: {str(exc).splitlines()[0]}[/dim]")
        raise typer.Exit(code=2) from None

    return analyze(result)


@app.command("hashes")
def hashes_cmd(
    run: Annotated[Path, typer.Argument(help="A run saved with --json.")],
) -> None:
    """Print sha256, md5 and path for the files that were read whole."""
    result, _ = _load(run)
    for entry in result.files:
        if not entry.sha256:
            continue
        path = entry.url.removeprefix(result.root_url) or entry.name
        sys.stdout.write(
            f"{entry.sha256}  {entry.md5 or '-'}  {path}" + chr(10)
        )


@app.command("rules")
def rules_cmd(
    run: Annotated[Path, typer.Argument(help="A run saved with --json.")],
    names: Annotated[
        list[str] | None,
        typer.Option("--name", "-n", help="Only these files. Repeat for more."),
    ] = None,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write the rules here.")
    ] = None,
) -> None:
    """Write YARA rules from a saved run, keyed to the indicators each file carried."""
    result, _ = _load(run)
    wanted = set(names or [])
    picked = [entry for entry in result.files if not wanted or entry.name in wanted]
    rules = build_rules(result, picked, run.stem)
    if out:
        _write(out, rules, f"{len(picked)} file(s) ->")
        return
    sys.stdout.write(rules)


@app.command("check")
def check_cmd(
    digest: Annotated[str, typer.Argument(help="An md5, sha1 or sha256.")],
) -> None:
    """Ask a public scanner about one hash. The digest goes out, never a file."""
    digest = digest.strip().lower()
    if len(digest) not in (32, 40, 64) or not set(digest) <= HASH_CHARS:
        console.print("[bold]That is not a hash.[/bold] Pass an md5, a sha1 or a sha256.")
        raise typer.Exit(code=2)
    try:
        verdict = lookup_hash(digest, api_key=api_key_from_env())
    except MissingKey as exc:
        console.print(str(exc))
        raise typer.Exit(code=2) from exc
    except httpx.HTTPStatusError as exc:
        # The scanner's own status codes say which of these it is, and the
        # answer is different work each time: fix the key, wait, or look again
        # later. A raw HTTPStatusError says none of that.
        status = exc.response.status_code
        if status == 401:
            console.print("[bold]The scanner rejected the key.[/bold]")
            console.print(
                "[dim]Check DIRSIFT_VT_API_KEY. A hash pasted in place of the key "
                "looks exactly like this.[/dim]"
            )
            raise typer.Exit(code=2) from None
        if status == 403:
            console.print("[bold]That key is not allowed to ask this.[/bold]")
            console.print("[dim]A free key cannot reach every endpoint.[/dim]")
            raise typer.Exit(code=2) from None
        if status == 429:
            console.print("[bold]Over the quota.[/bold]")
            console.print(
                "[dim]A free key allows about four lookups a minute and 500 a day. "
                "Wait and ask again.[/dim]"
            )
            raise typer.Exit(code=1) from None
        console.print(f"The scanner answered {status}.")
        raise typer.Exit(code=1) from None
    except Exception as exc:  # noqa: BLE001 - the reason belongs on the terminal
        console.print(f"The lookup failed: {type(exc).__name__}: {exc}")
        raise typer.Exit(code=1) from exc

    if not verdict.found:
        console.print("not seen by the scanner: nobody has submitted this file")
        return
    analysed = f", last analysed {verdict.analysed}" if verdict.analysed else ""
    console.print(f"{verdict.malicious}/{verdict.total} engines{analysed}")


@app.command("net")
def net_cmd(
    address: Annotated[str, typer.Argument(help="An IP address seen in a file.")],
    db: Annotated[
        Path | None,
        typer.Option("--db", help="The iptoasn table to read. Default: the one this machine has."),
    ] = None,
) -> None:
    """Say which network an address belongs to, from a table on disk.

    Nothing is resolved and nobody is asked. The answer is only as current as
    the file it came from, which is why the file and its date are printed too.
    """
    table = AsnTable.load(db) if db else default_table()
    if table.empty:
        console.print("[bold]No address table on this machine.[/bold]")
        console.print(
            "Download ip2asn-combined.tsv.gz from iptoasn.com, then either put it in "
            "~/.dirsift/ or point at it:"
        )
        console.print(f"  [dim]{ENV_PATH}=/path/to/ip2asn-combined.tsv.gz[/dim]")
        raise typer.Exit(code=2)

    found = table.lookup(address)
    if not found:
        console.print(f"{defang(address)} is in no range of {table.source}.")
        raise typer.Exit(code=1)
    console.print(network_note(found.asn, found.name, found.country))
    stamp = f", dated {table.stamp}" if table.stamp else ""
    console.print(f"[dim]{table.source}{stamp}[/dim]")


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
