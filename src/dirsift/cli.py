"""Command line interface."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Annotated

import httpx
import typer
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import assessment as assess
from . import detections, report_text
from .analyze import analyze
from .asn import ENV_PATH, AsnTable, default_table
from .banner import banner
from .diagnose import explain
from .diff import diff_runs, render_diff_markdown
from .enrich import MissingKey, api_key_from_env, lookup_hash
from .extract import SecretMask, defang
from .fetcher import ScopeError
from .models import ScanResult
from .pivots import (
    ENGINES,
    STRENGTHS,
    build_pivots,
    pivot_notes,
    render_pivots_markdown,
    render_pivots_plain,
    select,
)
from .report import LOGO_MODES, human_size, network_note, render_markdown
from .report_model import (
    ReportOptions,
    build_report,
    load_run_for_report,
    normalise_tlp,
    sibling_runs,
)
from .report_pdf import render_pdf
from .rules import build_rules
from .stix import build_bundle, bundle_json, left_out
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


def _write(
    path: Path, text: str, label: str, *, say: Console | None = None, newline: str | None = None
) -> None:
    """Write a result, making the folder it was told to write into.

    The line saying where it went is printed on ``say``, stdout unless told
    otherwise: a command whose stdout is carrying a report passes stderr, so the
    pipe stays clean.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline=newline)
    except OSError as exc:
        err.print(f"[red]could not write[/] {path}: {exc.strerror}")
        raise typer.Exit(code=2) from None
    (say or console).print(f"[green]{label}[/] {path}")


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
        mask = SecretMask(result.iocs)
        for ioc in result.iocs[:12]:
            # Square brackets would be eaten as rich markup here.
            label = f" [dim]({ioc.label})[/]" if ioc.label else ""
            network = network_note(ioc.asn, ioc.as_name, ioc.country)
            where = f" [dim]{network}[/]" if network else ""
            shown = escape(mask.indicator(ioc))
            console.print(f"  [magenta]{ioc.ioc_type:<9}[/] {shown}{label}{where}")
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
        Path | None,
        typer.Option("--out", "-o", help="Write the report here: .md or .pdf by the extension."),
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
    # Checked before the walk: a typo in the file name should not cost a scan.
    report_format = _report_format(out) if out else None

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
        if save_json:
            sha = hashlib.sha256(save_json.read_bytes()).hexdigest()
            options = ReportOptions(run_name=save_json.stem, asn_recorded=bool(result.asn_source))
            siblings = sibling_runs(save_json.parent, result.root_url)
        else:
            sha, options, siblings = None, ReportOptions(), ()
        err.print(f"[dim]{report_text.TLP_NOT_SET}[/]", highlight=False)
        report = build_report(result, candidates, options, None, None, sha, siblings)
        _write_report(out, report_format, report, "inline")


REPORT_SUFFIXES = {".md": "md", ".markdown": "md", ".pdf": "pdf"}


def _report_format(out: Path) -> str:
    """The report format the file name asks for, or an exit that says which exist."""
    fmt = REPORT_SUFFIXES.get(out.suffix.lower())
    if fmt is None:
        err.print(
            f"[red]{escape(out.name)}:[/] a report is written as Markdown (.md) or PDF (.pdf); "
            "the file name decides which.",
            highlight=False,
        )
        raise typer.Exit(code=2)
    return fmt


def _write_report(out: Path, fmt: str, report, logo: str) -> None:
    if fmt == "pdf":
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(render_pdf(report))
        except OSError as exc:
            err.print(f"[red]could not write[/] {out}: {exc.strerror}")
            raise typer.Exit(code=2) from None
        console.print(f"[green]report written[/] {out}")
    else:
        _write(out, render_markdown(report, logo=logo), "report written", newline="\n")


@app.command("report")
def report_cmd(
    run: Annotated[Path, typer.Argument(help="A run saved with --json.")],
    out: Annotated[
        Path | None,
        typer.Option(
            "--out", "-o",
            help="Write here: .md or .pdf by the extension. Without it, Markdown on stdout.",
        ),
    ] = None,
    tlp: Annotated[
        str | None,
        typer.Option(
            "--tlp",
            help="CLEAR, GREEN, AMBER, AMBER+STRICT or RED. Default: the saved one, else AMBER.",
        ),
    ] = None,
    author: Annotated[
        str | None,
        typer.Option("--author", help="The analyst named in the report. Not saved anywhere."),
    ] = None,
    assessment_file: Annotated[
        Path | None,
        typer.Option(
            "--assessment",
            help="Assessment file. Default: assessments/<run file name> beside the run.",
        ),
    ] = None,
    logo: Annotated[
        str, typer.Option("--logo", help="inline (default) or none: leave the mark out.")
    ] = "inline",
    scaffold: Annotated[
        bool | None, typer.Option("--scaffold/--no-scaffold", hidden=True)
    ] = None,
) -> None:
    """Write the triage report for a saved run. Touches nothing on the network."""
    banner(f"report | {run.name}")
    if scaffold is not None:
        err.print(
            "[yellow]The writeup scaffold is gone and this flag does nothing; the Analyst "
            "assessment section takes its place.[/]",
            highlight=False,
        )
    if logo not in LOGO_MODES:
        err.print(f"[red]The logo option takes {' or '.join(LOGO_MODES)}.[/]", highlight=False)
        raise typer.Exit(code=2)
    fmt = _report_format(out) if out else "md"
    chosen = None
    if tlp is not None:
        chosen = normalise_tlp(tlp)
        if chosen is None:
            err.print(f"[red]{report_text.TLP_UNKNOWN}[/]", highlight=False)
            raise typer.Exit(code=2)

    loaded = _load_for_report(run)
    sidecar = assessment_file or assess.sidecar_path(run)
    if assessment_file is not None and not assessment_file.exists():
        err.print(f"[red]No assessment file at[/] {escape(str(assessment_file))}",
                  highlight=False)
        raise typer.Exit(code=1)
    try:
        saved = assess.load(sidecar)
    except assess.AssessmentError as exc:
        err.print(
            f"[red]Assessment file {escape(str(sidecar))} is not valid:[/] {escape(str(exc))}",
            highlight=False,
        )
        raise typer.Exit(code=1) from None

    saved_tlp = saved.get("tlp") or None
    if chosen is None and saved_tlp is None:
        err.print(f"[dim]{report_text.TLP_NOT_SET}[/]", highlight=False)
    if chosen is not None:
        warning = assess.downgrade_warning(chosen, saved_tlp)
        if warning:
            err.print(f"[yellow]{escape(warning)}[/]", highlight=False)
    level = chosen or saved_tlp or report_text.DEFAULT_TLP

    options = ReportOptions(run_name=loaded.name, tlp=level, author=author,
                            asn_recorded=loaded.asn_recorded)
    report = build_report(loaded.result, loaded.candidates, options, saved, None,
                          loaded.run_sha256, loaded.siblings)
    if out:
        _write_report(out, fmt, report, logo)
    else:
        sys.stdout.write(render_markdown(report, logo=logo))


def _load_for_report(run: Path):
    """A saved run with what the report states about the file; failures in a sentence."""
    try:
        return load_run_for_report(run)
    except FileNotFoundError:
        console.print(f"[bold]No run at[/bold] {escape(str(run))}")
        console.print("[dim]A run is written by scan with --json. Check the path.[/dim]")
        raise typer.Exit(code=2) from None
    except OSError as exc:
        err.print(f"[bold]Cannot read[/bold] {escape(str(run))}: {exc.strerror}")
        raise typer.Exit(code=2) from None
    except (ValueError, ValidationError) as exc:
        err.print(f"[bold]{escape(str(run))} is not a run DirSift wrote.[/bold]")
        err.print(f"[dim]{type(exc).__name__}: {escape(str(exc).splitlines()[0])}[/dim]")
        raise typer.Exit(code=2) from None


@app.command("diff")
def diff_cmd(
    old: Annotated[Path, typer.Argument(help="The earlier run, saved with --json.")],
    new: Annotated[Path, typer.Argument(help="The later run of the same directory.")],
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write here instead of stdout.")
    ] = None,
    save_json: Annotated[
        Path | None, typer.Option("--json", help="Save the comparison as JSON.")
    ] = None,
) -> None:
    """Compare two saved runs of one directory. Touches nothing on the network."""
    banner(f"diff | {old.name} against {new.name}")
    older, _ = _load(old)
    newer, _ = _load(new)
    changes = diff_runs(older, newer)
    markdown = render_diff_markdown(changes)

    # With no -o the markdown is the output, so every other line goes to stderr.
    say = console if out else err
    if save_json:
        _write(save_json, changes.model_dump_json(indent=2), "comparison saved", say=say)
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
    min_confidence: Annotated[
        int | None,
        typer.Option(
            "--min-confidence", "-c", help="Only indicators scored this high or higher, 0 to 100."
        ),
    ] = None,
) -> None:
    """Print just the indicators, one per line, for piping.

    A secret is printed by its kind, fixed opening, length and digest, never
    quoted, with --fanged as well: the run file holds the value.
    """
    if min_confidence is not None and not 0 <= min_confidence <= 100:
        console.print(
            f"[bold]{min_confidence} is not a confidence.[/bold] Pass a number from 0 to 100."
        )
        raise typer.Exit(code=2)
    result, _ = _load(run)
    mask = SecretMask(result.iocs)
    for ioc in result.iocs:
        if ioc_type and ioc.ioc_type != ioc_type:
            continue
        if min_confidence is not None and (ioc.confidence or 0) < min_confidence:
            continue
        shown = mask.text(ioc.value) if fanged else mask.indicator(ioc)
        sys.stdout.write(shown + "\n")


@app.command("pivots")
def pivots_cmd(
    run: Annotated[Path, typer.Argument(help="A run saved with --json.")],
    engine: Annotated[
        str | None, typer.Option("--engine", "-e", help="Only this engine: shodan or fofa.")
    ] = None,
    strength: Annotated[
        str | None,
        typer.Option(
            "--strength", "-s", help="Only this strength and stronger: narrow, medium, broad."
        ),
    ] = None,
    plain: Annotated[
        bool, typer.Option("--plain", help="One query per line, for piping.")
    ] = False,
    fanged: Annotated[
        bool, typer.Option("--fanged", help="Print live values. You asked for it.")
    ] = False,
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write here instead of stdout.")
    ] = None,
) -> None:
    """Write search queries for sibling hosts from a saved run. Runs none of them.

    Nothing is sent anywhere and no key is read. A query tells the engine what
    you are looking at, so running one is a separate decision.
    """
    if engine is not None and engine not in ENGINES:
        console.print(f"[bold]No engine called {engine}.[/bold] Pass shodan or fofa.")
        raise typer.Exit(code=2)
    if strength is not None and strength not in STRENGTHS:
        console.print(f"[bold]No strength called {strength}.[/bold] Pass narrow, medium or broad.")
        raise typer.Exit(code=2)
    if not plain:
        banner(f"pivots | {run.name}")

    result, candidates = _load(run)
    pivots = select(build_pivots(result, candidates), engine=engine, strength=strength)
    if plain:
        text = render_pivots_plain(pivots, fanged=fanged, with_engine=engine is None)
    else:
        text = render_pivots_markdown(pivots, result, pivot_notes(result, candidates))

    if out:
        _write(out, text, "pivots written")
    else:
        sys.stdout.write(text)


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


@app.command("stix")
def stix_cmd(
    run: Annotated[Path, typer.Argument(help="A run saved with --json.")],
    out: Annotated[
        Path,
        typer.Option(
            "--out", "-o", help="Write the bundle here. Required: it carries live values."
        ),
    ],
) -> None:
    """Export a saved run as a STIX 2.1 bundle. Carries live indicators; writes to a file only.

    A platform matches live values and nothing else, so nothing in the bundle
    is defanged. That is why it never goes to stdout, where it would end up in
    a terminal scrollback or a pasted log.
    """
    banner(f"stix | {run.name}")
    result, candidates = _load(run)
    bundle = build_bundle(result, candidates)
    _write(out, bundle_json(bundle), "bundle written")

    counts: dict[str, int] = {}
    for obj in bundle["objects"]:
        kind = obj["type"]
        if kind not in ("infrastructure", "indicator", "relationship"):
            kind = "observables"
        counts[kind] = counts.get(kind, 0) + 1

    table = Table(box=None, pad_edge=False, show_header=False)
    table.add_column("what", style="cyan")
    table.add_column("count", justify="right")
    for kind in ("infrastructure", "indicator", "observables", "relationship"):
        table.add_row(kind, str(counts.get(kind, 0)))
    for reason, number in left_out(result).items():
        table.add_row(f"[dim]{reason}[/]", f"[dim]{number}[/]")
    console.print(table)
    console.print(
        f"[yellow]live indicators:[/] {out.name} is not defanged. Import it, but do not "
        "open it in a browser or paste it into a chat."
    )


@app.command("detections")
def detections_cmd(
    run: Annotated[Path, typer.Argument(help="A run saved with --json.")],
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="A target id, or all. See --list."),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="A folder (or a .zip with --target all). Required: the files carry live values.",
        ),
    ] = None,
    show_list: Annotated[
        bool, typer.Option("--list", help="List the targets and what each would carry.")
    ] = False,
    tlp: Annotated[str, typer.Option("--tlp", help="CLEAR, GREEN, AMBER or RED.")] = "AMBER",
    types: Annotated[
        list[str] | None,
        typer.Option("--type", help="Only these indicator types. Repeat or use commas."),
    ] = None,
    source: Annotated[
        str | None, typer.Option("--source", help="Only indicators from this file (name or path).")
    ] = None,
    include_private: Annotated[
        bool,
        typer.Option(
            "--include-private",
            help="Keep private, reserved, multicast and documentation addresses.",
        ),
    ] = False,
    include_protocol: Annotated[
        bool,
        typer.Option("--include-protocol", help="Keep protocol strings (SSH algorithm names)."),
    ] = False,
    profile: Annotated[
        str, typer.Option("--profile", help="Block list comments: generic, paloalto or bare.")
    ] = "generic",
    pick: Annotated[
        list[str] | None,
        typer.Option("--pick", help="Files for the YARA target, by name. Repeat for more."),
    ] = None,
) -> None:
    """Write detection content from a saved run: Sigma, SPL, KQL, block lists, CSV, STIX, YARA.

    Everything is a file. Nothing is sent to any product, and nothing live is
    printed: the files carry live values, so they only go where -o points.
    """
    banner(f"detections | {run.name}")
    result, candidates = _load(run)
    try:
        options = detections.Options(
            tlp=detections.parse_tlp(tlp),
            types=detections.parse_types(types, detections.SHAREABLE),
            exclude_private=not include_private,
            exclude_protocol=not include_protocol,
            profile=detections.parse_profile(profile),
        )
    except detections.BadOption as exc:
        console.print(f"[bold]{exc}.[/bold]")
        raise typer.Exit(code=2) from None

    if source:
        wanted = source.strip("/")
        match = next(
            (
                entry
                for entry in result.files
                if entry.name == source
                or entry.url.removeprefix(result.root_url).strip("/") == wanted
                or entry.url == source
            ),
            None,
        )
        if match is None:
            console.print(f"[bold]No file {source} in this run.[/bold]")
            raise typer.Exit(code=2)
        options = replace(options, source=match.url)
    if pick:
        names = set(pick)
        options = replace(
            options, pick=tuple(e.url for e in result.files if e.name in names)
        )

    bundle_run = detections.Run(result=result, name=run.stem, candidates=tuple(candidates))
    info = detections.summary(bundle_run, options)

    if show_list:
        table = Table(box=None, pad_edge=False)
        table.add_column("target", style="cyan")
        table.add_column("carries", justify="right")
        table.add_column("file", style="dim")
        for row in info["targets"]:
            count = "pick files" if row["needs_pick"] and not options.pick else str(row["count"])
            table.add_row(row["id"], count, row["filename"])
        console.print(table)
        _left_out_table(info["left_out"])
        return

    if target is None or out is None:
        console.print("[bold]Pass --target and --out[/bold] (or --list to see the targets).")
        console.print("[dim]The files carry live values, so they are never printed.[/dim]")
        raise typer.Exit(code=2)

    if target == "all":
        chosen = list(detections.TARGETS.values())
    elif target in detections.TARGETS:
        chosen = [detections.TARGETS[target]]
        if chosen[0].needs_pick and not options.pick:
            options = replace(options, pick=tuple(e.url for e in result.files))
    else:
        console.print(f"[bold]No target {target}.[/bold] One of: all, " + ", ".join(
            detections.TARGETS))
        raise typer.Exit(code=2)

    if target == "all" and out.suffix.lower() == ".zip":
        data = detections.zip_bytes(bundle_run, options, chosen)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
        except OSError as exc:
            err.print(f"[red]could not write[/] {out}: {exc.strerror}")
            raise typer.Exit(code=2) from None
        console.print(f"[green]archive written[/] {out}")
    else:
        names = []
        for item in chosen:
            if item.needs_pick and not options.pick:
                continue
            name = detections.filename(bundle_run, item)
            names.append(name)
            _write(
                out / name,
                detections.render(item, bundle_run, options),
                "written",
                newline="\n",
            )
        if target == "all":
            _write(
                out / "MANIFEST.txt",
                detections.manifest(bundle_run, options, names),
                "written",
                newline="\n",
            )

    table = Table(box=None, pad_edge=False, show_header=False)
    table.add_column("what", style="cyan")
    table.add_column("count", justify="right")
    for kind, number in info["types"].items():
        table.add_row(kind, str(number))
    console.print(table)
    _left_out_table(info["left_out"])
    console.print(
        f"[yellow]live indicators ({options.tlp_label}):[/] the files are not defanged. Import "
        "them, but do not open them in a browser or paste them into a chat."
    )


def _left_out_table(counts: dict[str, int]) -> None:
    table = Table(box=None, pad_edge=False, show_header=False, title="left out")
    table.add_column("reason", style="dim")
    table.add_column("count", justify="right", style="dim")
    for reason, number in counts.items():
        if number:
            table.add_row(reason, str(number))
    if table.row_count:
        console.print(table)


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

    uvicorn.run(
        create_app(runs_dir, allowed_hosts=(host,)),
        host=host,
        port=port,
        log_level="warning",
    )


def main() -> None:  # pragma: no cover
    app()
