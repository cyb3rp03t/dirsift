"""Render a scan as a markdown triage page.

The page is written to be read top to bottom once and then argued with: what
is here, what groups together, what probably starts it, what is worth pulling
into a VM, and the indicators at the end where they can be copied out in one
block. Every hostname, URL and address on the page is defanged, because these
notes get pasted into chats and posts.

The last section is a scaffold for the writeup, left empty on purpose. The
tool collects; the sentences are yours.
"""

from __future__ import annotations

from datetime import datetime

from .classify import INTERESTING_NAMES, mismatch
from .diagnose import explain
from .extract import SecretMask, defang
from .glue import GlueCandidate
from .models import Entry, Kind, ScanResult

_KIND_LABEL = {
    Kind.PE: "Windows executables",
    Kind.ELF: "ELF binaries",
    Kind.MACHO: "Mach-O binaries",
    Kind.SCRIPT: "Scripts",
    Kind.ARCHIVE: "Archives",
    Kind.DOCUMENT: "Documents",
    Kind.IMAGE: "Images",
    Kind.CONFIG: "Config",
    Kind.DATA: "Data and logs",
    Kind.WEB: "Web files",
    Kind.CERT: "Certificates and keys",
    Kind.UNKNOWN: "Unidentified",
}

_IOC_LABEL = {
    "ipv4": "IPv4", "ipv6": "IPv6", "url": "URLs", "domain": "Domains",
    "email": "Email", "secret": "Credentials and tokens", "btc": "Bitcoin",
    "eth": "Ethereum", "xmr": "Monero", "mutex": "Mutexes",
    "registry": "Registry keys", "path": "Filesystem paths",
}


def human_size(size: int | None) -> str:
    if size is None:
        return "-"
    value = float(size)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024 or unit == "T":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}T"


def network_note(asn: int | None, as_name: str = "", country: str = "") -> str:
    """How an address is described once its network is known.

    Written as one string because that is how it is read: the number, who
    announces it, and where they said it was. Missing parts are simply absent.
    """
    if not asn:
        return ""
    parts = [f"AS{asn}"]
    if as_name:
        parts.append(as_name)
    tail = " ".join(parts)
    return f"{tail}, {country}" if country else tail


def _rel(entry: Entry, root: str) -> str:
    return entry.url[len(root) :] if entry.url.startswith(root) else entry.url


def _fmt_time(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "-"


def _notable(result: ScanResult) -> list[tuple[str, str]]:
    """Rows a human should look at before deciding whether to go further."""
    rows: list[tuple[str, str]] = []
    for entry in result.files:
        note = mismatch(entry)
        if note:
            rows.append((entry.name, f"**type mismatch**: {note}"))
        elif entry.kind is Kind.CERT:
            rows.append((entry.name, "certificate or key material"))
        elif entry.name.lower() in INTERESTING_NAMES or entry.name.lower().startswith("."):
            rows.append((entry.name, "name suggests configuration or credentials"))
        elif entry.kind in (Kind.PE, Kind.ELF) and not entry.ext:
            rows.append((entry.name, "executable with no extension"))
    return rows


def render_markdown(
    result: ScanResult,
    candidates: list[GlueCandidate] | None = None,
    *,
    scaffold: bool = True,
    max_rows: int = 400,
) -> str:
    candidates = candidates or []
    root = result.root_url
    lines: list[str] = []
    add = lines.append

    # Header
    add(f"# Open directory triage: {defang(root)}")
    add("")
    add(f"- **Scanned**: {_fmt_time(result.started_at)} to {_fmt_time(result.finished_at)}")
    add(f"- **Server**: `{result.server or 'not advertised'}`")
    add(f"- **Index flavour**: `{result.listing_flavor or 'unknown'}`")
    if result.target_ip:
        network = network_note(result.target_asn, result.target_as_name, result.target_country)
        suffix = f" ({network})" if network else ""
        add(f"- **Address**: `{defang(result.target_ip)}`{suffix}")
    if result.title:
        add(f"- **Page title**: {result.title}")
    families = len(result.clusters)
    add(
        f"- **Found**: {len(result.files)} files, {len(result.dirs)} directories, "
        f"{families} version {'family' if families == 1 else 'families'}"
    )
    add(
        f"- **Cost**: {result.requests_made} requests, "
        f"{human_size(result.bytes_fetched)} read"
    )
    add("")

    # Inventory
    add("## Inventory")
    add("")
    by_kind = result.by_kind()
    if not by_kind:
        add("_Nothing was listed._")
        add("")
    else:
        add("| Type | Files | Size | Examples |")
        add("|---|---:|---:|---|")
        for kind, entries in sorted(by_kind.items(), key=lambda kv: -len(kv[1])):
            total = sum(e.size or e.fetched_bytes or 0 for e in entries)
            sample = ", ".join(f"`{e.name}`" for e in entries[:3])
            if len(entries) > 3:
                sample += f", +{len(entries) - 3} more"
            add(f"| {_KIND_LABEL.get(kind, str(kind))} | {len(entries)} | "
                f"{human_size(total) if total else '-'} | {sample} |")
        add("")

    # Clusters
    if result.clusters:
        add("## Version families")
        add("")
        add("Files whose names differ only by a version token. Gaps are shown as written: ")
        add("a missing number usually means a build was pulled, not that it never existed.")
        add("")
        add("| Family | Variants | Count | Members |")
        add("|---|---|---:|---|")
        for cluster in result.clusters:
            members = ", ".join(f"`{m}`" for m in cluster.members[:6])
            if len(cluster.members) > 6:
                members += f", +{len(cluster.members) - 6} more"
            add(f"| `{cluster.label}` | {', '.join(cluster.variants)} | "
                f"{len(cluster.members)} | {members} |")
        add("")

    # Entry points
    add("## Entry point candidates")
    add("")
    ranked = [c for c in candidates if c.score > 0]
    if not ranked:
        add("_No file in this listing reads like a driver for the others._")
        add("")
    else:
        add("Ranked by how much each file looks like the thing that runs the rest. ")
        add("These are candidates, not conclusions.")
        add("")
        for candidate in ranked[:6]:
            entry = candidate.entry
            add(f"### `{_rel(entry, root)}` ({candidate.score}/100)")
            add("")
            for reason in candidate.reasons:
                add(f"- {reason}")
            if candidate.references:
                refs = ", ".join(f"`{r}`" for r in candidate.references[:10])
                add(f"- references: {refs}")
            if candidate.tells:
                add(f"- execution tells: {', '.join(f'`{t}`' for t in candidate.tells[:10])}")
            add("")

    # Notable
    notable = _notable(result)
    if notable:
        add("## Worth a second look")
        add("")
        for name, note in notable[:40]:
            add(f"- `{name}`: {note}")
        add("")

    # Hashes
    hashed = [entry for entry in result.files if entry.sha256]
    if hashed:
        add("## Hashes")
        add("")
        add("Only the files DirSift read whole. A file cut at the peek ceiling has no ")
        add("hash here, because half a file hashes to nothing anyone can look up.")
        add("")
        add("| Path | SHA256 | MD5 |")
        add("|---|---|---|")
        for entry in hashed[:max_rows]:
            add(f"| `{_rel(entry, root)}` | `{entry.sha256}` | `{entry.md5 or '-'}` |")
        add("")

    # Indicators
    add("## Indicators")
    add("")
    if not result.iocs:
        add("_Nothing extracted. Either the readable files were empty or everything here "
            "is binary._")
        add("")
    else:
        add("Defanged. Pulled from file contents only: none of these was resolved, "
            "queried or submitted anywhere. The address in the header is the one the "
            "scan connected to, which the connection had to know regardless.")
        add("")
        if result.asn_source:
            stamp = f", dated {result.asn_stamp}" if result.asn_stamp else ""
            add(f"Networks read from `{result.asn_source}`{stamp}, on this machine. "
                "ASN ownership changes, so an answer older than the address is a guess.")
            add("")
        mask = SecretMask(result.iocs)
        grouped: dict[str, list] = {}
        for ioc in result.iocs:
            grouped.setdefault(ioc.ioc_type, []).append(ioc)
        for ioc_type, items in grouped.items():
            add(f"**{_IOC_LABEL.get(ioc_type, ioc_type)}** ({len(items)})")
            add("")
            add("```")
            for ioc in items[:80]:
                label = f"  [{ioc.label}]" if ioc.label else ""
                network = network_note(ioc.asn, ioc.as_name, ioc.country)
                add(f"{mask.indicator(ioc)}{label}{f'  {network}' if network else ''}")
            if len(items) > 80:
                add(f"... +{len(items) - 80} more")
            add("```")
            add("")

    # Full listing
    add("## Full listing")
    add("")
    add("| Path | Type | Size | Modified | Family |")
    add("|---|---|---:|---|---|")
    for entry in sorted(result.entries, key=lambda e: (e.depth, not e.is_dir, e.name))[:max_rows]:
        path = _rel(entry, root)
        if entry.is_dir and not path.endswith("/"):
            path += "/"
        kind = "dir" if entry.is_dir else str(entry.kind)
        add(
            f"| `{path}` | {kind} | {human_size(entry.size or entry.fetched_bytes)} | "
            f"{entry.modified or '-'} | {entry.cluster or '-'} |"
        )
    if len(result.entries) > max_rows:
        add(f"| _+{len(result.entries) - max_rows} more rows_ | | | | |")
    add("")

    # Errors
    if result.errors:
        add("## Notes and errors")
        add("")
        for error in result.errors[:30]:
            add(f"- `{_rel(Entry(url=error.url, name=''), root) or error.url}` "
                f"({error.stage}): {error.detail}")
            meaning = explain(error.detail)
            if meaning:
                add(f"  _{meaning}_")
        add("")

    # Writeup scaffold
    if scaffold:
        add("---")
        add("")
        add("## Writeup scaffold")
        add("")
        add("Empty on purpose. The tool collects; the sentences are yours.")
        add("")
        for heading, hint in [
            ("How I found it", "the query or feed that surfaced this host, and the date"),
            ("First impression", "what it looked like before you read anything"),
            ("What is in the directory", "the inventory above, in one paragraph"),
            ("The part worth looking at", "the single file that made this interesting"),
            ("The chain", "stage to stage, in order, with arrows"),
            ("What I could not establish", "say it plainly; unproven is not the same as false"),
            ("Assessment", "operator workspace, test box, or a pile of someone else's PoCs"),
            ("Indicators", "the block above"),
            ("Credit", "whoever pointed you at it"),
        ]:
            add(f"### {heading}")
            add("")
            add(f"<!-- {hint} -->")
            add("")

    return "\n".join(lines).rstrip() + "\n"
