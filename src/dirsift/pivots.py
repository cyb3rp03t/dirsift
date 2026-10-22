"""Search queries for the hosts that were set up with the same kit.

An open directory on a C2 box is rarely the only one. The same operator stands
up the next server from the same kit, and the kit leaves the same marks: the
page title, the Server header, the port, a handful of distinctive file names,
the network it was rented from. Written as queries for an internet search
engine, those marks are the shortest way to the siblings.

DirSift writes the queries and runs none of them. A query is a disclosure: it
tells whoever runs the engine what you are looking at, so pasting one is a
decision for the analyst, not a side effect of triage. Nothing in this module
opens a connection or reads a key.

One property of the engines shapes everything here: they index the page at the
root of each port and do not walk below it. A listing found at
``http://host:8080/files/`` is invisible to them; what they stored is whatever
``http://host:8080/`` served. Every query built from a listing that is not at
the root says so, and is trusted a step less.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from urllib.parse import quote, unquote, urlparse

from pydantic import BaseModel, Field

from .classify import mismatch
from .extract import defang
from .models import Entry, ScanResult

ENGINES = ("shodan", "fofa")
STRENGTHS = ("narrow", "medium", "broad")

#: How each engine spells each kind of fact. ``{}`` is the value.
#:
#: Kept in one place because the engines change their syntax, and a fix should
#: be one line. Only filters both engines document are used:
#:
#: * Shodan has no ``http.server`` filter. A Server header is searched as a
#:   quoted phrase in the banner, ``"Server: nginx/1.18.0"``. Shodan does have
#:   ``http.server_hash``, but DirSift does not compute that hash.
#: * Shodan writes an AS number with its ``AS`` prefix, FOFA without it.
#: * Shodan takes ``port`` and ``asn`` bare and every text value quoted, even a
#:   value without a space, for consistency. FOFA quotes every value.
#: * FOFA's ``=`` is a partial match and ``==`` an exact one. Partial is the
#:   default, so ``title="Index of /"`` also catches subdirectory titles. The
#:   exact form is only used for a full Server string, as a narrow variant.
#: * FOFA's ``domain=`` holds the registered domain, so it misses a subdomain
#:   such as ``cdn.example.com`` lifted from a file. Every name uses ``host=``.
SYNTAX: dict[str, dict[str, str | None]] = {
    "shodan": {
        "title": 'http.title:"{}"',
        "body": 'http.html:"{}"',
        "server": '"Server: {}"',
        "server_exact": None,
        "port": "port:{}",
        "asn": "asn:AS{}",
        "ip": "net:{}/32",
        "net": "net:{}",
        "host": 'hostname:"{}"',
        "and": " ",
    },
    "fofa": {
        "title": 'title="{}"',
        "body": 'body="{}"',
        "server": 'server="{}"',
        "server_exact": 'server=="{}"',
        "port": 'port="{}"',
        "asn": 'asn="{}"',
        "ip": 'ip="{}"',
        "net": 'ip="{}"',
        "host": 'host="{}"',
        "and": " && ",
    },
}

ENGINE_LABEL = {"shodan": "Shodan", "fofa": "FOFA"}

#: Characters no query here will try to escape. A wrong escape returns nothing,
#: and nothing reads as "no siblings", which is worse than no query at all.
NEEDS_ESCAPING = ('"', "\\", "\n", "\r")

DEFAULT_PORTS = {"http": 80, "https": 443}

#: Names every kind of server carries. A query for one finds half the internet.
GENERIC_NAMES = {
    "index.html", "index.htm", "index.php", "default.htm", "default.aspx",
    "favicon.ico", "robots.txt", "sitemap.xml", "readme.txt", "readme.md",
    "readme", "license", "license.txt", "changelog.txt", "setup.exe",
    "install.exe", "update.exe", "installer.exe", "test.txt", "test.php",
    "test.html", "1.txt", "a.exe", "a.txt", ".htaccess", ".htpasswd",
    "web.config", ".ds_store", "thumbs.db", "desktop.ini", "config.php",
    "info.php", "phpinfo.php", "upload.php", "shell.php", "main.exe",
    "run.exe", "file.exe", "new.txt", "log.txt", "error_log",
}

#: A name whose stem is shorter than this is too easy to share by accident.
MIN_STEM = 5

#: How many names, at most, are turned into queries of their own.
MAX_NAMES = 6

#: How many of the ranked entry point candidates are worth a query.
TOP_DRIVERS = 3

#: Address space no engine can see into. Spelled out rather than taken from
#: ``is_private``, which also counts the documentation ranges.
INTERNAL = [
    ipaddress.ip_network(block)
    for block in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]

_WEAKER = {"narrow": "medium", "medium": "broad", "broad": "broad"}


class Pivot(BaseModel):
    """One query for one engine, and why it is worth what it says it is."""

    engine: str  # shodan, fofa
    query: str
    url: str
    basis: str  # title, server, filename, family, network, host, neighbourhood, indicator
    strength: str  # narrow, medium, broad
    reason: str
    sources: list[str] = Field(default_factory=list)
    # The query rests on a page the engines never stored: a listing below the
    # root of its port.
    indexed_path_mismatch: bool = False
    # The form that is safe to print. The same as query and url, except for an
    # indicator, which is printed defanged like every other indicator.
    shown_query: str = ""
    shown_url: str = ""


class _NeedsEscaping(ValueError):
    """A value carries a character the query syntax would need escaped."""


def search_url(engine: str, query: str) -> str:
    """The address that opens ``query`` in the engine's own web interface."""
    if engine == "shodan":
        return "https://www.shodan.io/search?query=" + quote(query, safe="")
    encoded = base64.b64encode(query.encode("utf-8")).decode("ascii")
    return "https://en.fofa.info/result?qbase64=" + quote(encoded, safe="")


def _term(engine: str, kind: str, value: object, *, check: bool = True) -> str:
    template = SYNTAX[engine][kind]
    if template is None:
        raise KeyError(f"{engine} has no {kind} filter")
    text = str(value)
    if check and any(char in text for char in NEEDS_ESCAPING):
        raise _NeedsEscaping(text)
    return template.format(text)


def _query(engine: str, terms: list[tuple[str, object]], *, check: bool = True) -> str:
    """Terms joined the way the engine says AND."""
    joiner = SYNTAX[engine]["and"] or " "
    return joiner.join(_term(engine, kind, value, check=check) for kind, value in terms)


def defang_url(url: str) -> str:
    """A search link that cannot be clicked by accident: the scheme is neutered."""
    return url.replace("https://", "hxxps://", 1).replace(".", "[.]", 2)


def _port(root_url: str) -> int | None:
    """The port the listing was served on, from the URL or from its scheme."""
    parsed = urlparse(root_url)
    try:
        return parsed.port or DEFAULT_PORTS.get(parsed.scheme)
    except ValueError:
        return None


def _root_path(root_url: str) -> str:
    return unquote(urlparse(root_url).path) or "/"


def _folder(entry: Entry) -> str:
    """The path of the listing page that named this entry."""
    if entry.parent_url:
        return unquote(urlparse(entry.parent_url).path) or "/"
    path = unquote(urlparse(entry.url).path)
    return path.rsplit("/", 1)[0] + "/"


def _internal(address: str) -> bool | None:
    """True for an address no engine indexes, None for something not an address."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    return any(ip in block for block in INTERNAL if block.version == ip.version)


def _generic(name: str) -> bool:
    stem, dot, _ = name.rpartition(".")
    stem = stem if dot else name
    return name.lower() in GENERIC_NAMES or len(stem) < MIN_STEM


class _Collector:
    """Gathers pivots and the notes about the ones that could not be written."""

    def __init__(self) -> None:
        self.pivots: list[Pivot] = []
        self.notes: list[str] = []

    def add(
        self,
        terms: list[tuple[str, object]],
        *,
        basis: str,
        strength: str,
        reason: str,
        sources: list[str],
        folder: str = "/",
        engines: tuple[str, ...] = ENGINES,
    ) -> None:
        """One pivot per engine, demoted a step when its page was never indexed.

        ``folder`` is the path of the page the query describes. Anything other
        than the root of the port is a page the engines did not store.
        """
        mismatch = folder != "/"
        if mismatch:
            strength = _WEAKER[strength]
            reason = (
                f"{reason}; search engines index the root page of a port, and this "
                f"listing sits under {folder}, so the query only matches if the root "
                "lists the same content"
            )
        for engine in engines:
            try:
                query = _query(engine, terms)
            except _NeedsEscaping:
                self.notes.append(
                    f"{ENGINE_LABEL[engine]} {basis} pivot skipped, value needs escaping "
                    f"({', '.join(sources)})."
                )
                continue
            except KeyError:
                continue
            self.pivots.append(
                Pivot(
                    engine=engine,
                    query=query,
                    url=search_url(engine, query),
                    basis=basis,
                    strength=strength,
                    reason=reason[0].upper() + reason[1:] + ".",
                    sources=sources,
                    indexed_path_mismatch=mismatch,
                )
            )


# -- the pivots ----------------------------------------------------------------


def _listing(result: ScanResult, out: _Collector) -> None:
    """The page itself: its title, alone and with the Server header and port."""
    if not result.title:
        return
    folder = _root_path(result.root_url)
    port = _port(result.root_url)
    out.add(
        [("title", result.title)],
        basis="title",
        strength="broad",
        reason="a page title on its own is shared by every index of its kind",
        sources=["title"],
        folder=folder,
    )
    if result.server and port:
        out.add(
            [("title", result.title), ("server", result.server), ("port", port)],
            basis="title",
            strength="medium",
            reason="the title with the Server header and the port describes one setup, "
            "though a common one",
            sources=["title", "server", "port"],
            folder=folder,
        )


#: The title a root index usually carries, by the server that wrote it.
ROOT_TITLES = {
    "apache": "Index of /",
    "nginx": "Index of /",
    "caddy": "Index of /",
    "python": "Directory listing for /",
}


def _root_guess(result: ScanResult, out: _Collector) -> None:
    """The title the root would carry if it were an index too.

    When the listing sits below the root, the page the engines stored is the
    root, and nothing in the run says what that page is. If it is an index of
    the same kind, it has the server's usual root title.
    """
    guess = ROOT_TITLES.get(result.listing_flavor or "")
    if _root_path(result.root_url) == "/" or not guess:
        return
    out.add(
        [("title", guess)],
        basis="title",
        strength="broad",
        reason="this assumes the root of the port is an index as well, which the run "
        "never saw",
        sources=["listing_flavor"],
    )


def _server(result: ScanResult, out: _Collector) -> None:
    """The Server header, which the engines store for every port they visit.

    A string that carries a version describes one build of one server and is
    worth a medium query; a bare product name is not. The exact match exists
    only in FOFA, and with the port it is the narrowest thing a header can say.
    """
    if not result.server:
        return
    versioned = bool(re.search(r"\d", result.server))
    out.add(
        [("server", result.server)],
        basis="server",
        strength="medium" if versioned else "broad",
        reason="a Server header with its version names one build of one server"
        if versioned
        else "a Server header without a version is shared by most of its kind",
        sources=["server"],
    )
    port = _port(result.root_url)
    if port:
        out.add(
            [("server_exact", result.server), ("port", port)],
            basis="server",
            strength="narrow",
            reason="the exact Server string on the same port joins two facts",
            sources=["server", "port"],
            engines=("fofa",),
        )


def _notable_names(result: ScanResult, candidates) -> tuple[list[tuple[Entry, str, str]], int]:
    """The files whose names say most about the kit, and how many were too generic.

    In order of trust: the files ranked as the driver, one build from each
    version family, and every file whose bytes contradict its extension.
    Returns (entry, basis, why) for each, and the count of generic names left
    out along the way.
    """
    by_name = {}
    for entry in result.files:
        by_name.setdefault(entry.name, entry)

    picked: list[tuple[Entry, str, str]] = []
    generic: set[str] = set()

    def offer(entry: Entry | None, basis: str, why: str) -> None:
        if entry is None or any(entry.name == chosen.name for chosen, _, _ in picked):
            return
        if _generic(entry.name):
            generic.add(entry.name)
            return
        picked.append((entry, basis, why))

    for candidate in [c for c in candidates if c.score > 0][:TOP_DRIVERS]:
        offer(candidate.entry, "filename", "the file ranked as the driver")
    for cluster in result.clusters:
        offer(by_name.get(cluster.members[0]), "family", f"one build of {cluster.label}")
    for entry in result.files:
        if mismatch(entry):
            offer(entry, "filename", "a file whose bytes contradict its extension")
    return picked[:MAX_NAMES], len(generic)


def _names(result: ScanResult, candidates, out: _Collector) -> None:
    """Names as text in the listing body, alone and in pairs from one folder.

    The engines store the page they fetched, and an index page is mostly file
    names, so a distinctive name is searchable. A pair from the same folder is
    the closest a query gets to describing the kit itself.
    """
    picked, generic = _notable_names(result, candidates)
    if generic:
        out.notes.append(
            f"{generic} generic file name{'s were' if generic != 1 else ' was'} left out: "
            "every kind of server carries them."
        )
    for entry, basis, why in picked:
        out.add(
            [("body", entry.name)],
            basis=basis,
            strength="medium",
            reason=f"{why} is a rare name to find in an index page, though it may be "
            "missed on very long listings",
            sources=[entry.name],
            folder=_folder(entry),
        )
    folders: dict[str, list[Entry]] = {}
    for entry, _, _ in picked:
        folders.setdefault(_folder(entry), []).append(entry)
    for folder, entries in folders.items():
        if len(entries) < 2:
            continue
        first, second = entries[0], entries[1]
        out.add(
            [("body", first.name), ("body", second.name)],
            basis="filename",
            strength="narrow",
            reason="two distinctive names listed side by side describe the kit rather "
            "than a server, though they may be missed on very long listings",
            sources=[first.name, second.name],
            folder=folder,
        )


def _network(result: ScanResult, out: _Collector) -> None:
    """The title and port, inside the network the target was rented from."""
    if not result.target_asn:
        if result.asn_source:
            why = f"{result.asn_source} had no range for the target's address"
        else:
            why = "no address table was on the machine when the run was placed"
        out.notes.append(f"No network pivot: {why}.")
        return
    port = _port(result.root_url)
    if not result.title or not port:
        return
    out.add(
        [("asn", result.target_asn), ("port", port), ("title", result.title)],
        basis="network",
        strength="narrow",
        reason="the same page on the same port inside the same provider joins three facts",
        sources=["target_asn", "port", "title"],
        folder=_root_path(result.root_url),
    )


def _host(result: ScanResult, out: _Collector) -> None:
    """The target's own address and name, and the block around it.

    Every other port on the same box is one query away, and a panel or a second
    index often sits there. The /24 around it catches staging hosts rented
    together, and a great deal else.
    """
    host = urlparse(result.root_url).hostname or ""
    if _internal(host) is None and host:
        out.add(
            [("host", host)],
            basis="host",
            strength="medium",
            reason="the target's own name finds every port the engines saw under it",
            sources=["root_url"],
        )
    address = result.target_ip or (host if _internal(host) is not None else "")
    internal = _internal(address) if address else None
    if internal is None:
        return
    if internal:
        out.notes.append(
            "No pivots for the target's address: it is private, and no engine indexes it."
        )
        return
    ip = ipaddress.ip_address(address)
    if ip.version != 4:
        out.notes.append("No address pivots: the engines' single address filter is IPv4.")
        return
    out.add(
        [("ip", address)],
        basis="host",
        strength="medium",
        reason="the same address finds the other ports open on this box",
        sources=["target_ip"],
    )
    block = ipaddress.ip_network(f"{address}/24", strict=False)
    out.add(
        [("net", str(block))],
        basis="neighbourhood",
        strength="broad",
        reason="the surrounding /24 catches staging hosts rented together, and is noisy "
        "for the same reason",
        sources=["target_ip"],
    )


def _indicators(result: ScanResult, out: _Collector) -> None:
    """Addresses and names lifted from the files, as hosts to look at.

    Printed defanged by default, like every other indicator: the query is shown
    with the value neutered, and only a request for live values prints it whole.
    """
    skipped = 0
    for ioc in result.iocs:
        if ioc.ioc_type == "ipv4":
            address = ioc.value.split(":", 1)[0]
            if _internal(address):
                skipped += 1
                continue
            terms = [("ip", address)]
        elif ioc.ioc_type == "domain":
            terms = [("host", ioc.value)]
        else:
            continue
        before = len(out.pivots)
        out.add(
            terms,
            basis="indicator",
            strength="medium",
            reason="an address or name the kit itself calls is where the operator's "
            "other hosts usually sit",
            sources=sorted({_file_name(url) for url in ioc.sources or [ioc.source_url]}),
        )
        shown = defang(ioc.value.split(":", 1)[0] if ioc.ioc_type == "ipv4" else ioc.value)
        for pivot in out.pivots[before:]:
            pivot.shown_query = _query(
                pivot.engine, [(terms[0][0], shown)], check=False
            )
            pivot.shown_url = defang_url(search_url(pivot.engine, pivot.shown_query))
    if skipped:
        out.notes.append(
            f"{skipped} private address{'es' if skipped != 1 else ''} from the files "
            f"{'were' if skipped != 1 else 'was'} left out: no engine indexes "
            f"{'them' if skipped != 1 else 'it'}."
        )


def _file_name(url: str) -> str:
    return unquote(urlparse(url).path.rstrip("/").rsplit("/", 1)[-1])


def _collect(result: ScanResult, candidates) -> _Collector:
    out = _Collector()
    _listing(result, out)
    _root_guess(result, out)
    _server(result, out)
    _names(result, candidates, out)
    _network(result, out)
    _host(result, out)
    _indicators(result, out)
    return out


def _ordered(pivots: list[Pivot]) -> list[Pivot]:
    """Strongest first, then by basis, engine and query, with repeats dropped."""
    seen: set[tuple[str, str]] = set()
    unique = []
    for pivot in pivots:
        if (pivot.engine, pivot.query) in seen:
            continue
        seen.add((pivot.engine, pivot.query))
        unique.append(pivot)
    rank = {strength: index for index, strength in enumerate(STRENGTHS)}
    for pivot in unique:
        pivot.shown_query = pivot.shown_query or pivot.query
        pivot.shown_url = pivot.shown_url or pivot.url
    return sorted(unique, key=lambda p: (rank[p.strength], p.basis, p.engine, p.query))


def build_pivots(result: ScanResult, candidates) -> list[Pivot]:
    """Every query this run supports, strongest first. Runs none of them."""
    return _ordered(_collect(result, candidates).pivots)


def pivot_notes(result: ScanResult, candidates) -> list[str]:
    """What could not be turned into a query, and why."""
    return _collect(result, candidates).notes


def select(
    pivots: list[Pivot], *, engine: str | None = None, strength: str | None = None
) -> list[Pivot]:
    """The pivots for one engine, at one strength or stronger."""
    floor = STRENGTHS.index(strength) if strength else len(STRENGTHS) - 1
    return [
        pivot
        for pivot in pivots
        if (engine is None or pivot.engine == engine)
        and STRENGTHS.index(pivot.strength) <= floor
    ]


# -- the page --------------------------------------------------------------------


def _code(text: str) -> str:
    """Inline code that survives a backtick inside the value."""
    return f"`` {text} ``" if "`" in text else f"`{text}`"


def render_pivots_markdown(
    pivots: list[Pivot], result: ScanResult, notes: list[str] | None = None
) -> str:
    """The queries as a page: strongest first, each with why it is worth that much.

    Indicator queries are printed defanged, with a line saying so above each,
    because the page gets pasted into chats where a live address is a liability.
    The target's own name and address are printed as they are: the reader
    already scanned it.
    """
    lines: list[str] = []
    add = lines.append

    add(f"# Pivots: {defang(result.root_url)}")
    add("")
    add(f"- **Run**: {result.started_at.strftime('%Y-%m-%d %H:%M UTC')}")
    add(f"- **Queries**: {len(pivots)}")
    add("")
    add(
        "These are searches for other hosts set up with the same kit: the same page, "
        "the same Server header, the same file names, the same network. None of them "
        "has been run. A query tells whoever runs the engine what you are looking at, "
        "so pasting one is your decision. Shodan only answers filtered searches for a "
        "logged-in account."
    )
    add("")

    folder = _root_path(result.root_url)
    if folder != "/":
        add(
            f"> **This listing is not at the root of its port.** Search engines index the "
            f"page at `/` of each port and never see `{folder}`, so the queries built from "
            "the listing are marked and trusted a step less."
        )
        add("")

    for strength in STRENGTHS:
        group = [pivot for pivot in pivots if pivot.strength == strength]
        if not group:
            continue
        add(f"## {strength.capitalize()}")
        add("")
        for pivot in group:
            label = ENGINE_LABEL[pivot.engine]
            if pivot.basis == "indicator":
                add("- _Defanged on purpose, like every indicator here. Restore it before "
                    "running it._")
                add(f"  **{label}** {_code(pivot.shown_query)}")
            else:
                add(f"- **{label}** {_code(pivot.shown_query)}")
            add(f"  - [open in {label}]({pivot.shown_url})")
            add(f"  - {pivot.reason}")
            add(f"  - from: {', '.join(_code(source) for source in pivot.sources)}")
            if pivot.indexed_path_mismatch:
                add("  - built from a page the engines do not index")
        add("")

    if notes:
        add("## Notes")
        add("")
        for note in notes:
            add(f"- {note}")
        add("")

    if not pivots:
        add("_Nothing in this run supports a query._")
        add("")

    return "\n".join(lines).rstrip() + "\n"


def render_pivots_plain(
    pivots: list[Pivot], *, fanged: bool = False, with_engine: bool = True
) -> str:
    """One query per line, for a pipe.

    A pipe has nowhere to say "defanged on purpose", so indicator queries are
    left out unless live values were asked for, and then printed live.
    """
    rows = []
    for pivot in pivots:
        if pivot.basis == "indicator" and not fanged:
            continue
        rows.append(f"{pivot.engine}\t{pivot.query}" if with_engine else pivot.query)
    return "".join(row + "\n" for row in rows)
