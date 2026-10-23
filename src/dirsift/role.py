"""What kind of box this is, as candidates with their reasons.

The same attacker host does very different jobs, and the next step depends on
which one: on a distribution server you collect the builds and the addresses
they call, on a panel the traces that identify the panel, on a drop you first
decide how to handle other people's stolen data before reading any more of it.

Like the entry point guess, this is a candidate and not a verdict. It reads
only what the run already holds: file and folder names, the kinds the
classifier gave them, version families, the execution tells and references the
glue pass found, and the indicators already extracted. No request is made and
no file is read again.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import NamedTuple
from urllib.parse import unquote, urlparse

from .extract import execution_tells
from .models import Entry, HostRole, Kind, RoleCandidate, ScanResult

#: The roles, in the order ties are broken.
ROLES = ("distribution", "panel", "drop", "phishing", "toolkit")

#: What each role is called in STIX's infrastructure type vocabulary.
STIX_TYPES = {
    "distribution": "hosting-malware",
    "panel": "command-and-control",
    "drop": "exfiltration",
    "phishing": "phishing",
    "toolkit": "staging",
}

#: Every threshold the guess uses, in one place.
LIMITS = {
    "floor": 0,
    "ceiling": 100,
    "lead": 50,  # a role below this is not worth naming
    "margin": 15,  # two roles closer than this are both in play
    "evidence": 8,  # files kept per role; more is noise
    "report_evidence": 5,  # files shown per role on the page
    "web_files": 3,  # one php file is a page; three are an application
    "drop_files": 10,  # below this a listing is too small to call mostly data
    "victims": 5,  # five victim-shaped folders is a pattern, two a coincidence
    "callback_confidence": 75,  # high confidence, from the confidence pass
    "tool_prefix": 5,  # shorter tool names only count as the whole stem
    "layout_dirs": 2,  # of css, js, img, images
}

#: The share of files that have to be data before a listing reads as a drop.
DATA_SHARE = 0.5

#: Ports a web server is expected on. Anything else on a python index is odd.
STANDARD_PORTS = {None, 80, 443}


class Signal(NamedTuple):
    role: str
    name: str
    points: int  # per hit; per distinct name when ``cap`` is set
    reason: str  # ``{detail}`` is filled with what matched
    cap: int | None = None


#: Every signal, what it is worth and the sentence that goes with it. Reasons
#: are listed by their effect, and ties keep this order.
SIGNALS = (
    # A shelf of binaries is what a distribution host is for.
    Signal("distribution", "executables", 20, "executables on the shelf"),
    # Several builds of one thing: a payload under active development.
    Signal("distribution", "builds", 20, "a run of builds: {detail}"),
    # The script that pulls or starts the binaries beside it ties them together.
    Signal("distribution", "launcher", 20, "a script that fetches or launches files that sit here"),
    # Weaker: the glue ranking is itself a guess.
    Signal("distribution", "script_driver", 10, "the top entry point candidate is a script"),
    # A confident callback in code says the kit is wired up, not just stored.
    Signal("distribution", "callback", 10, "a callback address in a script or config"),
    # Operators stand these up in a hurry; weak on its own.
    Signal("distribution", "python_port", 5, "a throwaway python server on an odd port"),
    # A panel's name is the strongest single sign of one.
    Signal("panel", "panel_names", 25, "named like a panel"),
    # An application rather than a listing of files.
    Signal("panel", "web_files", 15, "web application files, not just a listing"),
    # Where a panel keeps its credentials and its victims.
    Signal("panel", "panel_config", 15, "panel configuration or a database dump"),
    # The usual folders of a PHP panel; common elsewhere too.
    Signal("panel", "panel_dirs", 10, "a panel's folder layout"),
    # Many folders named after machines is the clearest sign of a drop.
    Signal("drop", "victims", 25, "many folders named like victims"),
    # Stealer logs have fixed names; each one adds, three are enough.
    Signal("drop", "stealer_names", 10, "stealer log layout", cap=30),
    # A drop is mostly what was taken.
    Signal("drop", "mostly_data", 20, "mostly data files"),
    # The tool that moved the data out.
    Signal("drop", "exfil_client", 10, "an exfiltration client"),
    # Kits commonly report through a Telegram bot.
    Signal("phishing", "telegram", 25, "a Telegram bot token; kits commonly report through one"),
    # Kits write what victims typed into a file beside them.
    Signal("phishing", "results", 20, "a kit writing its results next to itself"),
    # The script a phishing form posts to.
    Signal("phishing", "form_handler", 20, "named like a kit's form handler"),
    # A cloned site keeps the original's layout.
    Signal("phishing", "cloned_layout", 10, "a cloned site's layout"),
    # Named tools tell a toolkit, and nothing else does. Fifteen a name so four
    # tools can lead a listing; a cap of sixty keeps a pile of names from
    # drowning every other role. Names are cheap, so the reason says so.
    Signal(
        "toolkit",
        "tools",
        15,
        "named like {detail}; names are cheap, check the bytes before believing it",
        cap=60,
    ),
)

EXECUTABLE_KINDS = {Kind.PE, Kind.ELF, Kind.MACHO}
CODE_KINDS = {Kind.SCRIPT, Kind.CONFIG}

PANEL_NAMES = {
    "login", "admin", "panel", "gate", "dashboard", "cp", "manage", "bot", "bots",
    "tasks", "install", "setup",
}
PANEL_CONFIG_NAMES = {
    "config.php", "db.php", "database.php", "conn.php", "connect.php", "settings.php", ".env",
}
PANEL_CONFIG_EXTENSIONS = {"sql"}
PANEL_DIRS = {"includes", "inc", "admin", "panel", "api", "gate", "bots"}

STEALER_NAMES = {
    "passwords.txt", "cookies", "autofill", "wallets", "information.txt",
    "userinformation.txt", "system_info.txt", "screenshot", "screen.jpg", "cc.txt", "history",
}
EXFIL_PREFIXES = ("rclone", "winscp", "megasync", "mega")

RESULT_NAMES = {"results.txt", "result.txt", "log.txt", "logs.txt", "rezult.txt"}
FORM_HANDLERS = {
    "next.php", "post.php", "send.php", "mail.php", "email.php", "submit.php", "verify.php",
}
SITE_INDEXES = {"index.html", "index.php"}
SITE_DIRS = {"css", "js", "img", "images"}

TOOLS = (
    "mimikatz", "rubeus", "sharphound", "adfind", "lazagne", "procdump", "psexec", "nc",
    "nc64", "ncat", "chisel", "ligolo", "frpc", "frps", "gost", "plink", "ngrok", "rclone",
    "anydesk", "winpeas", "linpeas", "nmap", "masscan", "sliver", "havoc", "beacon",
    "cobaltstrike",
)

#: Names a victim's folder or archive is given: a bracketed country code, an
#: address, a hardware ID, or a date beside a user name.
VICTIM_NAMES = (
    re.compile(r"^\[[a-z]{2}\]", re.I),
    re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"),
    re.compile(r"[0-9a-f]{16,}", re.I),
    re.compile(r"\d{4}[-_.]\d{2}[-_.]\d{2}.*[^\W\d_]{3,}|[^\W\d_]{3,}.*\d{4}[-_.]\d{2}[-_.]\d{2}"),
)


class Hit(NamedTuple):
    evidence: list[str]
    count: int = 1  # distinct names, for a signal paid per name
    detail: str = ""


class _Run:
    """The run, indexed the way the signals ask about it."""

    def __init__(self, result: ScanResult, candidates) -> None:
        self.result = result
        self.root = result.root_url
        self.candidates = [c for c in candidates if c.score > 0]
        self.files = result.files
        self.dirs = result.dirs
        self.by_url = {entry.url: entry for entry in self.files}

    def path(self, entry: Entry) -> str:
        rel = unquote(entry.url.removeprefix(self.root)) or entry.name
        return rel.rstrip("/") + "/" if entry.is_dir else rel


def _name(entry: Entry) -> str:
    return entry.name.lower()


def _stem(entry: Entry) -> str:
    stem, dot, _ = entry.name.lower().rpartition(".")
    return stem if dot and stem else entry.name.lower()


def _ext(entry: Entry) -> str:
    return entry.ext


def _hit(run: _Run, entries: list[Entry], **extra) -> Hit | None:
    return Hit([run.path(entry) for entry in entries], **extra) if entries else None


# -- distribution -------------------------------------------------------------------


def _executables(run: _Run) -> Hit | None:
    return _hit(run, [e for e in run.files if e.kind in EXECUTABLE_KINDS])


def _builds(run: _Run) -> Hit | None:
    names = {e.name: e for e in run.files}
    for cluster in run.result.clusters:
        members = [names[m] for m in cluster.members if m in names]
        if any(member.kind in EXECUTABLE_KINDS for member in members):
            return _hit(run, members, detail=cluster.label)
    return None


def _launcher(run: _Run) -> Hit | None:
    scripts = [
        e for e in run.files
        if e.kind is Kind.SCRIPT and e.references and execution_tells(e.text_preview or "")
    ]
    return _hit(run, scripts)


def _script_driver(run: _Run) -> Hit | None:
    if run.candidates and run.candidates[0].entry.kind is Kind.SCRIPT:
        return _hit(run, [run.candidates[0].entry])
    return None


def _callback(run: _Run) -> Hit | None:
    sources: list[Entry] = []
    for ioc in run.result.iocs:
        if ioc.ioc_type not in ("url", "ipv4", "ipv6") or ioc.confidence is None:
            continue
        if ioc.confidence < LIMITS["callback_confidence"]:
            continue
        for url in ioc.sources or [ioc.source_url]:
            entry = run.by_url.get(url)
            if entry is not None and entry.kind in CODE_KINDS and entry not in sources:
                sources.append(entry)
    return _hit(run, sources)


def _python_port(run: _Run) -> Hit | None:
    parsed = urlparse(run.root)
    try:
        port = parsed.port
    except ValueError:
        return None
    if run.result.listing_flavor == "python" and port not in STANDARD_PORTS:
        return Hit([])
    return None


# -- panel --------------------------------------------------------------------------


def _web_files(run: _Run) -> Hit | None:
    web = [e for e in run.files if e.kind is Kind.WEB]
    return _hit(run, web) if len(web) >= LIMITS["web_files"] else None


def _panel_names(run: _Run) -> Hit | None:
    return _hit(run, [e for e in run.files if e.kind is Kind.WEB and _stem(e) in PANEL_NAMES])


def _panel_config(run: _Run) -> Hit | None:
    return _hit(
        run,
        [
            e for e in run.files
            if _name(e) in PANEL_CONFIG_NAMES or _ext(e) in PANEL_CONFIG_EXTENSIONS
        ],
    )


def _panel_dirs(run: _Run) -> Hit | None:
    return _hit(run, [e for e in run.dirs if _name(e) in PANEL_DIRS])


# -- drop ---------------------------------------------------------------------------


def _mostly_data(run: _Run) -> Hit | None:
    data = [e for e in run.files if e.kind is Kind.DATA]
    if len(run.files) >= LIMITS["drop_files"] and len(data) >= DATA_SHARE * len(run.files):
        return _hit(run, data)
    return None


def _stealer_names(run: _Run) -> Hit | None:
    matched = [
        e for e in run.result.entries if _name(e) in STEALER_NAMES or _stem(e) in STEALER_NAMES
    ]
    distinct = {_name(e) if _name(e) in STEALER_NAMES else _stem(e) for e in matched}
    return _hit(run, matched, count=len(distinct))


def _victims(run: _Run) -> Hit | None:
    shaped = [
        e for e in run.result.entries
        if (e.is_dir or e.kind is Kind.ARCHIVE)
        and any(pattern.search(e.name) for pattern in VICTIM_NAMES)
    ]
    return _hit(run, shaped) if len(shaped) >= LIMITS["victims"] else None


def _exfil_client(run: _Run) -> Hit | None:
    return _hit(run, [e for e in run.files if _stem(e).startswith(EXFIL_PREFIXES)])


# -- phishing -----------------------------------------------------------------------


def _results(run: _Run) -> Hit | None:
    if not any(e.kind is Kind.WEB for e in run.files):
        return None
    return _hit(run, [e for e in run.files if _name(e) in RESULT_NAMES])


def _form_handler(run: _Run) -> Hit | None:
    return _hit(run, [e for e in run.files if _name(e) in FORM_HANDLERS])


def _telegram(run: _Run) -> Hit | None:
    sources: list[Entry] = []
    for ioc in run.result.iocs:
        if ioc.ioc_type != "secret" or ioc.label != "telegram_bot_token":
            continue
        for url in ioc.sources or [ioc.source_url]:
            entry = run.by_url.get(url)
            if entry is not None and entry.kind in (Kind.WEB, Kind.SCRIPT) and entry not in sources:
                sources.append(entry)
    return _hit(run, sources)


def _cloned_layout(run: _Run) -> Hit | None:
    index = [e for e in run.files if _name(e) in SITE_INDEXES]
    layout = [e for e in run.dirs if _name(e) in SITE_DIRS]
    handlers = [e for e in run.files if _name(e) in FORM_HANDLERS]
    if index and len({_name(e) for e in layout}) >= LIMITS["layout_dirs"] and handlers:
        return _hit(run, index + layout)
    return None


# -- toolkit ------------------------------------------------------------------------


def _tool(entry: Entry) -> str | None:
    """The tool a file is named like, if any. Short names only as the whole stem."""
    stem = _stem(entry)
    for tool in TOOLS:
        if stem == tool or (len(tool) >= LIMITS["tool_prefix"] and stem.startswith(tool)):
            return tool
    return None


def _tools(run: _Run) -> Hit | None:
    matched = [e for e in run.files if _tool(e)]
    names = list(dict.fromkeys(_tool(e) for e in matched))
    return _hit(run, matched, count=len(names), detail=", ".join(names))


DETECTORS: dict[str, Callable[[_Run], Hit | None]] = {
    "executables": _executables,
    "builds": _builds,
    "launcher": _launcher,
    "script_driver": _script_driver,
    "callback": _callback,
    "python_port": _python_port,
    "panel_names": _panel_names,
    "web_files": _web_files,
    "panel_config": _panel_config,
    "panel_dirs": _panel_dirs,
    "victims": _victims,
    "stealer_names": _stealer_names,
    "mostly_data": _mostly_data,
    "exfil_client": _exfil_client,
    "telegram": _telegram,
    "results": _results,
    "form_handler": _form_handler,
    "cloned_layout": _cloned_layout,
    "tools": _tools,
}


# -- the guess ----------------------------------------------------------------------


def _points(signal: Signal, hit: Hit) -> int:
    if signal.cap is None:
        return signal.points
    return min(signal.points * hit.count, signal.cap)


def _candidate(role: str, run: _Run) -> RoleCandidate:
    """One role's score, its reasons by effect, and the files behind it."""
    applied: list[tuple[int, int, str]] = []
    evidence: list[str] = []
    for order, signal in enumerate(SIGNALS):
        if signal.role != role:
            continue
        hit = DETECTORS[signal.name](run)
        if hit is None:
            continue
        points = _points(signal, hit)
        applied.append((points, order, signal.reason.format(detail=hit.detail)))
        for path in hit.evidence:
            if path not in evidence:
                evidence.append(path)
    total = sum(points for points, _, _ in applied)
    score = max(LIMITS["floor"], min(LIMITS["ceiling"], total))
    applied.sort(key=lambda item: (-item[0], item[1]))
    return RoleCandidate(
        role=role,
        score=score,
        reasons=[reason for _, _, reason in applied],
        evidence=evidence[: LIMITS["evidence"]],
    )


def _lead(candidates: list[RoleCandidate]) -> str:
    """The leading role, ``mixed`` when two are close, ``unclear`` when none is strong."""
    if not candidates or candidates[0].score < LIMITS["lead"]:
        return "unclear"
    if len(candidates) > 1 and candidates[1].score >= LIMITS["lead"]:
        if candidates[0].score - candidates[1].score < LIMITS["margin"]:
            return "mixed"
    return candidates[0].role


def describe_lead(role: HostRole) -> str:
    """The lead in a few words: one role and its score, or the two that are close."""
    if role.lead == "unclear" or not role.candidates:
        return "unclear"
    if role.lead == "mixed":
        return "mixed: " + ", ".join(f"{c.role} {c.score}" for c in role.candidates[:2])
    return f"{role.candidates[0].role} {role.candidates[0].score}"


def guess_role(result: ScanResult, candidates) -> HostRole:
    """Candidate roles for the directory, strongest first, with their reasons."""
    run = _Run(result, candidates)
    scored = [_candidate(role, run) for role in ROLES]
    ranked = sorted(
        (c for c in scored if c.score > 0), key=lambda c: (-c.score, ROLES.index(c.role))
    )
    drop = next((c.score for c in ranked if c.role == "drop"), 0)
    return HostRole(
        lead=_lead(ranked),
        candidates=ranked,
        victim_data_warning=drop >= LIMITS["lead"],
    )
