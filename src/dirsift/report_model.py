"""The triage report as one model that both renderers draw.

``build_report`` reads a run and turns every rule of the report into plain
blocks: paragraphs, notes, tables, code blocks, lists. The Markdown and PDF
renderers only lay those blocks out; neither decides what a sentence says.
Defanging and masking happen here, once, so the two formats cannot disagree
about what is safe to print.

Every number, name and sentence comes from the run or from the catalogue in
``report_text``, picked by a stated condition. What no rule can produce is the
analyst's to write, and it says so.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _dist_version
from pathlib import Path
from urllib.parse import urlparse

from pydantic import ValidationError

from . import detections
from . import report_text as T
from .analyze import analyze
from .classify import INTERESTING_NAMES, mismatch
from .confidence import band, short_reason
from .detections.collect import PROTOCOL_DOMAINS, SHARED_HOSTS, address_reason
from .detections.meta import Run
from .detections.options import Options
from .diagnose import explain
from .extract import SecretMask, defang, defang_text, refang
from .glue import GlueCandidate
from .models import Ioc, Kind, ScanResult
from .pivots import build_pivots

KIND_LABEL = {
    Kind.PE: "Windows executables", Kind.ELF: "ELF binaries", Kind.MACHO: "Mach-O binaries",
    Kind.SCRIPT: "Scripts", Kind.ARCHIVE: "Archives", Kind.DOCUMENT: "Documents",
    Kind.IMAGE: "Images", Kind.CONFIG: "Config", Kind.DATA: "Data and logs",
    Kind.WEB: "Web files", Kind.CERT: "Certificates and keys", Kind.UNKNOWN: "Unidentified",
}
KIND_PLURAL = {
    Kind.PE: "Windows executables", Kind.ELF: "ELF binaries", Kind.MACHO: "Mach-O binaries",
    Kind.SCRIPT: "scripts", Kind.ARCHIVE: "archives", Kind.DOCUMENT: "documents",
    Kind.IMAGE: "images", Kind.CONFIG: "configuration files", Kind.DATA: "data and log files",
    Kind.WEB: "web files", Kind.CERT: "certificate and key files",
    Kind.UNKNOWN: "unidentified files",
}
KIND_SHORT = {
    Kind.PE: "PE", Kind.ELF: "ELF", Kind.MACHO: "Mach-O", Kind.SCRIPT: "script",
    Kind.ARCHIVE: "archive", Kind.DOCUMENT: "document", Kind.IMAGE: "image",
    Kind.CONFIG: "config", Kind.DATA: "data", Kind.WEB: "web", Kind.CERT: "cert",
    Kind.UNKNOWN: "unidentified",
}
TYPE_LABEL = {
    "ipv4": "IPv4", "ipv6": "IPv6", "url": "URL", "domain": "Domain",
    "email": "Email-shaped", "secret": "Secret", "btc": "Bitcoin-shaped",
    "eth": "Ethereum-shaped", "xmr": "Monero-shaped", "mutex": "Mutex",
    "registry": "Registry key", "path": "Windows path",
}

HOME_DOT_NAMES = frozenset({
    ".bashrc", ".bash_profile", ".bash_logout", ".bash_history", ".profile", ".zshrc",
    ".zprofile", ".zsh_history", ".viminfo", ".lesshst", ".wget-hsts",
    ".sudo_as_admin_successful", ".selected_editor", ".python_history", ".mysql_history",
})
KEY_NAMES = frozenset({"authorized_keys", "known_hosts", "id_rsa", "id_dsa", "id_ecdsa",
                       "id_ed25519"})
KEY_EXTS = frozenset({"pem", "key", "pfx", "p12", "jks", "ppk"})

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
MOST_USEFUL = 10
TOP_CANDIDATES = 6
NETWORK_TYPES = ("url", "domain", "ipv4", "ipv6")
LEFT_OUT_OF_MOST_USEFUL = frozenset({
    T.NOTE_FILE_PATH, T.NOTE_BASE, "private or reserved address", "public resolver",
    "documentation address", "multicast address",
})
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_TOKEN_CHAR = re.compile(r"[A-Za-z0-9_-]")


def package_version() -> str:
    try:
        return _dist_version("dirsift")
    except PackageNotFoundError:  # pragma: no cover - running from a bare checkout
        return "0.0.0"


# Small formatting rules shared by every section


def iso(value: datetime | None) -> str:
    if value is None:
        return T.NOT_RECORDED
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def size(n: int | None) -> str:
    if n is None:
        return T.LISTING_UNREAD
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n // 1024} KiB" if n % 1024 == 0 else f"{n / 1024:.1f} KiB"
    return f"{n / 1024 / 1024:.1f} MiB"


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def code(text: str) -> str:
    """Inline code. A value that itself holds a backtick gets a longer fence."""
    if "`" in text:
        return f"`` {text} ``"
    return f"`{text}`"


def capped(items: list[str], limit: int = 12) -> str:
    """A comma list of at most ``limit`` items, then "+N more"; Appendix A has them all."""
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f", +{len(items) - limit} more"


def joined(items: list[str]) -> str:
    """'a', 'a and b', 'a, b and c'."""
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def b58check_ok(value: str) -> bool:
    """Whether a Base58 value carries a valid Base58Check checksum.

    bech32 values are a different encoding and are passed through here.
    """
    if value.lower().startswith("bc1"):
        return True
    num = 0
    for ch in value:
        if ch not in _B58:
            return False
        num = num * 58 + _B58.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(value) - len(value.lstrip("1"))) + raw
    if len(raw) != 25:
        return False
    check = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
    return check == raw[-4:]


def report_id(root_url: str, started_at: datetime) -> str:
    """``DSR-`` + start time + the first four hex of a hash of target and start."""
    started = started_at.astimezone(UTC)
    seed = root_url + "\n" + started.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:4]
    return "DSR-" + started.strftime("%Y%m%d-%H%M%S") + "-" + digest


def normalise_tlp(value: str | None) -> str | None:
    """A TLP label as the catalogue spells it, or None for an unknown one.

    Case does not matter and the ``TLP:`` prefix is optional. Whitespace inside
    the label reads as ``+``: a bare ``+`` typed into a query string arrives as
    a space, so ``?tlp=amber+strict`` means AMBER+STRICT.
    """
    if value is None:
        return None
    text = value.strip().upper()
    if text.startswith("TLP:"):
        text = text[4:].strip()
    text = re.sub(r"[\s+]+", "+", text)
    return text if text in T.TLP_DEFINITIONS else None


def tlp_rank(label: str) -> int:
    return T.TLP_ORDER.index(label)


# Blocks: what the renderers draw


class Free(str):
    """Text an analyst typed, carried through the model as the plain string it
    is. The Markdown renderer escapes it so a viewer that turns Markdown into
    HTML cannot be made to run a tag or follow a scheme from it; the PDF and the
    console already escape every field, so to them it is an ordinary string."""

    __slots__ = ()


@dataclass(frozen=True)
class Para:
    text: str


@dataclass(frozen=True)
class Note:
    text: str


@dataclass(frozen=True)
class Heading:
    text: str


@dataclass(frozen=True)
class Summary:
    text: str
    closing: str


@dataclass(frozen=True)
class Table:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    aligns: tuple[str, ...]
    kind: str = ""  # "kv", "listing", "vt" or ""
    keep: bool = False


@dataclass(frozen=True)
class Pre:
    lines: tuple[str, ...]
    title: str | None = None


@dataclass(frozen=True)
class Bullets:
    items: tuple[str, ...]
    ordered: bool = False


@dataclass(frozen=True)
class AssessmentEmpty:
    lead: str
    fields: str


@dataclass(frozen=True)
class AssessmentFull:
    assessment: str
    definition: str
    confidence: str
    priority: str
    author: str
    status: str
    rows: tuple[tuple[str, str], ...]
    references: tuple[str, ...] = ()


@dataclass
class Section:
    key: str
    number: str
    title: str
    label: str  # O, D, A, R
    blocks: list = field(default_factory=list)
    appendix: bool = False

    @property
    def reader_label(self) -> str:
        return T.LABELS[self.label]


@dataclass(frozen=True)
class Report:
    report_id: str
    version: str
    status: str
    status_text: str
    generated_at: datetime
    dirsift_version: str
    run_name: str | None
    run_sha256: str
    tlp: str
    author: str | None
    target: str
    started_at: datetime
    sections: tuple[Section, ...]
    doc_control: tuple[tuple[str, str], ...]
    iocs_defanged: frozenset[str] = frozenset()
    listing_paths: frozenset[str] = frozenset()
    summary_words: int = 0

    @property
    def generator(self) -> str:
        return f"DirSift {self.dirsift_version}"

    @property
    def tlp_label(self) -> str:
        return "TLP:" + self.tlp

    @property
    def tlp_definition(self) -> str:
        return T.TLP_DEFINITIONS[self.tlp]

    @property
    def review_line(self) -> str:
        if self.status == "Final":
            return T.REVIEW_BY.format(author=self.author or "")
        return T.REVIEW_NOT_REVIEWED


@dataclass(frozen=True)
class ReportOptions:
    """What the caller knows about the run beyond the run itself.

    ``run_name`` is None for a scan that was never saved. ``asn_recorded`` says
    whether the run file itself carried its network table, as opposed to one
    placed from this machine's table when the report was built.
    """

    run_name: str | None = None
    tlp: str = T.DEFAULT_TLP
    author: str | None = None
    version: str | None = None
    asn_recorded: bool = False


# Loading a run the way the report needs it


@dataclass(frozen=True)
class LoadedRun:
    result: ScanResult
    candidates: list
    run_sha256: str
    asn_recorded: bool
    name: str | None
    siblings: tuple[tuple[str, ScanResult], ...]


def sibling_runs(folder: Path, root_url: str) -> tuple[tuple[str, ScanResult], ...]:
    """Every run in ``folder`` of the same root, by start time.

    A file that is not a run is skipped. The glob is not recursive, so the
    assessments folder beside the runs never counts.
    """
    out = []
    for path in sorted(folder.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict) or payload.get("root_url") != root_url:
            continue
        try:
            other = ScanResult.model_validate(payload)
        except ValidationError:
            continue
        out.append((path.stem, other))
    out.sort(key=lambda item: item[1].started_at)
    return tuple(out)


def load_run_for_report(path: Path, *, asn_table=None) -> LoadedRun:
    """A saved run, analysed, with the facts the report states about the file.

    The SHA256 is of the bytes on disk as they are read, line endings included.
    Raises OSError, ValueError or ValidationError as reading and parsing do.
    """
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    recorded = bool(payload.get("asn_source")) if isinstance(payload, dict) else False
    result = ScanResult.model_validate(payload)
    result, candidates = analyze(result, asn_table=asn_table)
    return LoadedRun(
        result=result,
        candidates=candidates,
        run_sha256=hashlib.sha256(raw).hexdigest(),
        asn_recorded=recorded,
        name=path.stem,
        siblings=sibling_runs(path.parent, result.root_url),
    )


def unsaved_sha256(result: ScanResult) -> str:
    """For a scan that was not saved: the hash of the run as it would be written."""
    return hashlib.sha256(result.model_dump_json(indent=2).encode("utf-8")).hexdigest()


# The builder


class _Builder:
    def __init__(
        self,
        result: ScanResult,
        candidates: list[GlueCandidate],
        options: ReportOptions,
        assessment: dict,
        generated_at: datetime,
        run_sha256: str,
        siblings: tuple[tuple[str, ScanResult], ...],
    ) -> None:
        self.r = result
        self.root = result.root_url
        self.all_candidates = list(candidates)
        self.cands = [c for c in self.all_candidates if c.score > 0][:TOP_CANDIDATES]
        self.options = options
        self.name = options.run_name
        self.assessment = assessment
        self.generated_at = generated_at
        self.run_sha = run_sha256
        self.version = options.version or package_version()
        self.tlp = options.tlp
        self.mask = SecretMask(result.iocs)
        self.by_url = {e.url: e for e in result.entries}
        self.host = (urlparse(self.root).hostname or "").lower()
        self.target_addr = result.target_ip or ""
        own = self.name or T.RUN_NOT_SAVED
        others = [(n, o) for n, o in siblings if n != self.name]
        others.append((own, result))
        others.sort(key=lambda item: item[1].started_at)
        self.others = others
        self._notes: dict[int, list[str]] = {}

    # helpers

    def rel(self, url: str) -> str:
        """A path under the root as it is; anything else is a URL, and is defanged."""
        return url[len(self.root):] if url.startswith(self.root) else defang(url)

    def network(self) -> str:
        if not self.r.target_asn:
            return T.NOT_PLACED
        return f"AS{self.r.target_asn} {self.r.target_as_name}, {self.r.target_country}"

    def network_source(self) -> str:
        when = T.NETWORK_RECORDED if self.options.asn_recorded else T.NETWORK_PLACED_NOW
        return f"{code(self.r.asn_source or '')}, dated {self.r.asn_stamp}, {when}"

    # indicator rules

    def ioc_host(self, ioc: Ioc) -> str:
        if ioc.ioc_type == "ipv4":
            return ioc.value.split(":", 1)[0]
        if ioc.ioc_type == "url":
            try:
                return (urlparse(ioc.value).hostname or "").lower()
            except ValueError:
                return ""
        if ioc.ioc_type == "domain":
            return ioc.value.lower()
        if ioc.ioc_type == "email":
            return ioc.value.rpartition("@")[2].lower()
        return ""

    def is_target(self, ioc: Ioc) -> bool:
        h = self.ioc_host(ioc)
        return bool(h) and h in {self.host, self.target_addr}

    def from_logs_only(self, ioc: Ioc) -> bool:
        srcs = ioc.sources or [ioc.source_url]
        return all(self.by_url.get(u) is not None and self.by_url[u].ext == "log" for u in srcs)

    def base_address(self, ioc: Ioc) -> bool:
        if ioc.ioc_type != "ipv4":
            return False
        try:
            packed = ipaddress.ip_address(self.ioc_host(ioc)).packed
        except ValueError:
            return False
        return packed[-2:] == b"\x00\x00"

    def in_file_path(self, ioc: Ioc) -> bool:
        if ioc.ioc_type != "domain" or not ioc.context:
            return False
        text = refang(ioc.context)
        return re.search("(?<![/:])/" + re.escape(ioc.value) + "/", text, re.I) is not None

    def shared_suffix(self, ioc: Ioc) -> str | None:
        if ioc.ioc_type not in ("domain", "url"):
            return None
        h = self.ioc_host(ioc)
        if not h:
            return None
        return next((s for s in SHARED_HOSTS if h == s or h.endswith("." + s)), None)

    def ip_reason(self, ioc: Ioc) -> str | None:
        if ioc.ioc_type != "ipv4":
            return None
        try:
            return address_reason(self.ioc_host(ioc), Options())
        except ValueError:
            return None

    def token_fragment(self, ioc: Ioc) -> bool:
        ctx = ioc.context or ""
        i = ctx.find(ioc.value)
        if i < 0:
            return False
        before = ctx[i - 1] if i > 0 else ""
        end = i + len(ioc.value)
        after = ctx[end] if end < len(ctx) else ""
        return bool(before and after and _TOKEN_CHAR.match(before) and _TOKEN_CHAR.match(after))

    def wallet_masked(self, ioc: Ioc) -> bool:
        return ioc.ioc_type == "btc" and (not b58check_ok(ioc.value) or self.token_fragment(ioc))

    def shown(self, ioc: Ioc) -> str:
        if self.wallet_masked(ioc):
            digest = hashlib.sha256(ioc.value.encode()).hexdigest()[:12]
            return f"bitcoin_shaped  {len(ioc.value)} chars  sha256:{digest}"
        shown = self.mask.indicator(ioc)
        if ioc.ioc_type == "ipv6" and "[:]" not in shown:
            # an IPv6 address has no dot to bracket; its colons are bracketed instead
            shown = defang_text(shown)
        return shown

    def notes(self, ioc: Ioc) -> list[str]:
        cached = self._notes.get(id(ioc))
        if cached is not None:
            return cached
        out: list[str] = []
        port = None
        if ioc.ioc_type == "ipv4" and ":" in ioc.value:
            port = ioc.value.split(":", 1)[1]
        elif ioc.ioc_type == "url":
            try:
                port = urlparse(ioc.value).port
            except ValueError:
                port = None
        base = self.base_address(ioc)
        if self.is_target(ioc):
            out.append(T.NOTE_TARGET)
        if port:
            out.append(T.NOTE_PORT.format(port=port))
        if base:
            out.append(T.NOTE_BASE)
        reason = self.ip_reason(ioc)
        if reason and not base:
            out.append(reason)
        if self.in_file_path(ioc):
            out.append(T.NOTE_FILE_PATH)
        if self.shared_suffix(ioc):
            out.append(T.NOTE_SHARED)
        if ioc.ioc_type == "email":
            h = self.ioc_host(ioc)
            if any(h == d or h.endswith("." + d) for d in PROTOCOL_DOMAINS):
                out.append(T.NOTE_PROTOCOL)
        if (ioc.ioc_type in NETWORK_TYPES and self.from_logs_only(ioc)
                and not self.is_target(ioc) and not base):
            out.append(T.NOTE_FROM_LOGS)
        if ioc.ioc_type == "secret":
            out.append(T.NOTE_MASKED)
        if ioc.ioc_type == "btc":
            if not b58check_ok(ioc.value):
                out.append(T.NOTE_B58)
            if self.token_fragment(ioc):
                out.append(T.NOTE_FRAGMENT)
            if self.wallet_masked(ioc):
                out.append(T.NOTE_MASKED)
        self._notes[id(ioc)] = out
        return out

    def source_class(self, url: str) -> int:
        e = self.by_url.get(url)
        if e is None:
            return 3
        if e.kind in (Kind.SCRIPT, Kind.WEB, Kind.CONFIG):
            return 0
        if e.kind is Kind.DATA and e.ext != "log":
            return 1
        if e.kind is Kind.DATA:
            return 2
        return 3

    def confidence(self, ioc: Ioc) -> str:
        """The band and score: how sure the run is the indicator is a live part of the kit."""
        if ioc.confidence is None:
            return "-"
        return f"{band(ioc.confidence)} {ioc.confidence}"

    def confidence_reasons(self, ioc: Ioc) -> str:
        """A low score's reasons in short, since a low score is the one a reader will
        want to argue with; high and medium stay bare."""
        if ioc.confidence is None or band(ioc.confidence) != "low":
            return ""
        return defang_text(", ".join(short_reason(r) for r in ioc.confidence_reasons))

    def found_in(self, ioc: Ioc) -> str:
        srcs = ioc.sources or [ioc.source_url]
        first = code(self.rel(srcs[0]))
        return first + (f" +{len(srcs) - 1} more" if len(srcs) > 1 else "")

    def net_cell(self, ioc: Ioc) -> str:
        if ioc.asn:
            return f"AS{ioc.asn}, {ioc.country}" if ioc.country else f"AS{ioc.asn}"
        if ioc.ioc_type == "domain" or (ioc.ioc_type == "url" and not self._ip_host(ioc)):
            return T.NET_NOT_RESOLVED
        return T.NET_NOT_IN_TABLE

    def _ip_host(self, ioc: Ioc) -> bool:
        try:
            ipaddress.ip_address(self.ioc_host(ioc))
            return True
        except ValueError:
            return False

    # sections

    def build(self) -> list[Section]:
        r = self.r
        files = r.files
        self.read = [e for e in files if e.fetched_bytes is not None]
        self.hashed = [e for e in files if e.sha256]
        self.cut = [e for e in files if e.truncated]
        self.unread = [e for e in files if e.fetched_bytes is None]
        self.verdicts = [e for e in files if e.verdict]
        self.err_by_url: dict[str, object] = {}
        for err in r.errors:
            self.err_by_url.setdefault(err.url, err)
        self.signals = self.signal_rows()
        return [
            self.s_summary(), self.s_facts(), self.s_assessment(), self.s_limits(),
            self.s_hosting(), self.s_contents(), self.s_notable(), self.s_indicators(),
            self.s_hashes(), self.s_detections(), self.s_recommendations(), self.s_method(),
            self.a_listing(), self.a_indicators(), self.a_changelog(),
        ]

    def kinds_sorted(self):
        by = self.r.by_kind()
        return sorted(by.items(), key=lambda kv: (-len(kv[1]), KIND_LABEL[kv[0]]))

    def unread_detail(self) -> str:
        details = Counter(
            _detail(self.err_by_url[e.url].detail) for e in self.unread
            if e.url in self.err_by_url
        )
        return ", ".join(details) if details else T.NO_ERROR_RECORDED

    def later_failed(self):
        """Later runs of this root that could not list it, in start order."""
        return [(n, o) for n, o in self.others
                if o.started_at > self.r.started_at and not o.entries]

    def summary_names(self) -> list[str]:
        tally: Counter = Counter()
        for c in self.cands:
            for ref in dict.fromkeys(c.references):
                tally[ref] += 1
        return [n for n, _ in sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))][:4]

    def s_summary(self) -> Section:
        r = self.r
        start = r.started_at.astimezone(UTC)
        kinds = [
            f"{len(v)} {KIND_PLURAL[k] if len(v) != 1 else KIND_PLURAL[k].rstrip('s')}"
            for k, v in self.kinds_sorted()
        ]
        target = code(defang(self.root))
        if r.entries or not r.errors:
            s = [T.SUMMARY_LISTED.format(
                date=f"{start:%Y-%m-%d}", time=f"{start:%H:%M}", target=target,
                network=self.network(), server=code(r.server or "not advertised"))]
        else:
            s = [T.SUMMARY_NOT_LISTED.format(
                date=f"{start:%Y-%m-%d}", time=f"{start:%H:%M}", target=target,
                network=self.network())]
        if kinds:
            s.append(T.SUMMARY_HELD.format(files=plural(len(r.files), "file"),
                                           dirs=plural(len(r.dirs), "directory", "directories"),
                                           kinds=joined(kinds)))
        else:
            s.append(T.SUMMARY_HELD_EMPTY)
        names = self.summary_names()
        if names:
            s.append(T.SUMMARY_NAMES.format(names=joined([code(n) for n in names])))
        kinds_of_signal = list(dict.fromkeys(sig for _, sig, _ in self.signals))
        if kinds_of_signal:
            s.append(T.SUMMARY_SIGNALS.format(signals="; ".join(kinds_of_signal)))
        s.append(T.SUMMARY_READ.format(read=len(self.read), hashed=len(self.hashed),
                                       iocs=len(r.iocs)))
        if self.cands:
            top = self.cands[0]
            s.append(T.SUMMARY_TOP.format(name=code(self.rel(top.entry.url)),
                                          refs=plural(len(top.references), "other file")))
        if self.verdicts:
            no = sum(1 for e in self.verdicts if not e.verdict.found)
            yes = len(self.verdicts) - no
            if len(self.verdicts) == 1:
                s.append(T.SUMMARY_VT_ONE_NONE if no else T.SUMMARY_VT_ONE_FOUND)
            else:
                parts = []
                if no:
                    parts.append(f"{no} returned no record")
                if yes:
                    parts.append(f"{yes} returned a record")
                s.append(T.SUMMARY_VT_MANY.format(n=len(self.verdicts), parts=", ".join(parts)))
        for _, other in self.later_failed():
            detail = other.errors[0].detail if other.errors else T.NO_ANSWER_RECORDED
            s.append(T.SUMMARY_LATER.format(date=f"{other.started_at:%Y-%m-%d}",
                                            detail=_detail(detail)))
        text = " ".join(s)
        self.summary_words = len(re.findall(r"\S+", text))
        sec = Section("summary", "1", "Executive summary", "O")
        sec.blocks = [Summary(text, T.SUMMARY_CLOSING)]
        return sec

    def ceiling(self) -> str:
        peek = self.r.options.get("peek_bytes")
        return size(peek) if isinstance(peek, int) else T.NOT_RECORDED

    def s_facts(self) -> Section:
        r = self.r
        top = self.cands[0] if self.cands else None
        type_counts = Counter(i.ioc_type for i in r.iocs)

        def type_name(t: str) -> str:
            label = TYPE_LABEL.get(t, t)
            if t in ("ipv4", "ipv6", "url"):
                return label
            return label.lower().replace("bitcoin", "Bitcoin")

        ind = ", ".join(f"{type_counts[t]} {type_name(t)}"
                        for t in sorted(type_counts, key=lambda t: -type_counts[t]))
        vt = T.FACTS_VT_NONE
        if self.verdicts:
            vt = "; ".join(
                f"{code(self.rel(e.url))}: "
                + (T.FACTS_VT_NO_RECORD if not e.verdict.found else T.FACTS_VT_RECORD.format(
                    hits=e.verdict.malicious, total=e.verdict.total))
                + f" ({iso(e.verdict.checked_at)})" for e in self.verdicts)
        listed = [o for _, o in self.others if o.entries]
        last = max(listed, key=lambda o: o.started_at) if listed else r
        parsed = urlparse(self.root)
        scheme = parsed.scheme
        try:
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError:
            port = 443 if scheme == "https" else 80
        packs = self.pack_rows()
        made = [p[0] for p in packs if not p[1].startswith(T.YARA_NOT_GENERATED)]
        notmade = [p[0] for p in packs if p[1].startswith(T.YARA_NOT_GENERATED)]
        if made:
            pack_text = ", ".join(made) + (
                ". " + T.FACTS_PACKS_NOT_MADE.format(packs=", ".join(notmade)) if notmade else "")
        else:
            pack_text = T.FACTS_PACKS_NONE
        if any(e.size for e in r.files):
            total = size(sum(e.size or 0 for e in r.files))
        else:
            total = T.FACTS_NO_SIZE.format(
                size=size(sum(e.fetched_bytes or 0 for e in self.read)), files=len(self.read))
        if self.unread:
            hashed = T.FACTS_HASHED.format(hashed=len(self.hashed), cut=len(self.cut),
                                           ceiling=self.ceiling(), unread=len(self.unread),
                                           detail=self.unread_detail())
        else:
            hashed = (f"{len(self.hashed)} files read whole; {len(self.cut)} cut at the "
                      f"{self.ceiling()} ceiling; 0 not read")
        rows = [
            ("Target", code(defang(self.root))),
            ("Address", code(defang(self.target_addr)) if self.target_addr else T.NOT_RECORDED),
            ("Network", self.network() + " (note 1)"),
            ("Server", f"{code(r.server or 'not advertised')}, index flavour "
                       f"{code(r.listing_flavor or 'unknown')}, port {port}, "
                       f"{'TLS' if scheme == 'https' else 'no TLS'}"),
            ("Page title", defang_text(r.title) if r.title else "none"),
            ("Files and directories", f"{len(r.files)} files, {len(r.dirs)} directories"),
            ("Total size", total),
            ("Scanned", code(iso(r.started_at)) + " to " + code(iso(r.finished_at))),
            ("Last listed by DirSift", (code(iso(last.finished_at)) if listed
                                        else T.NOT_RECORDED) + " (note 2)"),
            ("Top entry point candidate",
             T.FACTS_TOP.format(name=code(self.rel(top.entry.url)), score=f"{top.score:.1f}")
             if top else "none"),
            ("Hashed", hashed),
            ("Indicator values", T.FACTS_INDICATORS.format(counts=ind) if ind
             else T.FACTS_NO_INDICATORS),
            ("VirusTotal", vt),
            ("Detection packs", pack_text),
        ]
        if r.asn_source:
            note1 = T.NOTE_NETWORK.format(
                table=code(r.asn_source), stamp=r.asn_stamp,
                when=T.NETWORK_RECORDED if self.options.asn_recorded else T.NETWORK_PLACED_NOW)
        else:
            note1 = T.NOTE_NETWORK_NONE
        failed = [
            T.NOTE_LATER_RUN.format(name=code(n), date=f"{o.started_at:%Y-%m-%d}",
                                    detail=_detail(o.errors[0].detail))
            for n, o in self.later_failed() if o.errors
        ]
        note2 = T.NOTE_LATER.format(runs="; ".join(failed)) if failed else T.NOTE_NO_LATER
        sec = Section("facts", "2", "Key facts", "O")
        sec.blocks = [_table(["Fact", "Value"], rows, kind="kv", keep=True),
                      Note(note1 + " " + note2 + ".")]
        return sec

    def s_assessment(self) -> Section:
        a = self.assessment
        sec = Section("assessment", "3", "Analyst assessment", "A")
        if not a.get("assessment"):
            sec.blocks = [AssessmentEmpty(
                T.ASSESSMENT_EMPTY, "Open fields: " + ", ".join(T.ASSESSMENT_OPEN_FIELDS) + ".")]
            return sec
        value = a["assessment"]
        sec.blocks = [AssessmentFull(
            assessment=value,
            definition=T.ASSESSMENT_DEFINITIONS[value],
            confidence=a.get("confidence") or T.NOT_ASSESSED,
            priority=a.get("priority") or T.NOT_ASSESSED,
            author=self.options.author or a.get("author") or "Not set",
            status=a.get("status") or "Preliminary",
            rows=tuple(self.assessment_rows(a)),
            references=tuple(Free(defang_text(x)) for x in a.get("references") or []),
        )]
        return sec

    def assessment_rows(self, a: dict) -> list[tuple[str, str]]:
        value = a["assessment"]
        rows = [
            ("Assessment", f"{value}: {T.ASSESSMENT_DEFINITIONS[value]}"),
            ("Confidence", a.get("confidence") or T.NOT_ASSESSED),
            ("Priority for follow-up", a.get("priority") or T.NOT_ASSESSED),
            ("Author", Free(defang_text(self.options.author or a.get("author") or "Not set"))),
            ("Bottom line", Free(defang_text(a.get("bottom_line") or T.NOT_ASSESSED))),
            ("Rationale", Free(defang_text(a.get("rationale") or T.ASSESSMENT_NO_RATIONALE))),
            ("Attribution",
             Free(defang_text(a.get("attribution") or T.ASSESSMENT_NO_ATTRIBUTION))),
        ]
        attack = a.get("attack") or []
        if attack:
            ver = a.get("attack_version") or T.ATTACK_VERSION_NOT_STATED
            ver_text = ver if ver == T.ATTACK_VERSION_NOT_STATED else f"version {ver}"
            rows.append(("ATT&CK", Free(defang_text(ver_text + ": " + "; ".join(
                f"{t.get('tactic', '')}: {t.get('technique', '')} ({t.get('id', '')}), "
                f"evidence: {t.get('evidence', '')}" for t in attack)))))
        else:
            rows.append(("ATT&CK techniques", T.ATTACK_NOT_MAPPED))
        return rows

    def s_limits(self) -> Section:
        r = self.r
        items = [T.LIMIT_EXECUTED]
        if self.cut or self.unread:
            parts = []
            if self.cut:
                parts.append(T.LIMIT_CUT.format(files=plural(len(self.cut), "file"),
                                                ceiling=self.ceiling()))
            if self.unread:
                parts.append(T.LIMIT_UNREAD.format(files=plural(len(self.unread), "file"),
                                                   detail=self.unread_detail()))
            text = " and ".join(parts)
            items.append(text[0].upper() + text[1:] + ".")
        log_only = self.log_only_addresses()
        if log_only:
            items.append(T.LIMIT_LOGS.format(n=len(log_only)))
        if any(i.ioc_type in ("domain", "url") for i in r.iocs):
            items.append(T.LIMIT_RESOLVED)
        if any(i.ioc_type == "secret" for i in r.iocs):
            items.append(T.LIMIT_SECRETS)
        if r.target_asn:
            items.append(T.LIMIT_OPERATOR)
        if self.verdicts:
            lookups = ("One VirusTotal lookup" if len(self.verdicts) == 1
                       else f"{len(self.verdicts)} VirusTotal lookups")
            found = ("no record" if all(not e.verdict.found for e in self.verdicts)
                     else "records")
            items.append(T.LIMIT_VT.format(lookups=lookups, found=found))
        else:
            items.append(T.LIMIT_NO_VT)
        listed = [o for _, o in self.others if o.entries] or [r]
        start = min(o.started_at for o in listed)
        end = max((o.finished_at or o.started_at) for o in listed)
        items.append(T.LIMIT_WINDOW.format(start=iso(start), end=iso(end)))
        ruled = {x.get("explanation"): x for x in self.assessment.get("alternatives") or []
                 if isinstance(x, dict)}
        rows = []
        for alt in T.ALTERNATIVES:
            hit = ruled.get(alt)
            if hit and hit.get("status") == T.RULED_OUT:
                rows.append((alt, Free("Ruled out: " + defang_text(hit.get("reason") or ""))))
            else:
                rows.append((alt, T.NOT_RULED_OUT))
        for extra in self.assessment.get("limits_added") or []:
            items.append(defang_text(str(extra)))
        sec = Section("limits", "4", "Limits and alternatives", "D")
        sec.blocks = [Heading("4.1 What this evidence does not show"), Bullets(tuple(items)),
                      Heading("4.2 Alternative explanations"), Para(T.ALTERNATIVES_LEAD),
                      _table(["Explanation", "Status"], rows)]
        return sec

    def log_only_addresses(self) -> set[str]:
        out = set()
        for i in self.r.iocs:
            if i.ioc_type == "ipv4" and T.NOTE_FROM_LOGS in self.notes(i) \
                    and not self.ip_reason(i):
                out.add(self.ioc_host(i))
        return out

    def s_hosting(self) -> Section:
        rows = []
        explained: OrderedDict[str, str] = OrderedDict()
        for name, o in self.others:
            requests = plural(o.requests_made, "request")
            if o.entries:
                res = T.SEEN_LISTED.format(files=len(o.files), dirs=len(o.dirs),
                                           requests=requests)
            else:
                detail = o.errors[0].detail if o.errors else T.NO_ANSWER_RECORDED
                res = T.SEEN_NOT_LISTED.format(detail=_detail(detail), requests=requests)
                if o.errors and explain(detail):
                    explained[detail] = explain(detail)
            rows.append((code(name), code(iso(o.started_at)), code(iso(o.finished_at)), res))
        found_via = self.assessment.get("found_via")
        sec = Section("hosting", "5", "Hosting and exposure", "O")
        sec.blocks = [
            Para(Free("**Found via:** " + defang_text(found_via)) if found_via
                 else "**Found via:** " + T.FOUND_VIA_NOT_RECORDED),
            Heading("Seen by DirSift"),
            _table(["Run", "Started (UTC)", "Finished (UTC)", "Result"], rows),
        ]
        for detail, text in explained.items():
            sec.blocks.append(Note(f"{_detail(detail)}: {text}"))
        sec.blocks.append(Note(T.FIRST_SEEN))
        return sec

    def s_contents(self) -> Section:
        sec = Section("contents", "6", "Directory contents", "O")
        if not self.r.files:
            blocks: list = [Para(T.NOTHING_LISTED)]
            if self.r.dirs:
                blocks.append(Pre(tuple(self.tree())))
        else:
            rows = []
            for kind, entries in self.kinds_sorted():
                ex = ", ".join(code(e.name) for e in entries[:3]) + (
                    f", +{len(entries) - 3} more" if len(entries) > 3 else "")
                rows.append((KIND_LABEL[kind], str(len(entries)),
                             size(sum(e.fetched_bytes or 0 for e in entries)), ex))
            advertised = any(e.size for e in self.r.files)
            blocks = [_table(["Type", "Files", "Read" if not advertised else "Size", "Examples"],
                             rows, aligns=["l", "r", "r", "l"])]
            if not advertised:
                blocks.append(Note(T.NO_SIZES))
            blocks.append(Pre(tuple(self.tree())))
        blocks.append(Heading("6.1 Version families"))
        if self.r.clusters:
            frows = []
            gap = False
            for c in self.r.clusters:
                frows.append((code(c.label), ", ".join(c.variants),
                              ", ".join(code(m) for m in c.members)))
                if c.variant_kind == "numeric":
                    nums = sorted(int(v) for v in c.variants if v.isdigit())
                    if nums and nums[-1] - nums[0] + 1 > len(nums):
                        gap = True
            blocks.append(_table(["Family", "Variants", "Members"], frows))
            if gap:
                blocks.append(Note(T.FAMILY_GAP))
        else:
            blocks.append(Para(T.NO_FAMILIES))
        sec.blocks = blocks
        return sec

    def tree(self) -> list[str]:
        dirs: dict[str, list] = {"/": []}
        for d in self.r.dirs:
            dirs.setdefault("/" + self.rel(d.url).rstrip("/") + "/", [])
        for e in self.r.files:
            path = "/" + self.rel(e.url)
            parent = path.rpartition("/")[0] + "/"
            dirs.setdefault(parent, []).append(e)
        lines: list[str] = []
        names = sorted(dirs)

        def describe(entries) -> str:
            if not entries:
                return "0 files"
            kinds = Counter(e.kind for e in entries)
            ordered = sorted(kinds.items(), key=lambda kv: (-kv[1], KIND_SHORT[kv[0]]))
            text = plural(len(entries), "file")
            if len(entries) <= 3:
                return text + "  " + ", ".join(e.name for e in entries)
            return text + "  (" + ", ".join(f"{n} {KIND_SHORT[k]}" for k, n in ordered) + ")"

        lines.append(f"{'/':<22}{describe(dirs['/'])}")
        children = [n for n in names if n != "/"]

        def walk(prefix: str, parent: str) -> None:
            kids = [n for n in children if n.rstrip("/").rpartition("/")[0] + "/" == parent]
            for i, kid in enumerate(kids):
                last = i == len(kids) - 1
                label = kid.rstrip("/").rpartition("/")[2] + "/"
                head = prefix + ("└── " if last else "├── ") + label
                lines.append(f"{head:<22}{describe(dirs[kid])}")
                walk(prefix + ("    " if last else "│   "), kid)

        walk("", "/")
        return lines

    def signal_rows(self):
        rows = []  # (files, signal, kind)
        files = self.r.files
        for e in files:
            n = mismatch(e)
            if n:
                rows.append(([e], T.SIGNAL_MISMATCH.format(note=n), "mismatch"))
        keys = [e for e in files
                if e.kind is Kind.CERT or e.name in KEY_NAMES or e.ext in KEY_EXTS]
        if keys:
            rows.append((keys, T.SIGNAL_KEY, "key"))
        by_parent: dict = {}
        for e in files:
            if e.name in HOME_DOT_NAMES:
                by_parent.setdefault(e.parent_url, []).append(e)
        for group in by_parent.values():
            if len(group) >= 2:
                rows.append((group, T.SIGNAL_HOME, "home"))
        named = [e for e in files if e.name.lower() in INTERESTING_NAMES]
        if named:
            rows.append((named, T.SIGNAL_NAMES, "names"))
        noext = [e for e in files if e.kind in (Kind.PE, Kind.ELF, Kind.MACHO) and not e.ext]
        if noext:
            rows.append((noext, T.SIGNAL_NOEXT, "noext"))
        same: dict = {}
        for e in files:
            if e.sha256 and e.sha256 != EMPTY_SHA256 and not e.truncated:
                same.setdefault(e.sha256, []).append(e)
        for group in same.values():
            if len(group) >= 2:
                rows.append((group, T.SIGNAL_SAME.format(n=len(group)), "same"))
        return rows

    def s_notable(self) -> Section:
        blocks: list = []
        if self.cands:
            blocks.append(Para(T.CANDIDATES_LEAD))
            rows = []
            for i, c in enumerate(self.cands, 1):
                refs = list(dict.fromkeys(c.references))
                names = ", ".join(code(n) for n in refs[:3]) + (
                    f", +{len(refs) - 3} more" if len(refs) > 3 else "")
                rows.append((str(i), code(self.rel(c.entry.url)), f"{c.score:.1f}",
                             "; ".join(c.reasons), names or "none"))
            blocks.append(_table(["Rank", "File", "Score", "Why", "Names"], rows,
                                 aligns=["r", "l", "r", "l", "l"]))
        else:
            blocks.append(Para(T.NO_CANDIDATES))
        blocks.append(Heading("Worth a second look"))
        srows = [(capped([code(self.rel(e.url)) for e in files]), sig)
                 for files, sig, kind in self.signals if kind != "mismatch"]
        if srows:
            blocks.append(_table(["Files", "Signal"], srows))
        mism = [(f, s) for f, s, k in self.signals if k == "mismatch"]
        if mism:
            blocks.append(_table(["File", "Type mismatch"],
                                 [(code(self.rel(f[0].url)), s) for f, s in mism]))
        elif srows:
            blocks.append(Para(T.NO_MISMATCHES))
        else:
            blocks.append(Para(T.NO_SIGNALS + " " + T.NO_MISMATCHES))
        sec = Section("notable", "7", "Notable files and entry point candidates", "D")
        sec.blocks = blocks
        return sec

    def s_indicators(self) -> Section:
        r = self.r
        sec = Section("indicators", "8", "Indicators", "D")
        if not r.iocs:
            sec.blocks = [Para(T.NO_INDICATORS)]
            return sec
        by_type: OrderedDict[str, list] = OrderedDict()
        for i in r.iocs:
            by_type.setdefault(i.ioc_type, []).append(i)
        rows = []
        unit_lines = []
        for t, items in by_type.items():
            src: Counter = Counter()
            for i in items:
                for u in (i.sources or [i.source_url]):
                    src[self.rel(u)] += 1
            top = ", ".join(f"{code(p)} ({n})" for p, n in
                            sorted(src.items(), key=lambda kv: (-kv[1], kv[0]))[:3])
            notes: list[str] = []
            if t == "ipv4":
                addrs = {self.ioc_host(i) for i in items}
                ported = sum(1 for i in items if ":" in i.value)
                cats: Counter = Counter()
                for i in items:
                    n = self.notes(i)
                    reason = self.ip_reason(i)
                    if T.NOTE_TARGET in n:
                        cats[T.NOTE_TARGET] += 1
                    elif T.NOTE_BASE in n:
                        cats[T.NOTE_BASE] += 1
                    elif reason:
                        cats[reason] += 1
                    elif T.NOTE_FROM_LOGS in n:
                        cats[T.CAT_FROM_LOGS] += 1
                    else:
                        cats["other"] += 1
                notes.append(T.TYPE_IPV4_NOTE.format(distinct=len(addrs), ported=ported))
                notes.append("; ".join(f"{k}: {v}" for k, v in
                                       sorted(cats.items(), key=lambda kv: -kv[1])
                                       if k != "other"))
                kept = detections.collect(r, Options()).counts().get("ipv4", 0)
                unit_lines.append(T.IPV4_UNITS.format(values=len(items), distinct=len(addrs),
                                                      ported=ported, kept=kept))
            elif t in ("domain", "url"):
                sh = [i for i in items if self.shared_suffix(i)]
                if sh:
                    suff = sorted({self.shared_suffix(i) for i in sh})
                    notes.append(T.TYPE_SHARED_NOTE.format(
                        n=len(sh), suffixes=", ".join(code(defang(s)) for s in suff)))
                fp = [i for i in items if self.in_file_path(i)]
                if fp:
                    notes.append(T.TYPE_PATH_NOTE.format(
                        n=len(fp), values=capped([code(i.defanged) for i in fp])))
            elif t == "email":
                pr = [i for i in items if T.NOTE_PROTOCOL in self.notes(i)]
                if pr:
                    doms = sorted({self.ioc_host(i) for i in pr})
                    notes.append(T.TYPE_PROTOCOL_NOTE.format(
                        n=len(pr), domains=", ".join(code("@" + defang(d)) for d in doms)))
            elif t == "secret":
                notes.append(T.TYPE_SECRET_NOTE)
            elif t == "btc":
                for i in items:
                    notes.append(", ".join(self.notes(i)))
            rows.append((TYPE_LABEL.get(t, t), str(len(items)), top,
                         "; ".join(n for n in notes if n) or "none"))
        useful = self.most_useful()
        urows = [(TYPE_LABEL[i.ioc_type], code(self.shown(i)), self.confidence(i),
                  self.net_cell(i), self.found_in(i), "; ".join(self.notes(i)) or "none")
                 for i in useful]
        sec.blocks = [
            Para(T.INDICATORS_LEAD),
            _table(["Type", "Values", "Mostly from", "Notes"], rows,
                   aligns=["l", "r", "l", "l"]),
            *[Note(x) for x in unit_lines],
            Heading("Most useful first"),
            Note(T.MOST_USEFUL_NOTE),
        ]
        if urows:
            sec.blocks.append(_table(["Type", "Value", "Confidence", "Network", "Found in",
                                      "Notes"], urows))
        else:
            sec.blocks.append(Para(T.MOST_USEFUL_NONE))
        return sec

    def most_useful(self) -> list[Ioc]:
        order = {t: n for n, t in enumerate(NETWORK_TYPES)}
        pool = []
        for i in self.r.iocs:
            if i.ioc_type not in order:
                continue
            if LEFT_OUT_OF_MOST_USEFUL & set(self.notes(i)):
                continue
            srcs = i.sources or [i.source_url]
            key = (0 if self.is_target(i) else 1, min(self.source_class(u) for u in srcs),
                   -len(srcs), order[i.ioc_type], i.value.lower())
            pool.append((key, i))
        pool.sort(key=lambda kv: kv[0])
        return [i for _, i in pool[:MOST_USEFUL]]

    def s_hashes(self) -> Section:
        blocks: list = []
        if self.hashed:
            nonempty = {e.sha256 for e in self.hashed if e.sha256 != EMPTY_SHA256}
            nonempty_files = [e for e in self.hashed if e.sha256 != EMPTY_SHA256]
            empty = [e for e in self.hashed if e.sha256 == EMPTY_SHA256]
            empty_text = T.HASHES_EMPTY.format(
                short=f"{EMPTY_SHA256[:8]}...{EMPTY_SHA256[-4:]}",
                files=plural(len(empty), "file")) if empty else ""
            text = T.HASHES_LEAD.format(hashed=len(self.hashed), distinct=len(nonempty),
                                        files=len(nonempty_files), empty=empty_text)
            if any(k == "same" for _, _, k in self.signals):
                text += T.HASHES_SAME
            blocks.append(Para(text))
        else:
            blocks.append(Para(T.HASHES_NONE))
        blocks.append(Heading("VirusTotal lookups"))
        if self.verdicts:
            rows = []
            for e in self.verdicts:
                v = e.verdict
                res = (T.FACTS_VT_NO_RECORD if not v.found else
                       T.FACTS_VT_RECORD.format(hits=v.malicious, total=v.total))
                rows.append((code(self.rel(e.url)), code(e.sha256 or ""), res,
                             code(iso(v.checked_at))))
            blocks.append(_table(["File", "SHA256", "Result", "Checked (UTC)"], rows, kind="vt"))
            missed = len(self.hashed) - len(self.verdicts)
            rest = (f"{plural(missed, 'hashed file')} "
                    f"{'was' if missed == 1 else 'were'} not looked up.")
            blocks.append(Note(T.VT_NOTE.format(rest=rest)))
        else:
            blocks.append(Para(T.VT_NONE))
        sec = Section("hashes", "9", "Hashes and VirusTotal", "D")
        sec.blocks = blocks
        return sec

    def detection_run(self) -> Run:
        return Run(result=self.r, name=self.name or "scan",
                   candidates=tuple(self.all_candidates))

    def pack_rows(self):
        if hasattr(self, "_packs"):
            return self._packs
        tlp = self.tlp if self.tlp in ("CLEAR", "GREEN", "AMBER", "RED") else "AMBER"
        info = detections.summary(self.detection_run(), Options(tlp=tlp))
        self.det_info = info
        rows = []
        lists = []
        label = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "URL",
                 "sha256": "SHA256", "md5": "MD5", "email": "email"}
        for t in info["targets"]:
            if not t["live"]:
                continue
            if t["group"] == "blocklist":
                if t["count"]:
                    lists.append(t)
                continue
            if t["needs_pick"] and not t["count"]:
                rows.append((t["label"], T.YARA_NOT_GENERATED, T.YARA_NO_PICK))
                continue
            if not t["count"]:
                continue
            carried = ", ".join(f"{label.get(k, k)} {v}" for k, v in t["counts"].items() if v)
            rows.append((t["label"], code(t["filename"]), carried))
        if lists:
            more = f" and {len(lists) - 1} more" if len(lists) > 1 else ""
            rows.append((f"{len(lists)} block lists", code(lists[0]["filename"]) + more,
                         ", ".join(f"{label.get(k, k)} {v}" for t in lists
                                   for k, v in t["counts"].items() if v)))
        yara = [r for r in rows if r[1] == T.YARA_NOT_GENERATED]
        rows = [r for r in rows if r[1] != T.YARA_NOT_GENERATED] + yara
        self._packs = rows
        return rows

    def s_detections(self) -> Section:
        packs = self.pack_rows()
        left = {k: v for k, v in self.det_info["left_out"].items() if v}
        total = sum(left.values())
        unit = {"shared hosting (host level)": T.SHARED_UNIT}
        left_text = "; ".join(f"{k} {v}" + (f" ({unit[k]})" if k in unit else "")
                              for k, v in left.items())
        pivots = build_pivots(self.r, self.all_candidates)
        by = Counter(p.strength for p in pivots)
        picked = []
        for strength in ("narrow", "medium", "broad"):
            picked += [p for p in pivots if p.strength == strength][:2]
        prows = [(p.strength, p.engine.capitalize() if p.engine != "fofa" else "FOFA",
                  code(defang_text(p.shown_query or p.query))) for p in picked]
        blocks: list = [Heading("10.1 Detections")]
        made = [p for p in packs if p[1] != T.YARA_NOT_GENERATED]
        if made:
            blocks.append(Para(T.DETECTIONS_LEAD.format(total=total, reasons=left_text)
                               if total else T.DETECTIONS_LEAD_NOTHING_LEFT_OUT))
            blocks.append(_table(["Pack", "File", "Carries"], packs))
        else:
            blocks.append(Para(T.DETECTIONS_NONE))
            if packs:
                blocks.append(_table(["Pack", "File", "Carries"], packs))
        if self.tlp == "AMBER+STRICT":
            blocks.append(Note(T.STRICT_WARNING))
        blocks.append(Heading("10.2 Pivot queries"))
        if pivots:
            blocks.append(Para(T.PIVOTS_LEAD.format(n=len(pivots), narrow=by["narrow"],
                                                    medium=by["medium"], broad=by["broad"])))
            blocks.append(_table(["Strength", "Engine", "Query"], prows))
        else:
            blocks.append(Para(T.PIVOTS_NONE))
        sec = Section("detections", "10", "Detections and pivots", "D")
        sec.blocks = blocks
        return sec

    def s_recommendations(self) -> Section:
        r = self.r
        items = []
        if any(i.ioc_type in NETWORK_TYPES for i in r.iocs):
            items.append(T.REC_NETWORK)
        nonempty = {e.sha256 for e in self.hashed if e.sha256 != EMPTY_SHA256}
        if nonempty:
            items.append(T.REC_HASHES.format(n=len(nonempty)))
        items.append(T.REC_INCIDENT)
        secrets = [i for i in r.iocs if i.ioc_type == "secret"]
        if secrets:
            where = sorted({self.rel(u) for i in secrets for u in (i.sources or [i.source_url])})
            items.append(T.REC_ROTATE.format(files=", ".join(code(w) for w in where),
                                             n=len(secrets)))
        if r.target_asn:
            items.append(T.REC_ABUSE.format(asn=r.target_asn, name=r.target_as_name))
        tail = ""
        later = [o for _, o in self.others if o.started_at > r.started_at]
        if later:
            o = later[-1]
            if not o.entries and o.errors:
                detail = o.errors[0].detail
                if _conclusive(detail):
                    tail = T.REC_LAST_GONE.format(date=f"{o.started_at:%Y-%m-%d}")
                else:
                    tail = T.REC_LAST_FAILED.format(date=f"{o.started_at:%Y-%m-%d}",
                                                    detail=_detail(detail))
        items.append(T.REC_RERUN + tail)
        sec = Section("recommendations", "11", "Recommendations", "D")
        sec.blocks = [Para(T.RECOMMENDATIONS_LEAD), Bullets(tuple(items), ordered=True)]
        return sec

    def s_method(self) -> Section:
        o = self.r.options

        def opt(key: str) -> str:
            value = o.get(key)
            if value is None:
                return T.NOT_RECORDED
            if isinstance(value, float):
                return f"{value:g}"
            return str(value)

        peek = o.get("peek_bytes")
        rows = [
            *T.METHOD_ROWS.items(),
            ("Scope", T.METHOD_SCOPE.format(root=code(defang(self.root)))),
            ("Pace", T.METHOD_PACE.format(delay=o.get("delay") if o.get("delay") is not None
                                          else T.NOT_RECORDED, timeout=opt("timeout"))),
            ("Budgets", T.METHOD_BUDGETS.format(
                depth=opt("depth"), entries=opt("max_entries"), requests=opt("max_requests"),
                used=self.r.requests_made, bytes=size(self.r.bytes_fetched))),
            ("Reads", T.METHOD_READS.format(peek=size(peek)) if isinstance(peek, int)
             else T.METHOD_READS_NONE),
            ("Outside calls", (T.METHOD_OUTSIDE_VT.format(
                lookups=plural(len(self.verdicts), "VirusTotal hash lookup"))
                if self.verdicts else "") + T.METHOD_OUTSIDE),
            ("Network data", T.METHOD_NETWORK.format(source=self.network_source())
             if self.r.asn_source else T.METHOD_NETWORK_NONE),
        ]
        groups: OrderedDict = OrderedDict()
        for err in self.r.errors:
            groups.setdefault((err.stage, err.detail), []).append(err.url)
        nrows = [(capped([code(self.rel(u) or "/") for u in urls]), stage, _detail(detail),
                  explain(detail) or T.NO_EXPLANATION)
                 for (stage, detail), urls in groups.items()]
        sec = Section("method", "12", "Method, rules of engagement and collection notes", "O")
        sec.blocks = [_table(["Rule", "This run"], rows, kind="kv"),
                      Heading("12.1 Collection notes and errors")]
        sec.blocks.append(_table(["Files", "Stage", "Detail", "What it means"], nrows)
                          if nrows else Para(T.NO_NOTES))
        return sec

    def a_listing(self) -> Section:
        sec = Section("listing", "A", "Full listing and hashes", "O", appendix=True)
        if not self.r.entries:
            sec.blocks = [Para(T.NOTHING_LISTED)]
            return sec
        has_mod = any(e.modified for e in self.r.entries)
        has_fam = bool(self.r.clusters)
        headers = (["Path", "Type", "Read", "SHA256", "MD5"]
                   + (["Modified (server-reported)"] if has_mod else [])
                   + (["Family"] if has_fam else []))
        rows = []
        for e in sorted(self.r.entries, key=lambda e: (e.depth, not e.is_dir, e.name)):
            path = self.rel(e.url)
            if e.is_dir and not path.endswith("/"):
                path += "/"
            if e.sha256:
                sha = code(e.sha256)
            elif e.is_dir:
                sha = ""
            else:
                sha = T.LISTING_CUT if e.truncated else T.LISTING_UNREAD
            row = [code(path), "dir" if e.is_dir else str(e.kind),
                   "" if e.is_dir else size(e.fetched_bytes), sha,
                   code(e.md5) if e.md5 else ""]
            if has_mod:
                row.append(e.modified or "")
            if has_fam:
                row.append(code(e.cluster) if e.cluster else "")
            rows.append(tuple(row))
        blocks: list = [_table(headers, rows, aligns=["l", "l", "r", "l", "l"]
                               + ["l"] * (len(headers) - 5), kind="listing")]
        if not has_mod:
            blocks.insert(0, Note(T.NO_MODIFIED))
        sec.blocks = blocks
        return sec

    def a_indicators(self) -> Section:
        sec = Section("allind", "B", "All indicators", "D", appendix=True)
        if not self.r.iocs:
            sec.blocks = [Para(T.NO_INDICATORS)]
            return sec
        by_type: OrderedDict[str, list] = OrderedDict()
        for i in self.r.iocs:
            by_type.setdefault(i.ioc_type, []).append(i)
        blocks: list = [Note(T.APPENDIX_B_LEAD)]
        for t, items in by_type.items():
            lines = []
            # Strongest first; ties keep the order by value they came in.
            for i in sorted(items, key=lambda item: -(item.confidence or 0)):
                srcs = ", ".join(self.rel(u) for u in (i.sources or [i.source_url]))
                val = self.shown(i)
                head = f"{val:<48} " if len(val) < 48 else f"{val} "
                line = f"{head}{self.confidence(i):<9} {srcs}"
                why = self.confidence_reasons(i)
                lines.append(f"{line}  ({why})" if why else line)
            blocks.append(Pre(tuple(lines), title=f"{TYPE_LABEL.get(t, t)} ({len(items)})"))
        sec.blocks = blocks
        return sec

    def a_changelog(self) -> Section:
        rows = []
        for h in self.assessment.get("history") or []:
            if not isinstance(h, dict):
                continue
            rows.append((str(h.get("version", "")), code(str(h.get("at", ""))),
                         Free(defang_text(str(h.get("by", "")))),
                         T.CHANGELOG_CHANGED.format(fields=", ".join(
                             str(f) for f in h.get("fields") or []))))
        # The report is generated now, after any edit the analyst saved, so
        # its row goes after theirs as the version they reached. With no edits
        # it is the single 1.0 row it always was.
        if rows:
            current = version_of(self.assessment)
            generated = (T.CHANGELOG_GENERATED_AS.format(version=current, name=code(self.name))
                         if self.name else
                         T.CHANGELOG_GENERATED_AS_UNSAVED.format(version=current))
        else:
            current = "1.0"
            generated = (T.CHANGELOG_GENERATED.format(name=code(self.name)) if self.name
                         else T.CHANGELOG_GENERATED_UNSAVED)
        rows.append((current, code(iso(self.generated_at)), f"DirSift {self.version}",
                     generated))
        saved_sha = self.assessment.get("run_sha256")
        if saved_sha and saved_sha != self.run_sha:
            rows.append((version_of(self.assessment), code(iso(self.generated_at)),
                         f"DirSift {self.version}", T.CHANGELOG_SHA_DIFFERS))
        sec = Section("changelog", "C", "Change log", "R", appendix=True)
        sec.blocks = [_table(["Version", "Time (UTC)", "By", "Change"], rows)]
        return sec


def _detail(text: str) -> str:
    """A scan note as the report prints it: a URL or host in it is defanged."""
    return defang_text(text)


def _conclusive(detail: str) -> bool:
    """A failed listing that is a definite answer: gone, not refused or unreachable."""
    return bool(re.search(r"HTTP (404|410)\b", detail or ""))


def _table(headers, rows, aligns=None, kind: str = "", keep: bool = False) -> Table:
    return Table(tuple(headers), tuple(tuple(r) for r in rows),
                 tuple(aligns or ["l"] * len(headers)), kind, keep)


def version_of(assessment: dict) -> str:
    try:
        revision = int(assessment.get("revision", 0) or 0)
    except (TypeError, ValueError):
        revision = 0
    return f"1.{revision}"


def build_report(
    result: ScanResult,
    candidates: list | None = None,
    options: ReportOptions | None = None,
    assessment: dict | None = None,
    generated_at: datetime | None = None,
    run_sha256: str | None = None,
    sibling_runs: tuple[tuple[str, ScanResult], ...] | list = (),
) -> Report:
    """The whole report as a model, ready for either renderer.

    ``result`` is an analysed run and ``candidates`` its entry point candidates.
    ``generated_at`` and ``options.version`` are parameters so a test can fix
    them; left out they are now and the installed package version.
    ``run_sha256`` left out means a scan that was not saved: the hash of the run
    as it would be written.
    """
    options = options or ReportOptions()
    assessment = dict(assessment or {})
    generated_at = (generated_at or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    sha = run_sha256 or unsaved_sha256(result)
    b = _Builder(result, list(candidates or []), options, assessment, generated_at, sha,
                 tuple(sibling_runs))
    sections = b.build()
    author = options.author or assessment.get("author") or None
    status = assessment.get("status") if assessment.get("status") in ("Preliminary", "Final") \
        else "Preliminary"
    status_text = (T.STATUS_FINAL.format(author=author or "") if status == "Final"
                   else T.STATUS_PRELIMINARY)
    rid = report_id(result.root_url, result.started_at)
    version = version_of(assessment)
    run_cell = code(options.run_name) if options.run_name else T.RUN_NOT_SAVED
    sha_cell = code(sha) if options.run_name else code(sha) + " (" + T.RUN_NOT_SAVED + ")"
    doc = (
        ("Report ID", code(rid)),
        ("Version", version),
        # Final folds the author's name into this sentence, so it is analyst
        # text and is escaped in Markdown like the rest.
        ("Status", Free(status_text)),
        ("Generated", code(iso(generated_at))),
        ("Generated by", f"DirSift {b.version}"),
        ("Run", run_cell),
        ("Run file SHA256 (at generation)", sha_cell),
        ("TLP", "TLP:" + options.tlp + ". " + T.TLP_DEFINITIONS[options.tlp]),
        ("Author", Free(defang_text(author)) if author else T.AUTHOR_NOT_SET),
        ("Distribution", T.DISTRIBUTION),
    )
    paths = frozenset(b.rel(e.url) for e in result.entries) | frozenset(
        e.name for e in result.entries)
    return Report(
        report_id=rid,
        version=version,
        status=status,
        status_text=status_text,
        generated_at=generated_at,
        dirsift_version=b.version,
        run_name=options.run_name,
        run_sha256=sha,
        tlp=options.tlp,
        author=author,
        target=defang(result.root_url),
        started_at=result.started_at,
        sections=tuple(sections),
        doc_control=doc,
        iocs_defanged=frozenset(i.defanged for i in result.iocs),
        listing_paths=paths,
        summary_words=b.summary_words,
    )
