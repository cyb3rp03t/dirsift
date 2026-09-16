"""Data model for a scan.

One scan produces one :class:`ScanResult`. Everything downstream (classify,
cluster, glue detection, IOC extraction, the markdown report, the web UI)
reads that object and nothing else, so a run can be saved as JSON and
re-analysed later without touching the target again. That matters here: the
target is live attacker infrastructure, and every extra request is another
line in someone's access log.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Kind(StrEnum):
    """What a file appears to be. Deliberately coarse."""

    PE = "pe"  # Windows executable or DLL
    ELF = "elf"
    MACHO = "macho"
    SCRIPT = "script"  # bat, ps1, sh, py, vbs, js
    ARCHIVE = "archive"
    DOCUMENT = "document"
    IMAGE = "image"
    CONFIG = "config"  # json, yaml, ini, xml, env
    DATA = "data"  # logs, csv, txt, db dumps
    WEB = "web"  # html, php, asp, jsp
    CERT = "cert"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    """How the kind was decided. Sniffed beats guessed, always."""

    SNIFFED = "sniffed"  # magic bytes read off the wire
    EXTENSION = "extension"  # filename only
    NONE = "none"


class Entry(BaseModel):
    """One row of a directory listing."""

    url: str
    name: str
    is_dir: bool = False
    depth: int = 0
    parent_url: str | None = None

    # Reported by the listing itself. Servers lie, formats vary, both optional.
    size: int | None = None
    modified: str | None = None

    # Filled in by the classify stage.
    kind: Kind = Kind.UNKNOWN
    confidence: Confidence = Confidence.NONE
    magic: str | None = None
    content_type: str | None = None

    # Filled in only when the entry was actually fetched.
    sha256: str | None = None
    md5: str | None = None
    fetched_bytes: int | None = None
    # The read stopped at the peek ceiling, so the bytes are a head, not the file.
    truncated: bool = False
    # First bytes as hex, kept for the hex view. Already fetched; nothing extra is read.
    head_hex: str | None = None
    text_preview: str | None = None

    # Set by the cluster stage: the label of the version family this belongs to.
    cluster: str | None = None

    # Set only when someone asks a public scanner about the hash, from the console.
    verdict: Verdict | None = None

    # Set by the glue stage: how strongly this file drives the other files here.
    glue_score: float = 0.0
    references: list[str] = Field(default_factory=list)

    @property
    def ext(self) -> str:
        _, _, ext = self.name.rpartition(".")
        return ext.lower() if ext and ext != self.name else ""


class Ioc(BaseModel):
    """An indicator lifted out of a file's contents."""

    ioc_type: str  # ipv4, ipv6, url, domain, email, btc, secret, mutex, path
    value: str
    defanged: str
    source_url: str
    context: str | None = None
    label: str | None = None  # e.g. "aws_access_key", "telegram_bot_token"

    def key(self) -> tuple[str, str]:
        return (self.ioc_type, self.value.lower())


class Verdict(BaseModel):
    """What a public scanner says about one digest, and when it was asked.

    Kept on the entry so a run carries its own answers: the same file is never
    asked about twice, and a saved run can be reread without going out again.
    """

    found: bool
    malicious: int = 0
    total: int = 0
    analysed: str | None = None  # the date of the scanner's own last analysis
    checked_at: datetime = Field(default_factory=_utcnow)


class Cluster(BaseModel):
    """A family of files whose names differ only by a version-ish token."""

    label: str  # e.g. "secrun{n}.exe"
    stem: str
    members: list[str]  # entry names
    variants: list[str]  # the differing tokens, e.g. ["2", "3", "4", "5", "6"]
    variant_kind: str  # numeric, date, hex, alpha


class ScanError(BaseModel):
    url: str
    stage: str
    detail: str
    at: datetime = Field(default_factory=_utcnow)


class ScanResult(BaseModel):
    """Everything one run of DirSift learned about one open directory."""

    root_url: str
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None

    server: str | None = None
    listing_flavor: str | None = None  # apache, nginx, iis, python, caddy, h5ai, json
    title: str | None = None

    entries: list[Entry] = Field(default_factory=list)
    clusters: list[Cluster] = Field(default_factory=list)
    iocs: list[Ioc] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)

    requests_made: int = 0
    bytes_fetched: int = 0
    options: dict[str, Any] = Field(default_factory=dict)

    @property
    def files(self) -> list[Entry]:
        return [e for e in self.entries if not e.is_dir]

    @property
    def dirs(self) -> list[Entry]:
        return [e for e in self.entries if e.is_dir]

    def by_kind(self) -> dict[Kind, list[Entry]]:
        out: dict[Kind, list[Entry]] = {}
        for entry in self.files:
            out.setdefault(entry.kind, []).append(entry)
        return out
