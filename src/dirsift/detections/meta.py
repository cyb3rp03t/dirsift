"""The lines every file opens with, written in each format's own comment style."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from ..extract import defang
from ..models import ScanResult
from ..stix import DIRSIFT_NAMESPACE, timestamp
from .options import Options

AUTHOR = "cyb3rp03t"
NOT_A_VERDICT = "Found in an open directory, not a verdict: hunt with it, decide yourself."


@dataclass(frozen=True)
class Run:
    """A saved run as the targets see it: the result, its name, its entry point candidates."""

    result: ScanResult
    name: str
    candidates: tuple = ()


def header(run: Run, options: Options, title: str, assumes: list[str]) -> list[str]:
    """The header as plain lines; each target adds its own comment marker."""
    lines = [
        f"{title}",
        f"dirsift run {run.name} | author {AUTHOR} | {options.tlp_label}",
        f"target {defang(run.result.root_url)} | scan started {timestamp(run.result.started_at)}",
        NOT_A_VERDICT,
    ]
    if options.source:
        lines.append(f"only indicators from {defang(options.source)}")
    for note in assumes:
        lines.append(f"assumes {note}")
    if options.live:
        lines.append(
            "live values, not defanged: import it, do not open it in a browser "
            "or paste it in a chat."
        )
    else:
        lines.append("preview: values are defanged here; the download carries them live.")
    return lines


def commented(lines: list[str], marker: str) -> list[str]:
    return [f"{marker} {line}".rstrip() for line in lines]


def stable_uuid(run: Run, options: Options, *parts: str) -> str:
    """A UUID with version 4 bits, determined entirely by the run and ``parts``.

    The same run and the same options always give the same identifier, so an
    import updates what an earlier import of the same run created.
    """
    key = "|".join([run.result.root_url, run.name, options.source or "", *parts])
    derived = uuid.uuid5(DIRSIFT_NAMESPACE, key)
    return str(uuid.UUID(bytes=derived.bytes, version=4))


def started(run: Run) -> datetime:
    """When the scan started, in UTC; a time without a zone is taken as UTC."""
    value = run.result.started_at
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def slug(value: str, limit: int = 48) -> str:
    """Lower case letters, digits and underscores only, for identifiers in rule languages."""
    cleaned = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return cleaned[:limit].rstrip("_") or "run"
