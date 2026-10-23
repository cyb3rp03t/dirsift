"""How sure a run is that an indicator is a live part of the kit.

A directory gives up sixty indicators and most of them are not the kit: an
address in a comment someone left behind, a resolver pinged to test the line, a
domain an analyst wrote down defanged. The score separates those from the
callback the loader actually uses.

It is not a maliciousness score. DirSift does not judge; the score weighs how
the indicator sits in the files that carried it: in how many files, in which
kind of file, in code or in a comment, live or defanged, pointing out or back
at the host itself. Every point it gains or loses comes with the sentence that
explains it, and there is no point without one.

Nothing here touches the network.
"""

from __future__ import annotations

from typing import NamedTuple
from urllib.parse import urlparse

from .extract import host_of
from .models import Entry, Ioc, Kind, ScanResult
from .pivots import internal_address


class Weight(NamedTuple):
    points: int
    reason: str  # what the person reading the run is told; empty for settings


#: Every number the score is made of, with the sentence that goes with it.
#: Reasons are listed by the size of their effect, and ties keep this order.
WEIGHTS: dict[str, Weight] = {
    # Where every indicator starts: found in a file, as likely live as not.
    "start": Weight(50, ""),
    # Each file beyond the first that names it. A kit repeats its own
    # infrastructure; a stray note does not.
    "more_files": Weight(10, "named in {n} files"),
    # Three files say most of what thirty would.
    "more_files_cap": Weight(20, ""),
    # Kept through a rebuild is the strongest sign it is the kit's own.
    "family": Weight(15, "survived across builds of {family}"),
    # Config and scripts are what the kit reads and runs.
    "config_or_script": Weight(10, "sits in a config or script"),
    # The file that drives the others names what matters to it. Small, because
    # the ranking itself is a guess.
    "entry_point": Weight(5, "named by the likely entry point"),
    # Staging hosts call home to themselves: a second port, a panel.
    "own_host": Weight(10, "points back at the host being triaged"),
    # Notes left behind, not configuration.
    "comment_only": Weight(-15, "only in comments"),
    # Defanged by a person writing about it: the strongest sign of notes.
    "written_defanged": Weight(
        -25, "written defanged in the source; likely someone's notes, not live config"
    ),
    # Real, but no use to anyone outside that network.
    "private": Weight(-20, "private address; does not pivot outside that network"),
    # A connectivity check, almost every time.
    "public_resolver": Weight(
        -30, "public resolver; usually a connectivity check, not infrastructure"
    ),
    # Seen in the first bytes only; the rest of the file may say otherwise.
    "head_only": Weight(-5, "read from the head of the file only"),
    # The scale, and where it is cut into bands.
    "floor": Weight(0, ""),
    "ceiling": Weight(100, ""),
    "high": Weight(75, ""),
    "medium": Weight(50, ""),
}

#: Resolvers a script pings to see whether the line is up.
PUBLIC_RESOLVERS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
    "208.67.222.222", "208.67.220.220",
}

#: File kinds whose contents the kit itself reads or runs.
CODE_KINDS = {Kind.CONFIG, Kind.SCRIPT}


def band(score: int) -> str:
    """high, medium or low, from where the score sits on the scale."""
    if score >= WEIGHTS["high"].points:
        return "high"
    if score >= WEIGHTS["medium"].points:
        return "medium"
    return "low"


def short_reason(reason: str) -> str:
    """A reason cut to its first clause, for a line that has to stay short."""
    return reason.split(";", 1)[0]


def _address(ioc: Ioc) -> str:
    """The bare address an indicator names, if it names one."""
    if ioc.ioc_type == "ipv4":
        return ioc.value.split(":", 1)[0]
    if ioc.ioc_type == "ipv6":
        return ioc.value.strip("[]")
    if ioc.ioc_type == "url":
        host = host_of(ioc.value)
        return host if internal_address(host) is not None else ""
    return ""


def _host(ioc: Ioc) -> str:
    """The host an indicator points at: an address, a name, or a URL's host."""
    if ioc.ioc_type in ("ipv4", "ipv6"):
        return _address(ioc)
    if ioc.ioc_type == "domain":
        return ioc.value.lower()
    if ioc.ioc_type == "url":
        return host_of(ioc.value).lower()
    return ""


def _driver(candidates) -> str | None:
    """The file ranked first as the driver, if it actually names other files.

    A run with one file always ranks that file first; ranking first among one
    says nothing. A driver is a file that names the others.
    """
    ranked = [c for c in candidates if c.score > 0]
    if ranked and ranked[0].references:
        return ranked[0].entry.url
    return None


def _family(sources: list[Entry]) -> str | None:
    """A version family at least two of the files belong to, if there is one."""
    counts: dict[str, int] = {}
    for entry in sources:
        if entry.cluster:
            counts[entry.cluster] = counts.get(entry.cluster, 0) + 1
    shared = sorted(label for label, count in counts.items() if count >= 2)
    return shared[0] if shared else None


def _rules(ioc: Ioc, sources: list[Entry], result: ScanResult, driver: str | None):
    """The rules that apply to one indicator, as (rule name, reason) pairs."""
    named = len(ioc.sources or [ioc.source_url])
    if named > 1:
        yield "more_files", WEIGHTS["more_files"].reason.format(n=named)
    family = _family(sources)
    if family:
        yield "family", WEIGHTS["family"].reason.format(family=family)
    if any(entry.kind in CODE_KINDS for entry in sources):
        yield "config_or_script", WEIGHTS["config_or_script"].reason
    if driver and driver in (ioc.sources or [ioc.source_url]):
        yield "entry_point", WEIGHTS["entry_point"].reason

    own = {urlparse(result.root_url).hostname or "", result.target_ip or ""} - {""}
    if _host(ioc) and _host(ioc) in {host.lower() for host in own}:
        yield "own_host", WEIGHTS["own_host"].reason

    if ioc.in_comment:
        yield "comment_only", WEIGHTS["comment_only"].reason
    if not ioc.seen_live:
        yield "written_defanged", WEIGHTS["written_defanged"].reason

    address = _address(ioc)
    if address and internal_address(address):
        yield "private", WEIGHTS["private"].reason
    if address in PUBLIC_RESOLVERS:
        yield "public_resolver", WEIGHTS["public_resolver"].reason

    if sources and all(entry.truncated for entry in sources):
        yield "head_only", WEIGHTS["head_only"].reason


def _points(rule: str, ioc: Ioc) -> int:
    if rule == "more_files":
        extra = len(ioc.sources or [ioc.source_url]) - 1
        return min(WEIGHTS["more_files"].points * extra, WEIGHTS["more_files_cap"].points)
    return WEIGHTS[rule].points


def score_ioc(ioc: Ioc, result: ScanResult, by_url: dict[str, Entry], driver: str | None):
    """The score for one indicator, and its reasons, largest effect first."""
    sources = [by_url[url] for url in (ioc.sources or [ioc.source_url]) if url in by_url]
    order = list(WEIGHTS)
    applied = [
        (_points(rule, ioc), order.index(rule), reason)
        for rule, reason in _rules(ioc, sources, result, driver)
    ]
    total = WEIGHTS["start"].points + sum(points for points, _, _ in applied)
    score = max(WEIGHTS["floor"].points, min(WEIGHTS["ceiling"].points, total))
    applied.sort(key=lambda item: (-abs(item[0]), item[1]))
    return score, [reason for _, _, reason in applied]


def score_iocs(result: ScanResult, candidates) -> None:
    """Fill in the confidence and its reasons on every indicator of the run."""
    by_url = {entry.url: entry for entry in result.files}
    driver = _driver(candidates)
    for ioc in result.iocs:
        ioc.confidence, ioc.confidence_reasons = score_ioc(ioc, result, by_url, driver)
