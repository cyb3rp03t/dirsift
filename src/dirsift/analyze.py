"""Run every offline pass over a :class:`ScanResult`.

Nothing here touches the network. That separation is the point: a run can be
saved to JSON during the scan and re-analysed as often as you like, with
sharper rules each time, without knocking on the target again.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .asn import AsnTable, default_table
from .cluster import apply_clusters, find_clusters
from .extract import dedupe_iocs, extract_iocs
from .glue import GlueCandidate, apply_glue, score_glue
from .models import ScanResult


def _address_of(value: str) -> str:
    """The bare address in an indicator that may carry a port or brackets."""
    text = value.strip()
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1:  # an IPv4 with a port; IPv6 has more colons
        return text.split(":", 1)[0]
    return text


def _placeable(ioc) -> str:
    """The address inside an indicator, when it has one written out.

    A URL to a bare address is the same host in another spelling, so it is
    placed too. A URL to a name is not: finding out where it points means
    asking someone, and that is a question this tool does not ask.
    """
    if ioc.ioc_type in ("ipv4", "ipv6"):
        return _address_of(ioc.value)
    if ioc.ioc_type == "url":
        return urlparse(ioc.value).hostname or ""
    return ""


def place_in_networks(result: ScanResult, table: AsnTable) -> None:
    """Say which network each address belongs to, from a table already on disk."""
    if table.empty:
        return
    result.asn_source = table.source
    result.asn_stamp = table.stamp
    for ioc in result.iocs:
        target = _placeable(ioc)
        if not target:
            continue
        found = table.lookup(target)
        if found:
            ioc.asn, ioc.as_name, ioc.country = found.asn, found.name, found.country
    if result.target_ip:
        found = table.lookup(result.target_ip)
        if found:
            result.target_asn = found.asn
            result.target_as_name = found.name
            result.target_country = found.country


def analyze(
    result: ScanResult, *, glue_top: int = 10, asn_table: AsnTable | None = None
) -> tuple[ScanResult, list[GlueCandidate]]:
    """Cluster, score, extract, and place addresses. Mutates and returns ``result``."""
    clusters = find_clusters(result.entries)
    apply_clusters(result.entries, clusters)
    result.clusters = clusters

    candidates = score_glue(result.entries, top=glue_top)
    apply_glue(result.entries, candidates)

    # Indicators are extracted again from scratch every time, so any network
    # already recorded would be thrown away with them. It is kept: the run was
    # placed against a dated table on the machine that did the scanning, and
    # the same file opened elsewhere should still say where the address was.
    known = {
        ioc.value: (ioc.asn, ioc.as_name, ioc.country) for ioc in result.iocs if ioc.asn
    }

    iocs = []
    for entry in result.files:
        if entry.text_preview:
            iocs.extend(extract_iocs(entry.text_preview, entry.url))
    result.iocs = dedupe_iocs(iocs)
    place_in_networks(result, asn_table if asn_table is not None else default_table())

    for ioc in result.iocs:
        if not ioc.asn and ioc.value in known:
            ioc.asn, ioc.as_name, ioc.country = known[ioc.value]

    return result, candidates
