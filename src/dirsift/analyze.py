"""Run every offline pass over a :class:`ScanResult`.

Nothing here touches the network. That separation is the point: a run can be
saved to JSON during the scan and re-analysed as often as you like, with
sharper rules each time, without knocking on the target again.
"""

from __future__ import annotations

from .cluster import apply_clusters, find_clusters
from .extract import dedupe_iocs, extract_iocs
from .glue import GlueCandidate, apply_glue, score_glue
from .models import ScanResult


def analyze(result: ScanResult, *, glue_top: int = 10) -> tuple[ScanResult, list[GlueCandidate]]:
    """Cluster, score and extract. Mutates and returns ``result``."""
    clusters = find_clusters(result.entries)
    apply_clusters(result.entries, clusters)
    result.clusters = clusters

    candidates = score_glue(result.entries, top=glue_top)
    apply_glue(result.entries, candidates)

    iocs = []
    for entry in result.files:
        if entry.text_preview:
            iocs.extend(extract_iocs(entry.text_preview, entry.url))
    result.iocs = dedupe_iocs(iocs)

    return result, candidates
