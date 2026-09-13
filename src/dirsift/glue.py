"""Find the file that drives the others.

An open directory is a pile until you find the one file that names the rest.
That file is usually small, usually text, and usually boring to look at: a
``run.bat`` calling three binaries in order, a ``main.py`` importing the
modules around it, an ``install.sh`` that fetches and schedules. Once you have
it, the listing stops being an inventory and becomes a sequence, and the
sequence is what a teardown is actually about.

Scoring, in plain terms: a file earns most of its score for naming other files
in this directory, some for looking like an entry point, and some for reading
like a command line. Nothing here is certain, so the output is a ranked list
of candidates rather than a verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .classify import is_textual
from .extract import execution_tells
from .models import Entry, Kind

#: Filenames that announce themselves as the way in.
_ENTRY_NAMES = {
    "run", "start", "main", "launch", "install", "setup", "build", "deploy",
    "init", "boot", "go", "exec", "update", "loader", "dropper", "stage1",
    "autorun", "makefile", "entrypoint", "bootstrap",
}

_SCRIPT_KINDS = {Kind.SCRIPT, Kind.WEB, Kind.CONFIG}


@dataclass
class GlueCandidate:
    entry: Entry
    score: float
    references: list[str]
    tells: list[str]
    reasons: list[str]


def _stem(name: str) -> str:
    stem, dot, _ = name.rpartition(".")
    return (stem if dot else name).lower()


def _find_references(text: str, names: list[str], self_name: str) -> list[str]:
    """Which of ``names`` this text mentions.

    Matches the full filename, and also a bare stem when the stem is
    distinctive enough that a coincidence is unlikely.
    """
    lowered = text.lower()
    hits: list[str] = []
    for name in names:
        if name.lower() == self_name.lower():
            continue
        if name.lower() in lowered:
            hits.append(name)
            continue
        stem = _stem(name)
        if len(stem) >= 5 and re.search(rf"\b{re.escape(stem)}\b", lowered):
            hits.append(name)
    return hits


def score_glue(entries: list[Entry], *, top: int = 10) -> list[GlueCandidate]:
    """Rank the files in ``entries`` by how much they look like the driver."""
    files = [e for e in entries if not e.is_dir]
    names = [e.name for e in files]
    sibling_count = max(len(files) - 1, 1)
    candidates: list[GlueCandidate] = []

    for entry in files:
        if not entry.text_preview or not is_textual(entry):
            continue

        text = entry.text_preview
        references = _find_references(text, names, entry.name)
        tells = execution_tells(text)
        reasons: list[str] = []

        # Naming the neighbours is the strongest signal, and it saturates:
        # referencing 3 of 40 files already means this file orchestrates.
        coverage = min(len(references) / min(sibling_count, 8), 1.0)
        score = 55.0 * coverage
        if references:
            reasons.append(
                f"names {len(references)} other file"
                f"{'s' if len(references) != 1 else ''} in this directory"
            )

        if tells:
            score += min(len(tells), 6) * 3.0
            reasons.append("contains " + ", ".join(tells[:4]))

        if _stem(entry.name) in _ENTRY_NAMES:
            score += 12.0
            reasons.append("named like an entry point")
        elif any(_stem(entry.name).startswith(n) for n in _ENTRY_NAMES):
            score += 6.0
            reasons.append("name starts like an entry point")

        if entry.kind in _SCRIPT_KINDS:
            score += 6.0
        if entry.depth <= 1:
            score += 4.0
            reasons.append("sits at the top of the tree")
        if (entry.size or entry.fetched_bytes or 0) < 8192 and references:
            score += 4.0
            reasons.append("small enough to be a wrapper")

        if score <= 0:
            continue
        candidates.append(
            GlueCandidate(
                entry=entry,
                score=round(min(score, 100.0), 1),
                references=references,
                tells=tells,
                reasons=reasons,
            )
        )

    candidates.sort(key=lambda c: (-c.score, c.entry.name))
    return candidates[:top]


def apply_glue(entries: list[Entry], candidates: list[GlueCandidate]) -> None:
    """Write scores and reference lists back onto the entries."""
    by_url = {c.entry.url: c for c in candidates}
    for entry in entries:
        candidate = by_url.get(entry.url)
        if candidate is not None:
            entry.glue_score = candidate.score
            entry.references = candidate.references
