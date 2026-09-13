"""Group files whose names differ only by a version-ish token.

``secrun2.exe`` through ``secrun6.exe`` is one artefact with five builds, not
five artefacts, and reading it as five is how a triage session turns into an
afternoon. Collapsing the family also surfaces the gaps: a listing that jumps
from 2 to 6 with no 4 says a build was pulled, and the timestamps across the
family are a development timeline you get for free.

Three masks run in order, most specific first, so that a hex blob is not
shredded into digits:

* hex runs of six or more characters      ``payload_a3f29c.bin``
* date-shaped digit runs (8 or 6 digits)  ``dump_20260911.txt``
* any remaining digit run                 ``secrun2.exe``

and finally a single-character alphabetic pass for ``runa/runb/runc``.
"""

from __future__ import annotations

import re
from collections import defaultdict

from .models import Cluster, Entry

# A run of hex characters that contains at least one a-f, so that an all-digit
# run like 20260911 falls through to the date pass instead of being eaten here.
_HEX_RUN = re.compile(
    r"(?<![0-9a-zA-Z])(?![0-9]+(?![0-9a-zA-Z]))[0-9a-f]{6,}(?![0-9a-zA-Z])", re.I
)
_DATE_RUN = re.compile(r"(?<!\d)(?:20\d{6}|\d{6})(?!\d)")
_DIGIT_RUN = re.compile(r"\d+")

_PLACEHOLDER = {"hex": "{hex}", "date": "{date}", "numeric": "{n}", "alpha": "{a}"}


def _split_ext(name: str) -> tuple[str, str]:
    stem, dot, ext = name.rpartition(".")
    if not dot:
        return name, ""
    return stem, ext.lower()


def _mask(stem: str) -> tuple[str, str, list[str]] | None:
    """Return (masked_stem, variant_kind, tokens) for the first mask that bites."""
    for pattern, kind in ((_HEX_RUN, "hex"), (_DATE_RUN, "date"), (_DIGIT_RUN, "numeric")):
        tokens = pattern.findall(stem)
        if tokens:
            return pattern.sub(_PLACEHOLDER[kind], stem), kind, tokens
    return None


def _varying_tokens(token_lists: list[list[str]]) -> list[str]:
    """Pick the token position that actually differs across the family.

    ``build_v1.2.3.zip`` and ``build_v1.2.4.zip`` mask to the same stem with
    three numeric tokens each; only the third one carries the version.
    """
    width = min(len(tokens) for tokens in token_lists)
    for index in range(width):
        column = [tokens[index] for tokens in token_lists]
        if len(set(column)) > 1:
            return column
    return [tokens[0] for tokens in token_lists]


def _compact(variants: list[str], kind: str) -> list[str]:
    """Render 2,3,4,5,6 as ['2..6'] but leave gaps visible."""
    if kind != "numeric":
        return sorted(set(variants), key=str)
    try:
        numbers = sorted({int(v) for v in variants})
    except ValueError:
        return sorted(set(variants))

    runs: list[str] = []
    start = prev = numbers[0]
    for number in numbers[1:]:
        if number == prev + 1:
            prev = number
            continue
        runs.append(str(start) if start == prev else f"{start}..{prev}")
        start = prev = number
    runs.append(str(start) if start == prev else f"{start}..{prev}")
    return runs


def _alpha_pass(names: list[str], already: set[str]) -> list[Cluster]:
    """Catch ``runa.exe`` / ``runb.exe``: same length, one letter apart."""
    groups: dict[tuple[str, str, int], list[str]] = defaultdict(list)
    for name in names:
        if name in already:
            continue
        stem, ext = _split_ext(name)
        if len(stem) < 3:
            continue
        for i, ch in enumerate(stem):
            if ch.isalpha():
                groups[(stem[:i] + "\x00" + stem[i + 1 :], ext, i)].append(name)

    clusters: list[Cluster] = []
    claimed: set[str] = set()
    for (pattern, ext, index), members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        members = [m for m in members if m not in claimed]
        if len(members) < 3:  # two files differing by a letter is usually a coincidence
            continue
        claimed.update(members)
        stem = pattern.replace("\x00", "{a}")
        clusters.append(
            Cluster(
                label=f"{stem}.{ext}" if ext else stem,
                stem=stem,
                members=sorted(members),
                variants=sorted(_split_ext(m)[0][index] for m in members),
                variant_kind="alpha",
            )
        )
    return clusters


def find_clusters(entries: list[Entry], *, min_members: int = 2) -> list[Cluster]:
    """Group ``entries`` into version families. Singletons are not returned."""
    files = [e for e in entries if not e.is_dir]
    groups: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)

    for entry in files:
        stem, ext = _split_ext(entry.name)
        masked = _mask(stem)
        if masked is None:
            continue
        masked_stem, kind, tokens = masked
        groups[(masked_stem, ext, kind)].append((entry.name, tokens))

    clusters: list[Cluster] = []
    clustered: set[str] = set()
    for (masked_stem, ext, kind), members in groups.items():
        if len(members) < min_members:
            continue
        names = sorted(name for name, _ in members)
        clustered.update(names)
        clusters.append(
            Cluster(
                label=f"{masked_stem}.{ext}" if ext else masked_stem,
                stem=masked_stem,
                members=names,
                variants=_compact(_varying_tokens([t for _, t in members]), kind),
                variant_kind=kind,
            )
        )

    clusters.extend(_alpha_pass([e.name for e in files], clustered))
    clusters.sort(key=lambda c: (-len(c.members), c.label))
    return clusters


def apply_clusters(entries: list[Entry], clusters: list[Cluster]) -> None:
    """Write each cluster's label back onto its member entries."""
    label_by_name = {name: c.label for c in clusters for name in c.members}
    for entry in entries:
        if not entry.is_dir:
            entry.cluster = label_by_name.get(entry.name)
