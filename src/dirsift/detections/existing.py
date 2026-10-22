"""The outputs DirSift already had, under the same options as the new ones.

YARA comes from ``rules.py`` (secrets kept out there), STIX from ``stix.py``
with the chosen TLP marking, and the two text lists carry the same filtered
indicators the other targets read.
"""

from __future__ import annotations

from ..rules import build_rules
from ..stix import build_bundle, bundle_json
from .collect import collect
from .meta import Run, commented, header
from .options import Options


def render_yara(run: Run, options: Options) -> str:
    wanted = set(options.pick)
    picked = [entry for entry in run.result.files if entry.url in wanted]
    if not picked:
        return "// nothing was selected: pick files in the listing to build rules from\n"
    return build_rules(run.result, picked, run.name, tlp=options.tlp_label)


def render_stix(run: Run, options: Options) -> str:
    """The bundle over the same filtered values every other target carries."""
    collected = collect(run.result, options)
    return bundle_json(
        build_bundle(run.result, list(run.candidates), tlp=options.tlp, only=collected)
    )


def render_indicators(run: Run, options: Options) -> str:
    """Every value a shared file may carry, defanged, one per line. Never live."""
    collected = collect(run.result, options)
    lines = header(run, options.preview(), "dirsift indicators (defanged)", [])
    lines = commented(lines[:-1] + ["defanged: safe to read and paste."], "#")
    lines += [f"{item.kind}\t{item.defanged}" for item in collected.indicators]
    return "\n".join(lines) + "\n"


def render_hashes(run: Run, options: Options) -> str:
    """sha256, md5 and path, for the files read whole. A hash is never live."""
    lines = commented(
        header(run, options.preview(), "dirsift hashes of files read whole", [])[:-1], "#"
    )
    for entry in run.result.files:
        if not entry.sha256 or entry.truncated:
            continue
        if options.source is not None and entry.url != options.source:
            continue
        path = entry.url.removeprefix(run.result.root_url) or entry.name
        lines.append(f"{entry.sha256}  {entry.md5 or '-'}  {path}")
    return "\n".join(lines) + "\n"
