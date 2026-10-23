"""Detection content built from a saved run: rules, queries, lists and feeds.

Every target is a pure function from a run and the export options to text.
Nothing here opens a socket, reads a key or calls a product: the content is
written to a file, and the person who downloads it decides where it goes.

A file carries live values, because a matcher matches nothing defanged. The
preview is the same text with every value defanged, for reading on screen.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlparse

from ..extract import defang, defang_text, host_of
from ..models import ScanResult
from . import csvfeed, elastic, kql, logscale, misp, qradar, rpz, secops, sigma, splunk, suricata
from .blocklist import ASSUMES as LIST_ASSUMES
from .blocklist import render_list, without_scheme
from .collect import REASONS, SHAREABLE, collect
from .existing import render_hashes, render_indicators, render_stix, render_yara
from .meta import Run
from .options import (
    PROFILES,
    TLP_LEVELS,
    BadOption,
    Options,
    defang_value,
    parse_profile,
    parse_tlp,
    parse_types,
)

__all__ = [
    "FAMILIES",
    "GROUPS",
    "PROFILES",
    "REASONS",
    "SHAREABLE",
    "TARGETS",
    "TLP_LEVELS",
    "BadOption",
    "collect",
    "defang_rendering",
    "defang_with",
    "live_values",
    "manifest",
    "zip_name",
    "Options",
    "Run",
    "Target",
    "filename",
    "parse_profile",
    "parse_tlp",
    "parse_types",
    "preview",
    "render",
    "summary",
    "zip_bytes",
]

GROUPS = ("existing", "blocklist", "siem", "network", "share")


@dataclass(frozen=True)
class Target:
    id: str
    group: str
    label: str
    product: str
    ext: str
    media_type: str
    live: bool
    kinds: tuple[str, ...]  # the indicator types it carries
    assumes: tuple[str, ...]
    render: Callable[[Run, Options], str]
    needs_pick: bool = False


TEXT = "text/plain; charset=utf-8"

_TARGETS = [
    Target(
        "yara", "existing", "YARA", "YARA rules for the files picked in the listing",
        "yar", TEXT, True, ("url", "ipv4", "ipv6", "domain", "email"),
        ("YARA 4, ascii strings; secrets are never written into a rule",),
        render_yara, needs_pick=True,
    ),
    Target(
        "stix", "existing", "STIX 2.1 bundle",
        "STIX 2.1 for OpenCTI, MISP, Cortex XSOAR, Sentinel threat intelligence",
        "json", "application/json", True, ("ipv4", "ipv6", "domain", "url", "sha256"),
        ("STIX 2.1 with the TLP 1.0 marking definitions the specification fixes",),
        render_stix,
    ),
    Target(
        "indicators", "existing", "Indicators (defanged)", "Defanged list for notes and chat",
        "txt", TEXT, False, SHAREABLE, (), render_indicators,
    ),
    Target(
        "hashes", "existing", "Hashes", "sha256, md5 and path of the files read whole",
        "txt", TEXT, False, ("sha256", "md5"), (), render_hashes,
    ),
]

for _kind, _label in (
    ("ipv4", "IPv4"), ("ipv6", "IPv6"), ("domain", "Domain"), ("url", "URL"), ("sha256", "SHA256"),
):
    _TARGETS.append(
        Target(
            f"blocklist-{_kind}", "blocklist", f"{_label} block list",
            "Palo Alto EDL, Fortinet threat feed, Check Point, Cisco, pfSense and OPNsense",
            "txt", TEXT, _kind != "sha256", (_kind,),
            (LIST_ASSUMES[_kind],),
            (lambda kind: lambda run, options: render_list(kind, run, options))(_kind),
        )
    )

for _key, (_label, _kinds, _element) in qradar.SETS.items():
    _TARGETS.append(
        Target(
            f"qradar-set-{_key}", "siem", f"QRadar reference set, {_label}",
            "IBM QRadar reference set, loaded with ReferenceDataUtil.sh",
            "csv", "text/csv; charset=utf-8", _key != "hash", _kinds,
            (f"a QRadar reference set of element type {_element}",),
            (lambda key: lambda run, options: qradar.render_set(key, run, options))(_key),
        )
    )

_TARGETS += [
    Target(
        "sigma", "siem", "Sigma", "Sigma rule collection, for any SIEM through sigma-cli",
        "yml", "application/yaml", True, sigma.KINDS, tuple(sigma.ASSUMES), sigma.render,
    ),
    Target(
        "splunk", "siem", "Splunk SPL", "Splunk Enterprise and Enterprise Security (CIM)",
        "spl", TEXT, True, splunk.KINDS, tuple(splunk.ASSUMES), splunk.render,
    ),
    Target(
        "kql", "siem", "Microsoft Sentinel / Defender KQL",
        "Microsoft Defender XDR advanced hunting and Microsoft Sentinel",
        "kql", TEXT, True, kql.KINDS, tuple(kql.ASSUMES), kql.render,
    ),
    Target(
        "elastic-esql", "siem", "Elastic ES|QL", "Elastic Security hunting in Discover (ECS)",
        "esql", TEXT, True, elastic.KINDS, tuple(elastic.ESQL_ASSUMES), elastic.render_esql,
    ),
    Target(
        "elastic-rules", "siem", "Elastic detection rules",
        "Elastic Security detection rule import (NDJSON, KQL, ECS)",
        "ndjson", "application/x-ndjson", True, elastic.KINDS, tuple(elastic.RULE_ASSUMES),
        elastic.render_rules,
    ),
    Target(
        "secops-yaral", "siem", "Google SecOps YARA-L", "Google SecOps (Chronicle) rules over UDM",
        "yaral", TEXT, True, secops.KINDS, tuple(secops.ASSUMES), secops.render,
    ),
    Target(
        "qradar-aql", "siem", "IBM QRadar AQL", "IBM QRadar Advanced Search over events and flows",
        "aql", TEXT, True, qradar.KINDS, tuple(qradar.ASSUMES), qradar.render_aql,
    ),
    Target(
        "logscale-cql", "siem", "CrowdStrike LogScale CQL",
        "CrowdStrike Falcon LogScale and Next-Gen SIEM",
        "cql", TEXT, True, logscale.KINDS, tuple(logscale.ASSUMES), logscale.render,
    ),
    Target(
        "suricata", "network", "Suricata rules", "Suricata IDS (IP rules also read in Snort 3)",
        "rules", TEXT, True, suricata.KINDS, tuple(suricata.ASSUMES), suricata.render,
    ),
    Target(
        "rpz", "network", "DNS RPZ zone", "Response policy zone for BIND, Unbound, Knot, PowerDNS",
        "zone", TEXT, True, rpz.KINDS, tuple(rpz.ASSUMES), rpz.render,
    ),
    Target(
        "misp", "share", "MISP event", "MISP event import (core format), your organisation only",
        "json", "application/json", True, misp.KINDS, tuple(misp.ASSUMES), misp.render,
    ),
    Target(
        "csv", "share", "CSV (SOAR / TIP import)", "Generic CSV for SOAR and TIP list imports",
        "csv", "text/csv; charset=utf-8", True, csvfeed.KINDS, tuple(csvfeed.ASSUMES),
        csvfeed.render,
    ),
]

TARGETS: dict[str, Target] = {target.id: target for target in _TARGETS}

#: How a report groups the live targets: one row per family, never one per file.
FAMILIES = (
    ("SIEM queries", ("splunk", "kql", "elastic-esql", "secops-yaral", "qradar-aql",
                      "logscale-cql", *(f"qradar-set-{key}" for key in qradar.SETS))),
    ("Rules and sharing", ("yara", "sigma", "elastic-rules", "stix", "misp", "csv")),
    ("Block lists", tuple(t.id for t in _TARGETS if t.group == "blocklist")),
    ("Network", ("suricata", "rpz")),
)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def filename(run: Run, target: Target) -> str:
    """An ASCII file name that is the same on every platform."""
    stem = _SAFE_NAME.sub("-", run.name).strip("-.") or "run"
    return f"dirsift_{stem}_{target.id}.{target.ext}"


def zip_name(run: Run) -> str:
    stem = _SAFE_NAME.sub("-", run.name).strip("-.") or "run"
    return f"dirsift_{stem}_detections.zip"


def render(target: Target, run: Run, options: Options) -> str:
    """The file as it is downloaded: live values where the target carries them."""
    return target.render(run, options)


def _live_values(run: Run) -> list[str]:
    """Every live value the run holds that a rendering could carry, longest first."""
    return live_values(run.result)


def live_values(result: ScanResult) -> list[str]:
    """Every live value a saved run holds, longest first, for defanging a rendering."""
    values = {result.root_url, urlparse(result.root_url).hostname or ""}
    if result.target_ip:
        values.add(result.target_ip)
    for ioc in result.iocs:
        if ioc.ioc_type in ("ipv4", "ipv6", "domain", "url", "email"):
            values.add(ioc.value)
            if ioc.ioc_type == "ipv4":
                values.add(ioc.value.split(":", 1)[0])
            if ioc.ioc_type == "url":
                values.add(without_scheme(ioc.value))
                values.add(host_of(ioc.value))
    wanted = [value for value in values if value and ("." in value or ":" in value)]
    return sorted(wanted, key=len, reverse=True)


def defang_rendering(text: str, run: Run) -> str:
    """A rendering with nothing live left in it.

    The targets already defang through ``Options.show``; YARA and STIX are
    built live by their own modules, so every value the run holds is replaced
    here as well, and anything that still looks like an address after that is
    defanged by the prose pass.
    """
    return defang_with(text, _live_values(run))


def defang_with(text: str, values: list[str]) -> str:
    """Replace each of ``values`` (longest first) with its defanged form, then defang the prose."""
    for value in values:
        if value in text:
            text = text.replace(value, defang_value(value))
    return defang_text(text)


def preview(target: Target, run: Run, options: Options) -> str:
    """The same content, defanged, for reading on screen."""
    return defang_rendering(target.render(run, options.preview()), run)


def summary(run: Run, options: Options) -> dict:
    """Per target: what it would carry and what was kept out."""
    collected = collect(run.result, options)
    counts = collected.counts()
    targets = []
    for target in TARGETS.values():
        carried = {kind: counts[kind] for kind in target.kinds if kind in counts}
        if target.id == "yara":
            carried = {}
        targets.append(
            {
                "id": target.id,
                "group": target.group,
                "label": target.label,
                "product": target.product,
                "filename": filename(run, target),
                "media_type": target.media_type,
                "live": target.live,
                "needs_pick": target.needs_pick,
                "count": sum(carried.values()) if target.id != "yara" else len(options.pick),
                "counts": carried,
                "assumes": list(target.assumes),
                "left_out": collected.left_out(target.kinds),
            }
        )
    return {
        "types": counts,
        "left_out": collected.left_out(),
        "targets": targets,
    }


def manifest(run: Run, options: Options, names: list[str]) -> str:
    info = summary(run, options)
    lines = [
        f"dirsift detections for run {run.name}",
        f"target {defang(run.result.root_url)}",
        f"{options.tlp_label}",
        "Found in an open directory, not a verdict: hunt with it, decide yourself.",
        "The files carry live values: import them, do not open them in a browser.",
        "",
        "files:",
        *[f"  {name}" for name in names],
        "",
        "indicators:",
        *[f"  {kind}: {count}" for kind, count in info["types"].items()],
        "",
        "left out:",
        *[f"  {reason}: {count}" for reason, count in info["left_out"].items()],
    ]
    return "\n".join(lines) + "\n"


def zip_bytes(run: Run, options: Options, targets: list[Target]) -> bytes:
    """Every chosen target in one archive, with a manifest. Fixed timestamps, fixed order."""
    buffer = io.BytesIO()
    names = []
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for target in targets:
            if target.needs_pick and not options.pick:
                continue
            name = filename(run, target)
            names.append(name)
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, render(target, run, options).encode("utf-8"))
        info = zipfile.ZipInfo("MANIFEST.txt", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, manifest(run, options, names).encode("utf-8"))
    return buffer.getvalue()
