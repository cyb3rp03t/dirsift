"""Candidate block lists: one value per line, one type per file.

Palo Alto external dynamic lists, Fortinet threat feeds, Check Point, Cisco
Security Intelligence and pfSense or OPNsense URL table aliases all read a plain
list with one value per line, and none of them takes two types in one list.
What they disagree on is the comment, so the profile picks it:

- generic: whole lines starting with ``#`` (the FortiOS 7.4 threat feed guide
  allows these).
- paloalto: the comment on the same line as the first value, after a space
  (the PAN-OS 11.1 formatting guidelines require that; a line holding only a
  comment is not documented).
- bare: no comment at all. The label then travels only in the file name.

URLs are written without the scheme: PAN-OS asks for it to be left out and
FortiOS strips it anyway. A domain is written as found; PAN-OS does not widen
it to subdomains unless the list is set to.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .collect import collect
from .meta import Run, commented, header
from .options import Options

#: The indicator types each list carries.
LISTS = {
    "ipv4": ("ipv4",),
    "ipv6": ("ipv6",),
    "domain": ("domain",),
    "url": ("url",),
    "sha256": ("sha256",),
}

ASSUMES = {
    "ipv4": "an IP list (Palo Alto EDL IP, Fortinet IP feed, pfSense alias)",
    "ipv6": "an IP list that takes IPv6 (Palo Alto EDL IP, Fortinet IP feed)",
    "domain": "a domain list matched exactly, subdomains not widened",
    "url": "a URL list without the scheme (Palo Alto EDL URL, Fortinet URL feed)",
    "sha256": "a file hash list (Fortinet malware hash feed)",
}


def without_scheme(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        # A host that does not read still loses its scheme.
        return url.split("://", 1)[-1]
    return url[len(parts.scheme) + 3 :] if parts.scheme and "://" in url else url


def render_list(kind: str, run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    values = []
    for item in collected.of(*LISTS[kind]):
        value = without_scheme(item.value) if kind == "url" else item.value
        values.append(options.show(value))
    title = f"dirsift candidate block list, {kind}"
    lines = header(run, options, title, [ASSUMES[kind]])
    if not values:
        lines.append("no indicators left after filtering")

    if options.profile == "bare":
        body = values
    elif options.profile == "paloalto":
        summary = f"# {title} | run {run.name} | {options.tlp_label} | not a verdict"
        body = [values[0] + " " + summary] + values[1:] if values else []
    else:
        body = commented(lines, "#") + values
    return "\n".join(body) + "\n" if body else ""
