"""A DNS Response Policy Zone that answers NXDOMAIN for the domains found.

From the RPZ draft (https://datatracker.ietf.org/doc/html/draft-vixie-dnsop-dns-rpz-00):

- an RPZ is an ordinary zone: an SOA record with a serial, and at least one
  NS record at the apex, by convention the placeholder ``localhost.``.
- ``name CNAME .`` is the NXDOMAIN action; a name and its subdomains need two
  records, the name itself and ``*.name``.
- owner names are relative to the zone, so the file has no ``$ORIGIN``: the
  name the resolver configuration gives the zone is the origin.

Comments start with ``;`` (RFC 1035 master file format). The serial is the
scan's start as YYYYMMDDHH, so the same run always gives the same zone and a
later run gives a higher serial. Only names made of letters, digits, hyphens
and underscores in dot separated labels of at most 63 characters are written;
anything else is left out and counted, because a master file gives other
characters a meaning.
"""

from __future__ import annotations

import re

from .collect import collect
from .meta import Run, commented, header, started
from .options import Options

KINDS = ("domain",)

ASSUMES = [
    "a resolver with response policy zones (BIND, Unbound, Knot Resolver, PowerDNS Recursor); "
    "load the file as the zone and name the zone in the resolver configuration",
]

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
#: Room left for the zone's own name inside the 255 octet limit of a name.
MAX_NAME = 200
TTL = 300


def zone_name_ok(name: str) -> bool:
    """Whether a name can stand in the zone file as an owner name without escaping."""
    if not name or len(name) > MAX_NAME or name.endswith("."):
        return False
    return all(_LABEL.match(label) for label in name.split("."))


def serial(run: Run) -> str:
    return started(run).strftime("%Y%m%d%H")


def render(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    lines = commented(header(run, options, "dirsift DNS response policy zone (NXDOMAIN)",
                             ASSUMES), ";")
    names, left_out = [], 0
    for item in collected.of("domain"):
        if zone_name_ok(item.value):
            names.append(options.show(item.value))
        else:
            left_out += 1
    if left_out:
        lines.append(f"; {left_out} name(s) left out: characters a zone file would read as syntax")
    lines += [
        "",
        f"$TTL {TTL}",
        f"@ IN SOA localhost. hostmaster.localhost. ( {serial(run)} 3600 600 86400 {TTL} )",
        "@ IN NS localhost.",
    ]
    if not names:
        lines.append("; no indicators left after filtering")
    for name in names:
        lines += [f"{name} CNAME .", f"*.{name} CNAME ."]
    return "\n".join(lines) + "\n"
