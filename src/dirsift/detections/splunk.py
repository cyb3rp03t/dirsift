"""Splunk searches over the Common Information Model data models.

One search per data model, each a block of its own: paste one at a time. The
fields are the CIM ones, so any add-on that maps its data to CIM answers:

- Network_Traffic: ``All_Traffic.dest_ip``
- Network_Resolution: ``DNS.query``
- Web: ``Web.url``, ``Web.url_domain`` and ``Web.dest``
- Endpoint: ``Processes.process_hash`` and ``Filesystem.file_hash``

``tstats`` reads accelerated data models; ``summariesonly=false`` lets it fall
back to raw events where a model is not accelerated, at the cost of speed.
Hash fields often hold several digests in one value (``SHA256=...,MD5=...``),
so hashes are matched with wildcards on both sides. Comments use Splunk's
triple backtick syntax.
"""

from __future__ import annotations

from .blocklist import without_scheme
from .collect import collect
from .meta import Run, header
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "sha256", "md5")

ASSUMES = [
    "Splunk CIM data models Network_Traffic, Network_Resolution, Web and Endpoint",
]


def spl_string(value: str) -> str:
    """A value in double quotes, with the backslash and the quote escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _comment(lines: list[str]) -> str:
    return "\n".join("``` " + line.replace("```", "'''") + " ```" for line in lines)


def _any(field: str, values: list[str]) -> str:
    return "(" + " OR ".join(f"{field}={spl_string(value)}" for value in values) + ")"


def render(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    show = options.show
    blocks = [_comment(header(run, options, "dirsift Splunk searches (SPL)", ASSUMES))]
    tail = "min(_time) as first_seen max(_time) as last_seen"

    addresses = [show(item.value) for item in collected.of("ipv4", "ipv6")]
    if addresses:
        blocks.append(
            _comment(["1. connections to addresses found in the directory (Network_Traffic)"])
            + "\n| tstats summariesonly=false count "
            + tail
            + " from datamodel=Network_Traffic where "
            + _any("All_Traffic.dest_ip", addresses)
            + " by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port"
        )

    domains = [show(item.value) for item in collected.of("domain")]
    if domains:
        names = domains + ["*." + value for value in domains]
        blocks.append(
            _comment(["2. DNS lookups of domains found in the directory (Network_Resolution)"])
            + "\n| tstats summariesonly=false count "
            + tail
            + " from datamodel=Network_Resolution where "
            + _any("DNS.query", names)
            + " by DNS.src DNS.query"
        )

    urls = [show(without_scheme(item.value)) for item in collected.of("url")]
    if domains or urls:
        terms = []
        if domains:
            terms += [_any("Web.url_domain", domains), _any("Web.dest", domains)]
        if urls:
            terms.append(_any("Web.url", ["*" + value + "*" for value in urls]))
        blocks.append(
            _comment(["3. web requests to hosts and URLs found in the directory (Web)"])
            + "\n| tstats summariesonly=false count "
            + tail
            + " from datamodel=Web where "
            + " OR ".join(terms)
            + " by Web.src Web.dest Web.url"
        )

    digests = [item.value for item in collected.of("sha256", "md5")]
    if digests:
        wild = ["*" + value + "*" for value in digests]
        blocks.append(
            _comment(["4. processes started from files read whole in the directory (Endpoint)"])
            + "\n| tstats summariesonly=false count "
            + tail
            + " from datamodel=Endpoint.Processes where "
            + _any("Processes.process_hash", wild)
            + " by Processes.dest Processes.process_name Processes.process_hash"
        )
        blocks.append(
            _comment(["5. the same files written to disk (Endpoint Filesystem)"])
            + "\n| tstats summariesonly=false count "
            + tail
            + " from datamodel=Endpoint.Filesystem where "
            + _any("Filesystem.file_hash", wild)
            + " by Filesystem.dest Filesystem.file_name Filesystem.file_hash"
        )

    if len(blocks) == 1:
        blocks[0] += "\n" + _comment(["no indicators left after filtering"])
    return "\n\n".join(blocks) + "\n"
