r"""CrowdStrike Falcon LogScale and Next-Gen SIEM: CQL hunting queries.

Syntax from the CrowdStrike Query Language pages under
https://library.humio.com/crowdstrike-query-language/ (syntax-comments,
syntax-filters, functions-in) and the grammar subset at
https://library.humio.com/lql-grammar/syntax-grammar-guide-subset.html:

- ``//`` starts a comment; a step follows a ``|``.
- ``in(field=..., values=[...], ignoreCase=true)`` keeps an event whose field
  equals one of the values.
- a quoted string is written in double quotes; ``\"`` is a quote and ``\\``
  a backslash inside it, ``\n`` a line feed, and no other backslash sequence
  is recommended. A value with a carriage return or a tab is left out and
  counted.
- the grammar says ``*`` in a pattern is a wildcard that cannot be escaped. A
  value holding a ``*`` therefore matches a little more than itself; the file
  says how many do.

Fields. Falcon sensor events, as the queries in CrowdStrike's own
logscale-community-content repository read them: ``#event_simpleName`` with
``NetworkConnectIP4`` and ``NetworkConnectIP6`` (``RemoteAddressIP4``,
``RemoteAddressIP6``), ``DnsRequest`` (``DomainName``) and ``ProcessRollup2``
(``SHA256HashData``, ``MD5HashData``). Third party data in Next-Gen SIEM is
parsed to ECS style names, so ``destination.ip``, ``dns.question.name`` and
``url.original`` are asked as well. Each block is one query that runs alone.
"""

from __future__ import annotations

from .blocklist import without_scheme
from .collect import collect
from .meta import Run, commented, header
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "sha256", "md5")

ASSUMES = [
    "Falcon sensor events (NetworkConnectIP4/IP6, DnsRequest, ProcessRollup2) and ECS style "
    "fields for third party data in Next-Gen SIEM (destination.ip, dns.question.name, "
    "url.original)",
    "the time range is the one set in the search page",
]


def cql_string(value: str) -> str:
    """A CQL quoted string: the backslash and the quote escaped, a line feed as ``\\n``.

    Check ``cql_ok`` first: the grammar names no escape for a carriage return or a tab.
    """
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def cql_ok(value: str) -> bool:
    """Whether a value can be written as a CQL quoted string with a documented escape."""
    return "\r" not in value and "\t" not in value


def _in(field: str, values: list[str], ignore_case: bool = False) -> str:
    listed = ", ".join(cql_string(value) for value in values)
    case = ", ignoreCase=true" if ignore_case else ""
    return f"in(field={field}, values=[{listed}]{case})"


def render(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    show = options.show
    top = header(run, options, "dirsift CQL hunting queries (Falcon LogScale, Next-Gen SIEM)",
                 ASSUMES)
    blocks = ["\n".join(commented(top, "//"))]

    def block(title: str, lines: list[str]) -> None:
        blocks.append("\n".join([f"// {title}", *lines]))

    left_out: set[str] = set()

    def keep(values: list[str]) -> list[str]:
        out = []
        for value in values:
            if cql_ok(value):
                out.append(value)
            else:
                left_out.add(value)
        return out

    ipv4 = [show(item.value) for item in collected.of("ipv4")]
    ipv6 = [show(item.value) for item in collected.of("ipv6")]
    domains = keep([show(item.value) for item in collected.of("domain")])
    names = domains + ["*." + value for value in domains]
    urls = keep([show(without_scheme(item.value)) for item in collected.of("url")])
    sha256 = [item.value for item in collected.of("sha256")]
    md5 = [item.value for item in collected.of("md5")]

    if ipv4:
        block("Falcon: connections to IPv4 addresses found in the directory",
              ["#event_simpleName=NetworkConnectIP4", "| " + _in("RemoteAddressIP4", ipv4)])
    if ipv6:
        block("Falcon: connections to IPv6 addresses found in the directory",
              ["#event_simpleName=NetworkConnectIP6",
               "| " + _in("RemoteAddressIP6", ipv6, ignore_case=True)])
    if domains:
        block("Falcon: DNS requests for domains found in the directory, and their subdomains",
              ["#event_simpleName=DnsRequest", "| " + _in("DomainName", names, ignore_case=True)])
    if sha256 or md5:
        for field, values in (("SHA256HashData", sha256), ("MD5HashData", md5)):
            if values:
                block(f"Falcon: processes started from files read whole in the directory ({field})",
                      ["#event_simpleName=ProcessRollup2",
                       "| " + _in(field, values, ignore_case=True)])
    if ipv4 or ipv6:
        block("Next-Gen SIEM: third party events to addresses found in the directory",
              [_in("destination.ip", ipv4 + ipv6, ignore_case=True)])
    if domains:
        block("Next-Gen SIEM: third party DNS events for domains found in the directory",
              [_in("dns.question.name", names, ignore_case=True)])
    if urls:
        block("Next-Gen SIEM: third party web events for URLs found in the directory",
              [_in("url.original", ["*" + value + "*" for value in urls])])

    if left_out:
        blocks[0] += (
            f"\n// {len(left_out)} value(s) left out: a carriage return or a tab, "
            "which CQL strings have no escape for"
        )
    wild = sum(1 for value in urls if "*" in value)
    if wild:
        blocks[0] += f"\n// {wild} URL(s) hold a * that CQL reads as a wildcard"
    if len(blocks) == 1:
        blocks[0] += "\n// no indicators left after filtering"
    return "\n\n".join(blocks) + "\n"
