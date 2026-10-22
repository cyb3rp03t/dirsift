"""Hunting queries for Microsoft Defender XDR and Microsoft Sentinel (KQL).

Each query is one block with no blank line inside it, because both consoles
run the query under the cursor and a blank line ends it. Every block carries
its own ``let`` lists, so any one of them runs alone.

Tables and columns, from the Microsoft Learn schema pages:

- Defender XDR advanced hunting: ``DeviceNetworkEvents`` (``RemoteIP``,
  ``RemoteUrl``), ``DeviceFileEvents`` and ``DeviceProcessEvents`` (``SHA256``,
  ``MD5``; Microsoft notes ``SHA256`` is often empty, so MD5 is matched too),
  ``EmailUrlInfo`` (``Url``, ``UrlDomain``).
- Sentinel: ``CommonSecurityLog`` (``DestinationIP``, ``DestinationHostName``,
  ``RequestURL``) and ``DnsEvents`` (``Name``).

``has_any`` matches whole terms without regard to case, so a domain matches
inside a URL or a subdomain; ``in~`` compares hashes without regard to case.
"""

from __future__ import annotations

from .blocklist import without_scheme
from .collect import collect
from .meta import Run, commented, header
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "sha256", "md5")

ASSUMES = [
    "Defender XDR advanced hunting tables (DeviceNetworkEvents, DeviceFileEvents, "
    "DeviceProcessEvents, EmailUrlInfo) and Sentinel tables (CommonSecurityLog, DnsEvents)",
    "a 30 day window (Defender advanced hunting keeps 30 days)",
]


def kql_string(value: str) -> str:
    """A KQL string literal in double quotes, backslash and quote escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _let(name: str, values: list[str]) -> str:
    return f"let {name} = dynamic([" + ", ".join(kql_string(value) for value in values) + "]);"


def render(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    show = options.show
    addresses = [show(item.value) for item in collected.of("ipv4", "ipv6")]
    domains = [show(item.value) for item in collected.of("domain")]
    urls = [show(without_scheme(item.value)) for item in collected.of("url")]
    sha256 = [item.value for item in collected.of("sha256")]
    md5 = [item.value for item in collected.of("md5")]

    top = header(run, options, "dirsift KQL hunting queries", ASSUMES)
    blocks = ["\n".join(commented(top, "//"))]

    def block(title: str, lines: list[str]) -> None:
        blocks.append("\n".join([f"// {title}", *lines]))

    if addresses or domains:
        lets, terms = [], []
        if addresses:
            lets.append(_let("dirsift_ip", addresses))
            terms.append("RemoteIP in (dirsift_ip)")
        if domains:
            lets.append(_let("dirsift_domain", domains))
            terms.append("RemoteUrl has_any (dirsift_domain)")
        block(
            "Defender XDR: devices that connected to addresses or hosts found in the directory",
            lets
            + [
                "DeviceNetworkEvents",
                "| where Timestamp > ago(30d)",
                "| where " + " or ".join(terms),
                "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, "
                "RemotePort, RemoteUrl, ActionType",
            ],
        )

    if sha256 or md5:
        lets, terms = [], []
        if sha256:
            lets.append(_let("dirsift_sha256", sha256))
            terms.append("SHA256 in~ (dirsift_sha256)")
        if md5:
            lets.append(_let("dirsift_md5", md5))
            terms.append("MD5 in~ (dirsift_md5)")
        for table, columns in (
            (
                "DeviceFileEvents",
                "Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5",
            ),
            (
                "DeviceProcessEvents",
                "Timestamp, DeviceName, FolderPath, FileName, ProcessCommandLine, SHA256, MD5",
            ),
        ):
            block(
                f"Defender XDR: {table} for files read whole in the directory",
                lets
                + [
                    table,
                    "| where Timestamp > ago(30d)",
                    "| where " + " or ".join(terms),
                    "| project " + columns,
                ],
            )

    if domains or urls:
        lets, terms = [], []
        if domains:
            lets.append(_let("dirsift_domain", domains))
            terms.append("UrlDomain in~ (dirsift_domain)")
        if urls:
            lets.append(_let("dirsift_url", urls))
            terms.append("Url has_any (dirsift_url)")
        block(
            "Defender XDR: mail that carried hosts or URLs found in the directory",
            lets
            + [
                "EmailUrlInfo",
                "| where Timestamp > ago(30d)",
                "| where " + " or ".join(terms),
                "| project Timestamp, NetworkMessageId, Url, UrlDomain",
            ],
        )

    if addresses or domains or urls:
        lets, terms = [], []
        if addresses:
            lets.append(_let("dirsift_ip", addresses))
            terms.append("DestinationIP in (dirsift_ip)")
        if domains:
            lets.append(_let("dirsift_domain", domains))
            terms.append("DestinationHostName has_any (dirsift_domain)")
            terms.append("RequestURL has_any (dirsift_domain)")
        if urls:
            lets.append(_let("dirsift_url", urls))
            terms.append("RequestURL has_any (dirsift_url)")
        block(
            "Sentinel: firewall and proxy events (CommonSecurityLog)",
            lets
            + [
                "CommonSecurityLog",
                "| where TimeGenerated > ago(30d)",
                "| where " + " or ".join(terms),
                "| project TimeGenerated, DeviceVendor, DeviceProduct, SourceIP, "
                "DestinationIP, DestinationHostName, RequestURL, DeviceAction",
            ],
        )

    if domains:
        block(
            "Sentinel: DNS queries for domains found in the directory (DnsEvents)",
            [
                _let("dirsift_domain", domains),
                "DnsEvents",
                "| where TimeGenerated > ago(30d)",
                "| where Name has_any (dirsift_domain)",
                "| project TimeGenerated, Computer, ClientIP, Name, IPAddresses",
            ],
        )

    if len(blocks) == 1:
        blocks[0] += "\n// no indicators left after filtering"
    return "\n\n".join(blocks) + "\n"
