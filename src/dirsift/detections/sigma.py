"""Sigma rules, written by hand: one rule per log source, in one rule collection.

Field names come from the Sigma taxonomy appendix where it defines them, and
from the conventions of the SigmaHQ rule repository where it does not:

- firewall: ``dst_ip`` (taxonomy).
- dns: ``query`` (the taxonomy lists the category without fields; the network
  rules in the SigmaHQ repository use ``query``).
- proxy: ``cs-host`` for the host and ``c-uri`` for the path (taxonomy; it
  prefers ``cs-host`` over ``r-dns``).
- process_creation: ``sha256`` and ``md5`` (taxonomy), and ``Hashes`` with
  ``SHA256=`` and ``MD5=`` (the Sysmon form SigmaHQ rules match on).

Values are quoted for YAML and escaped for Sigma, where ``*``, ``?`` and the
backslash are wildcard syntax. Identifiers are UUIDs derived from the run, so
the same run always gives the same rules.
"""

from __future__ import annotations

import uuid
from urllib.parse import urlsplit

from ..stix import DIRSIFT_NAMESPACE
from .collect import Indicator, collect
from .meta import AUTHOR, NOT_A_VERDICT, Run, commented, header
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "sha256", "md5")

ASSUMES = [
    "Sigma taxonomy log sources: firewall (dst_ip), dns (query), proxy (cs-host, c-uri), "
    "process_creation (sha256, md5, Hashes)",
]


def rule_id(run: Run, options: Options, kind: str) -> str:
    """A UUID with version 4 bits, determined entirely by the run and the rule."""
    key = f"sigma|{run.result.root_url}|{run.name}|{options.source or ''}|{kind}"
    derived = uuid.uuid5(DIRSIFT_NAMESPACE, key)
    return str(uuid.UUID(bytes=derived.bytes, version=4))


def sigma_value(value: str) -> str:
    """A value escaped for Sigma's wildcards, then quoted for YAML."""
    escaped = value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
    return "'" + escaped.replace("'", "''") + "'"


def yaml_text(value: str) -> str:
    """Plain text quoted for YAML, with no wildcard escaping."""
    return "'" + value.replace("'", "''") + "'"


def _list(field: str, values: list[str], indent: int = 8) -> list[str]:
    pad = " " * indent
    return [f"{pad}{field}:"] + [f"{pad}    - {sigma_value(value)}" for value in values]


def _rule(
    run: Run,
    options: Options,
    kind: str,
    title: str,
    description: str,
    logsource: str,
    detection: list[str],
    condition: str,
) -> list[str]:
    tlp = "tlp." + options.tlp.lower()
    return [
        f"title: {yaml_text(title)}",
        f"id: {rule_id(run, options, kind)}",
        "status: experimental",
        f"description: {yaml_text(description)}",
        f"author: {AUTHOR}",
        f"date: {run.result.started_at.strftime('%Y-%m-%d')}",
        "tags:",
        f"    - {tlp}",
        "    - detection.threat-hunting",
        "logsource:",
        f"    category: {logsource}",
        "detection:",
        *detection,
        f"    condition: {condition}",
        "falsepositives:",
        "    - Shared or reused infrastructure; check the source before acting",
        "level: medium",
    ]


def _shown(items: list[Indicator], options: Options) -> list[str]:
    return [options.show(item.value) for item in items]


def render(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    name = run.name
    lines = commented(header(run, options, "dirsift Sigma rule collection", ASSUMES), "#")
    rules: list[list[str]] = []
    about = f"Indicators from an open directory walked by dirsift, run {name}. {NOT_A_VERDICT}"

    addresses = _shown(collected.of("ipv4", "ipv6"), options)
    if addresses:
        rules.append(
            ["# log source: firewall or network connection logs with the destination in dst_ip"]
            + _rule(
                run, options, "firewall",
                f"dirsift {name} addresses in network connections",
                about, "firewall",
                ["    selection:", *_list("dst_ip", addresses)],
                "selection",
            )
        )

    domains = _shown(collected.of("domain"), options)
    if domains:
        rules.append(
            ["# log source: DNS query logs (resolver, DNS server or network sensor), name in query"]
            + _rule(
                run, options, "dns",
                f"dirsift {name} domains in DNS queries",
                about, "dns",
                [
                    "    selection_exact:",
                    *_list("query", domains),
                    "    selection_subdomain:",
                    *_list("query|endswith", ["." + value for value in domains]),
                ],
                "1 of selection_*",
            )
        )

    urls = collected.of("url")
    if domains or urls:
        detection: list[str] = []
        if domains:
            detection += [
                "    selection_host:",
                *_list("cs-host", domains),
                "    selection_subdomain:",
                *_list("cs-host|endswith", ["." + value for value in domains]),
            ]
        for number, item in enumerate(urls, start=1):
            try:
                parts = urlsplit(item.value)
                path = item.value[item.value.index(parts.netloc) + len(parts.netloc) :] or "/"
                host = parts.hostname or ""
            except ValueError:
                # A link whose host does not read gives no rule line.
                continue
            detection += [f"    url_{number}:", *_list("cs-host", [options.show(host)])]
            if path not in ("", "/"):
                detection += _list("c-uri|contains", [options.show(path)])
        condition = " or ".join(
            part
            for part, present in (("1 of selection_*", bool(domains)), ("1 of url_*", bool(urls)))
            if present
        )
        rules.append(
            ["# log source: web proxy logs with the host in cs-host and the path in c-uri"]
            + _rule(
                run, options, "proxy",
                f"dirsift {name} hosts and URLs in proxy logs",
                about, "proxy",
                detection, condition,
            )
        )

    sha256 = [item.value for item in collected.of("sha256")]
    md5 = [item.value for item in collected.of("md5")]
    if sha256 or md5:
        detection = []
        if sha256:
            detection += ["    selection_sha256:", *_list("sha256", sha256)]
        if md5:
            detection += ["    selection_md5:", *_list("md5", md5)]
        sysmon = ["SHA256=" + value.upper() for value in sha256] + [
            "MD5=" + value.upper() for value in md5
        ]
        detection += ["    selection_sysmon:", *_list("Hashes|contains", sysmon)]
        rules.append(
            [
                "# log source: process creation with hashes (EDR, or Sysmon event 1 hashing)",
                "# only files the scan read whole have a hash",
            ]
            + _rule(
                run, options, "process_creation",
                f"dirsift {name} file hashes in process creation",
                about, "process_creation",
                detection, "1 of selection_*",
            )
        )

    if not rules:
        lines.append("# no indicators left after filtering")
        return "\n".join(lines) + "\n"
    body = "\n---\n".join("\n".join(rule) for rule in rules)
    return "\n".join(lines) + "\n" + body + "\n"
