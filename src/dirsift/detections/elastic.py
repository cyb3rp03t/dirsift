r"""Elastic Security: ES|QL hunting queries, and detection rules to import.

Field names are the Elastic Common Schema ones, so any integration that maps
its data to ECS answers: ``destination.ip``, ``dns.question.name``,
``url.domain``, ``url.full``, ``file.hash.sha256``, ``file.hash.md5``,
``process.hash.sha256`` and ``process.hash.md5``.

ES|QL (the hunting file). Syntax from
https://www.elastic.co/docs/reference/query-languages/esql/esql-syntax and the
operator and function pages under it:

- a string literal sits in double quotes; a quote inside is written ``\"``,
  a backslash ``\\`` (the LIKE page gives ``"foo \\* bar"`` and the triple
  quoted ``foo \* bar`` as the same pattern), and CR, LF and TAB as ``\r``,
  ``\n`` and ``\t``.
- ``IN`` takes a list of literals or expressions; addresses go through
  ``TO_IP`` so no implicit cast is relied on.
- ``ENDS_WITH`` matches the subdomains; ``//`` starts a comment.
- ES|QL stops with an error on a column no index in ``FROM`` maps, so every
  block asks about one field family and runs alone.

Detection rules (the NDJSON file), one rule per line, from the Kibana create
rule API (https://www.elastic.co/docs/api/doc/kibana/operation/operation-createrule)
that the import API (operation-importrules) reads as an ``.ndjson`` file.
Each rule is a custom query rule in KQL; the KQL page
(https://www.elastic.co/docs/reference/query-languages/kql) says that inside
quotation marks only the quote and the backslash are escaped, and an asterisk
is a literal asterisk. Rules are imported disabled: an analyst turns them on.
The default security indices are used, because ``index`` is left out.
"""

from __future__ import annotations

import json

from .collect import collect
from .meta import AUTHOR, NOT_A_VERDICT, Run, commented, header, stable_uuid
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "sha256", "md5")

ESQL_ASSUMES = [
    "ECS fields in a logs-* index pattern (destination.ip, dns.question.name, url.domain, "
    "url.full, file.hash.*, process.hash.*); change FROM to your own pattern",
    "a 30 day window; each block runs alone, so a field your data lacks fails only its block",
]

RULE_ASSUMES = [
    "Kibana detection rule import (NDJSON, one custom query rule per line, KQL)",
    "ECS fields; the rules are imported disabled and read the default security indices",
]

INDEX = "logs-*"
WINDOW = "30 days"


def esql_string(value: str) -> str:
    """An ES|QL string literal in double quotes."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )
    return '"' + escaped + '"'


def kql_value(value: str) -> str:
    """A Kibana KQL value in quotation marks: only the quote and the backslash are escaped."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _values(collected, options: Options, *kinds: str) -> list[str]:
    return [options.show(item.value) for item in collected.of(*kinds)]


def render_esql(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    top = header(run, options, "dirsift Elastic ES|QL hunting queries", ESQL_ASSUMES)
    blocks = ["\n".join(commented(top, "//"))]

    def block(title: str, where: str) -> None:
        blocks.append(
            "\n".join(
                [
                    f"// {title}",
                    f"FROM {INDEX}",
                    f"| WHERE @timestamp > NOW() - {WINDOW}",
                    f"| WHERE {where}",
                    "| SORT @timestamp DESC",
                    "| LIMIT 1000",
                ]
            )
        )

    addresses = _values(collected, options, "ipv4", "ipv6")
    if addresses:
        listed = ", ".join(f"TO_IP({esql_string(value)})" for value in addresses)
        block("connections to addresses found in the directory", f"destination.ip IN ({listed})")

    domains = _values(collected, options, "domain")
    if domains:
        exact = ", ".join(esql_string(value) for value in domains)
        under = " OR ".join(
            f"ENDS_WITH(dns.question.name, {esql_string('.' + value)})" for value in domains
        )
        block(
            "DNS lookups of domains found in the directory, and their subdomains",
            f"dns.question.name IN ({exact}) OR {under}",
        )
        under = " OR ".join(
            f"ENDS_WITH(url.domain, {esql_string('.' + value)})" for value in domains
        )
        block(
            "web requests to hosts found in the directory, and their subdomains",
            f"url.domain IN ({exact}) OR {under}",
        )

    urls = _values(collected, options, "url")
    if urls:
        listed = ", ".join(esql_string(value) for value in urls)
        block("web requests to URLs found in the directory, matched whole",
              f"url.full IN ({listed})")

    for kind in ("sha256", "md5"):
        digests = [item.value for item in collected.of(kind)]
        if not digests:
            continue
        listed = ", ".join(esql_string(value) for value in digests)
        block(f"files read whole in the directory, by {kind}", f"file.hash.{kind} IN ({listed})")
        block(
            f"processes started from those files, by {kind}",
            f"process.hash.{kind} IN ({listed})",
        )

    if len(blocks) == 1:
        blocks[0] += "\n// no indicators left after filtering"
    return "\n\n".join(blocks) + "\n"


def _any(field: str, values: list[str]) -> str:
    return f"{field}: (" + " or ".join(kql_value(value) for value in values) + ")"


def _rule(run: Run, options: Options, key: str, name: str, query: str) -> dict:
    about = (
        f"Indicators from an open directory walked by dirsift, run {run.name}. "
        f"{NOT_A_VERDICT} {options.tlp_label}."
    )
    return {
        "rule_id": stable_uuid(run, options, "elastic-rule", key),
        "name": f"dirsift {run.name}: {name}",
        "description": about,
        "type": "query",
        "language": "kuery",
        "query": query,
        "risk_score": 47,
        "severity": "medium",
        "enabled": False,
        "from": "now-6m",
        "interval": "5m",
        "max_signals": 100,
        "version": 1,
        "author": [AUTHOR],
        "tags": ["dirsift", options.tlp_label, "Threat Hunting"],
        "false_positives": ["Shared or reused infrastructure; check the source before acting"],
        "references": [],
        "threat": [],
    }


def render_rules(run: Run, options: Options) -> str:
    """One rule per line. An empty run gives an empty file: there is no comment syntax."""
    collected = collect(run.result, options)
    rules = []

    addresses = _values(collected, options, "ipv4", "ipv6")
    if addresses:
        rules.append(
            _rule(run, options, "network", "addresses in network events",
                  _any("destination.ip", addresses))
        )

    domains = _values(collected, options, "domain")
    if domains:
        rules.append(
            _rule(run, options, "dns", "domains in DNS questions",
                  _any("dns.question.name", domains))
        )

    urls = _values(collected, options, "url")
    if domains or urls:
        terms = []
        if domains:
            terms += [_any("url.domain", domains), _any("destination.domain", domains)]
        if urls:
            terms.append(_any("url.full", urls))
        rules.append(_rule(run, options, "web", "hosts and URLs in web events", " or ".join(terms)))

    terms = []
    for kind in ("sha256", "md5"):
        digests = [item.value for item in collected.of(kind)]
        if digests:
            terms += [_any(f"file.hash.{kind}", digests), _any(f"process.hash.{kind}", digests)]
    if terms:
        rules.append(_rule(run, options, "hashes", "file hashes", " or ".join(terms)))

    return "".join(json.dumps(rule, ensure_ascii=True) + "\n" for rule in rules)
