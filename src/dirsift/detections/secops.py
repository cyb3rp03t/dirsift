r"""Google SecOps (Chronicle): YARA-L 2.0 rules over UDM fields.

Syntax from the YARA-L pages under https://docs.cloud.google.com/chronicle/docs/yara-l/
(meta-syntax, events-syntax, condition-syntax, expressions, functions) and the
UDM field list at https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list:

- a rule is ``rule name { meta: events: condition: }``; meta values are double
  quoted strings, ``condition: $e`` asks for at least one matching event.
- predicates on separate lines are joined with ``and``; ``or`` chains are
  grouped in parentheses, which the expressions page shows.
- a double quoted string takes escape sequences, and a backslash is written
  ``\\`` (the page writes ``".*altostrat\\.com"``). A back quoted string is
  read literally. The page does not say how a double quote is escaped, so a
  value holding one is back quoted, and a value holding a double quote and a
  back quote both is left out and counted. ``\t`` is the documented tab; no
  escape is documented for a line break, so a value with a CR or an LF is left
  out and counted as well.
- ``nocase`` follows a comparison on a string field or a regular expression;
  regular expressions sit between slashes.
- ``strings.contains(str, substr)`` is in the functions list.
- UDM fields: ``target.ip``, ``network.dns.questions.name``,
  ``target.hostname``, ``target.url``, ``target.file.sha256`` and ``md5``,
  ``target.process.file.sha256`` and ``md5``.

Each rule holds one event variable and one family of indicators, so any one
of them can be saved alone. The expressions page warns that the number of
``or`` terms a rule may hold has a limit that depends on the account; a run
with very many indicators may need its rule split by hand.
"""

from __future__ import annotations

import re

from .blocklist import without_scheme
from .collect import collect
from .meta import AUTHOR, NOT_A_VERDICT, Run, commented, header, slug
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "sha256", "md5")

ASSUMES = [
    "UDM events (target.ip, network.dns.questions.name, target.hostname, target.url, "
    "target.file and target.process.file hashes)",
]

#: A host name a regular expression may carry without any escaping beyond the dot.
_PLAIN_HOST = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")


def yaral_string(value: str) -> str | None:
    """A YARA-L string literal, or None when no documented quoting can hold it.

    The page documents ``\\t`` for a tab inside double quotes, and no escape for
    a line break, so a value with a CR or an LF is left out, and so is a value
    with a tab that needs back quotes (they read every character literally).
    """
    if "\r" in value or "\n" in value:
        return None
    if '"' not in value:
        return '"' + value.replace("\\", "\\\\").replace("\t", "\\t") + '"'
    if "`" not in value and "\t" not in value:
        return "`" + value + "`"
    return None


def meta_text(value: str) -> str:
    """Free text for a meta value: quotes and backslashes are dropped, not escaped."""
    text = "".join(char if char >= " " else " " for char in value)
    return '"' + text.replace("\\", "/").replace('"', "'") + '"'


def host_regex(host: str) -> str:
    """The host and its subdomains, anchored, as a YARA-L regular expression."""
    return "/(^|\\.)" + host.replace(".", "\\.") + "$/"


def _rule(run: Run, options: Options, part: str, title: str, events: list[str]) -> list[str]:
    name = f"dirsift_{slug(run.name)}_{part}"
    return [
        f"rule {name} {{",
        "  meta:",
        f"    author = {meta_text(AUTHOR)}",
        f"    description = {meta_text(f'{title}. dirsift run {run.name}. {NOT_A_VERDICT}')}",
        f"    tlp = {meta_text(options.tlp_label)}",
        '    severity = "MEDIUM"',
        "  events:",
        *[f"    {line}" for line in events],
        "  condition:",
        "    $e",
        "}",
    ]


def _either(terms: list[str]) -> str:
    return "(" + " or ".join(terms) + ")" if len(terms) > 1 else terms[0]


def render(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    show = options.show
    lines = commented(header(run, options, "dirsift YARA-L 2.0 rules (Google SecOps)", ASSUMES),
                      "//")
    rules: list[list[str]] = []
    left_out: set[str] = set()

    def quoted(values: list[str]) -> list[str]:
        out = []
        for value in values:
            literal = yaral_string(value)
            if literal is None:
                left_out.add(value)
            else:
                out.append(literal)
        return out

    addresses = quoted([show(item.value) for item in collected.of("ipv4", "ipv6")])
    if addresses:
        rules.append(
            _rule(run, options, "network", "Addresses found in an open directory",
                  [_either([f"$e.target.ip = {value}" for value in addresses])])
        )

    plain, odd = [], []
    for item in collected.of("domain"):
        (plain if _PLAIN_HOST.match(item.value) else odd).append(item.value)
    domain_terms = [f"$e.network.dns.questions.name = {host_regex(show(v))} nocase" for v in plain]
    domain_terms += [f"$e.network.dns.questions.name = {value} nocase"
                     for value in quoted([show(v) for v in odd])]
    if domain_terms:
        rules.append(
            _rule(run, options, "dns", "Domains found in an open directory, and their subdomains",
                  ['$e.metadata.event_type = "NETWORK_DNS"', _either(domain_terms)])
        )

    web_terms = [f"$e.target.hostname = {host_regex(show(v))} nocase" for v in plain]
    web_terms += [f"$e.target.hostname = {value} nocase"
                  for value in quoted([show(v) for v in odd])]
    web_terms += [
        f"strings.contains($e.target.url, {value})"
        for value in quoted([show(without_scheme(item.value)) for item in collected.of("url")])
    ]
    if web_terms:
        rules.append(
            _rule(run, options, "web", "Hosts and URLs found in an open directory",
                  [_either(web_terms)])
        )

    hash_terms = []
    for kind in ("sha256", "md5"):
        for item in collected.of(kind):
            literal = '"' + item.value + '"'
            hash_terms.append(f"$e.target.file.{kind} = {literal} nocase")
            hash_terms.append(f"$e.target.process.file.{kind} = {literal} nocase")
    if hash_terms:
        rules.append(
            _rule(run, options, "hashes", "Files read whole in an open directory",
                  [_either(hash_terms)])
        )

    if left_out:
        lines.append(
            f"// {len(left_out)} value(s) left out: no documented quoting holds them "
            "(both quote kinds, or a line break)"
        )
    if not rules:
        lines.append("// no indicators left after filtering")
        return "\n".join(lines) + "\n"
    return "\n".join(lines) + "\n\n" + "\n\n".join("\n".join(rule) for rule in rules) + "\n"
