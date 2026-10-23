"""Suricata IDS rules, with the IP rules also readable by Snort 3.

Syntax from the Suricata rule pages under https://docs.suricata.io/en/latest/rules/
(intro, meta, payload-keywords, transforms, dns-keywords, tls-keywords,
http-keywords):

- ``;`` and ``"`` must be escaped with a backslash in an option value, and so
  must the backslash itself; that is how ``msg`` is written.
- inside ``content`` the page lists ``"`` ``;`` ``:`` and ``|`` as characters
  to write in hex between pipes (``|22|`` ``|3B|`` ``|3A|`` ``|7C|``). Those,
  the backslash, and every byte outside printable ASCII are written that way.
- ``dns.query`` and ``tls.sni`` are sticky buffers; ``dotprefix`` puts a dot
  in front of the buffer, so ``content:".example.com"; endswith;`` matches the
  name and its subdomains and nothing else.
- ``http.host`` is lower case and holds no port, so it takes no ``nocase``;
  ``http.uri.raw`` is the path and query as sent.
- ``sid`` 1000000 to 1999999 is reserved for local use (https://sidallocation.org/,
  and the Snort 3 sid page). ``classtype:trojan-activity`` is in the
  classification.config both engines ship.

The IP rules use only ``msg``, ``classtype``, ``sid`` and ``rev`` on an
``alert ip`` header, which the Snort 3 rule pages (https://docs.snort.org/rules/)
also document; the DNS, TLS and HTTP rules use Suricata keywords only.

A sid is derived from the indicator and the rule, so the same indicator gets
the same sid in every run; two indicators that land on the same number move
to the next free one, in the fixed order of the file.
"""

from __future__ import annotations

import hashlib
import ipaddress
from urllib.parse import urlsplit

from .collect import collect
from .meta import Run, commented, header
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url")

ASSUMES = [
    "Suricata 7 or later with HOME_NET set; the alert ip rules also read in Snort 3",
]

SID_BASE = 1000000
SID_SPAN = 1000000

#: How much of a value a msg quotes; the rest is cut and marked, the match keeps it whole.
MSG_VALUE_LIMIT = 200
MSG_CUT = "...(cut)"
#: Suricata stops reading a rule line at about 8 KB (``suricata -T`` fails past it), so
#: a longer rule is left out and counted, with room to spare.
MAX_RULE_BYTES = 7900
#: Suricata 8.0.3 built with Hyperscan stops loading a rule whose content is
#: past about 4000 bytes (measured with ``suricata -T``), so a longer one is
#: left out the same way.
MAX_CONTENT_BYTES = 3500

#: Characters a content match writes in hex: the documented ones and the backslash.
_HEX_ALWAYS = frozenset('";:|\\')


def content(value: str) -> str:
    """A content string: printable ASCII as is, everything the rule language reserves in hex."""
    out = []
    for char in value:
        if char in _HEX_ALWAYS or not (" " <= char <= "~"):
            out.append("|" + " ".join(f"{byte:02X}" for byte in char.encode("utf-8")) + "|")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def msg_text(value: str) -> str:
    """A msg value: the backslash, the quote and the semicolon escaped, nothing unprintable."""
    printable = "".join(char if " " <= char <= "~" else "?" for char in value)
    escaped = printable.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")
    return '"' + escaped + '"'


def clip(value: str) -> str:
    """A value short enough to quote in a msg."""
    if len(value) <= MSG_VALUE_LIMIT:
        return value
    return value[:MSG_VALUE_LIMIT] + MSG_CUT


def address(value: str) -> str | None:
    """The address as a rule header takes it: an IPv6 zone id is dropped, a bad address is None."""
    try:
        return str(ipaddress.ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


class _Sids:
    """Hands out sids in the local range, derived from a key, unique within the file."""

    def __init__(self) -> None:
        self.used: set[int] = set()

    def take(self, key: str) -> int:
        number = int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16) % SID_SPAN
        while SID_BASE + number in self.used:
            number = (number + 1) % SID_SPAN
        self.used.add(SID_BASE + number)
        return SID_BASE + number


def _rule(header_line: str, message: str, body: list[str], sid: int) -> str:
    options = [f"msg:{msg_text(message)}", *body, "classtype:trojan-activity", f"sid:{sid}",
               "rev:1"]
    return f"{header_line} (" + "; ".join(options) + ";)"


def _url_parts(url: str) -> tuple[str, str] | None:
    """The host and the raw path with its query, or None when the link does not read."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return None
    if not host or not parts.netloc:
        return None
    rest = url[url.index(parts.netloc) + len(parts.netloc):].split("#", 1)[0]
    return host, rest


def render(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    show = options.show
    lines = commented(header(run, options, "dirsift Suricata rules", ASSUMES), "#")
    sids = _Sids()
    rules: list[str] = []
    tag = f"dirsift {clip(run.name)}"
    too_long = 0
    unreadable = 0

    def emit(into: list[str], rule: str) -> None:
        nonlocal too_long
        if len(rule.encode("utf-8")) > MAX_RULE_BYTES:
            too_long += 1
        else:
            into.append(rule)

    addresses = collected.of("ipv4", "ipv6")
    if addresses:
        rules.append("# addresses found in the directory")
    for item in addresses:
        plain = address(item.value)
        if plain is None:
            unreadable += 1
            continue
        emit(
            rules,
            _rule(
                f"alert ip $HOME_NET any -> {show(plain)} any",
                f"{tag} traffic to an address found in an open directory {show(plain)}",
                [],
                sids.take(f"ip|{plain}"),
            ),
        )

    domains = collected.of("domain")
    if domains:
        rules.append("# domains found in the directory, and their subdomains")
    for item in domains:
        name = show(item.value)
        dotted = content("." + name)
        for proto, buffer, flow, nocase, label in (
            ("dns", "dns.query", None, True, "DNS query for"),
            ("tls", "tls.sni", "flow:established,to_server", True, "TLS SNI for"),
            ("http", "http.host", "flow:established,to_server", False, "HTTP host for"),
        ):
            body = [flow] if flow else []
            body += [buffer, "dotprefix", f"content:{dotted}"]
            if nocase:
                body.append("nocase")
            body.append("endswith")
            emit(
                rules,
                _rule(
                    f"alert {proto} $HOME_NET any -> any any",
                    f"{tag} {label} a domain found in an open directory {clip(name)}",
                    body,
                    sids.take(f"{proto}|{item.value}"),
                ),
            )

    urls = collected.of("url")
    url_rules: list[str] = []
    skipped = 0
    for item in urls:
        parts = _url_parts(item.value)
        if parts is None:
            skipped += 1
            continue
        host, rest = parts
        if rest in ("", "/") or _is_ipv6(host):
            # The host level rules already cover a bare host; an IPv6 host is
            # covered by its address rule.
            skipped += 1
            continue
        shown_host, shown_rest = show(host), show(rest)
        if len(rest.encode("utf-8")) > MAX_CONTENT_BYTES:
            too_long += 1
            continue
        emit(
            url_rules,
            _rule(
                "alert http $HOME_NET any -> any any",
                f"{tag} HTTP request for a URL found in an open directory "
                f"{clip(show(item.value))}",
                [
                    "flow:established,to_server",
                    "http.host",
                    f"content:{content(shown_host.lower())}",
                    f"bsize:{len(shown_host.encode('utf-8'))}",
                    "http.uri.raw",
                    f"content:{content(shown_rest)}",
                    "startswith",
                ],
                sids.take(f"url|{item.value}"),
            ),
        )
    if url_rules:
        rules.append("# URLs found in the directory, host and path")
        rules += url_rules
    if unreadable:
        lines.append(f"# {unreadable} address(es) left out: a rule header cannot read them")
    if too_long:
        lines.append(
            f"# {too_long} rule(s) left out: longer than {MAX_RULE_BYTES} bytes or a content "
            f"over {MAX_CONTENT_BYTES} bytes, past what Suricata loads"
        )
    if skipped:
        lines.append(f"# {skipped} URL(s) without a path of their own: the host rules cover them")

    if not rules:
        lines.append("# no indicators left after filtering")
        return "\n".join(lines) + "\n"
    return "\n".join(lines) + "\n\n" + "\n".join(rules) + "\n"


def _is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False
