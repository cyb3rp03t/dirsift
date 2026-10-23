"""IBM QRadar: AQL hunting searches, and reference set files to load.

AQL, from the QRadar AQL pages on https://www.ibm.com/docs (SS42VS / SSKMKU,
com.ibm.qradar.doc: c_qradar_aql_syntax, r_aql_operators,
r_aql_supported_functions, r_aql_start_stop):

- single quotes hold a string value; ``IN`` takes a list of them, IPv6
  included (the page's own example lists ``'::1'``).
- ``ILIKE`` matches without regard to case, with ``%`` as the wildcard.
- ``UTF8(payload)`` returns the event payload as text.
- ``LAST 7 DAYS`` sets the window; minutes, hours and days are the units.

The pages say nothing about writing a single quote inside a value, nor about
escaping ``%`` or ``_``, nor about comments. So a value holding a single quote,
a line break or a tab is left out and counted, a ``%`` or ``_`` inside a value stays a wildcard
(the search then matches a little more than the value), and every search is
one line of its own: the lines around it start with ``#`` and are notes for
the reader, not part of any search. Paste one search at a time into Advanced
Search.

Reference sets, from the reference data technote "Creating Reference Maps"
(https://public.dhe.ibm.com/software/security/products/qradar/documents/71MR2/QNAD/EN/Creating_Reference_Maps.pdf)
and the ReferenceDataUtil command reference: the file is CSV, a ``#`` in the
first column starts a comment line, the first other line is the column
header, and a set's one column is ``data``. Load it with
``./ReferenceDataUtil.sh load <set name> <file>``. The IP element type takes
IPv4 only, so the address set is meant for an ALN set. The technote shows no
quoting, so a value holding a comma, a quote or a line break is left out and
counted, and so is one that a spreadsheet would read as a formula.
"""

from __future__ import annotations

from .collect import collect
from .csvfeed import FORMULA_START
from .meta import Run, commented, header
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "sha256", "md5")

ASSUMES = [
    "QRadar events and flows (destinationip) and the event payload (UTF8(payload) ILIKE)",
    "a 7 day window; each search is one line, paste one at a time",
]

#: The reference set files: id suffix, label, kinds, and the element type to create the set with.
SETS = {
    "ip": ("IP addresses", ("ipv4", "ipv6"), "ALN"),
    "domain": ("domains", ("domain",), "ALNIC"),
    "url": ("URLs", ("url",), "ALN"),
    "hash": ("file hashes", ("sha256", "md5"), "ALNIC"),
}

WINDOW = "LAST 7 DAYS"


def aql_string(value: str) -> str | None:
    """A single quoted AQL value, or None when it holds a quote AQL cannot carry."""
    if any(char in value for char in ("'", "\n", "\r", "\t")):
        return None
    return "'" + value + "'"


def render_aql(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    show = options.show
    lines = commented(header(run, options, "dirsift QRadar AQL searches", ASSUMES), "#")
    searches: list[tuple[str, str]] = []
    left_out = 0

    def quoted(values: list[str]) -> list[str]:
        nonlocal left_out
        out = []
        for value in values:
            literal = aql_string(value)
            if literal is None:
                left_out += 1
            else:
                out.append(literal)
        return out

    addresses = quoted([show(item.value) for item in collected.of("ipv4", "ipv6")])
    if addresses:
        listed = ", ".join(addresses)
        for table in ("events", "flows"):
            searches.append(
                (
                    f"{table} to addresses found in the directory",
                    f"SELECT * FROM {table} WHERE destinationip IN ({listed}) {WINDOW}",
                )
            )

    for title, kinds in (
        ("event payloads that name domains found in the directory", ("domain",)),
        ("event payloads that carry URLs found in the directory", ("url",)),
        ("event payloads that carry hashes of files read whole in the directory",
         ("sha256", "md5")),
    ):
        values = [show(item.value) for item in collected.of(*kinds)]
        terms = [f"UTF8(payload) ILIKE {literal}" for literal in
                 quoted(["%" + value + "%" for value in values])]
        if terms:
            searches.append((title, f"SELECT * FROM events WHERE {' OR '.join(terms)} {WINDOW}"))

    if left_out:
        lines.append(
            f"# {left_out} value(s) left out: they hold a single quote, a line break or a tab"
        )
    if not searches:
        lines.append("# no indicators left after filtering")
        return "\n".join(lines) + "\n"
    body = []
    for number, (title, search) in enumerate(searches, start=1):
        body += ["", f"# {number}. {title}", search]
    return "\n".join(lines + body) + "\n"


def set_value_ok(value: str) -> bool:
    """Whether a value can stand on a line of the set file as it is."""
    if any(char in value for char in (",", '"', "'", "\n", "\r", "\t")):
        return False
    return not value.startswith(FORMULA_START) and not value.startswith("#") and value != "data"


def render_set(key: str, run: Run, options: Options) -> str:
    label, kinds, element = SETS[key]
    collected = collect(run.result, options)
    values, left_out = [], 0
    for item in collected.of(*kinds):
        if set_value_ok(item.value):
            values.append(options.show(item.value))
        else:
            left_out += 1
    title = f"dirsift QRadar reference set, {label}"
    assumes = [
        f"a reference set of element type {element}; load it with "
        f"./ReferenceDataUtil.sh load <set name> <this file>",
    ]
    lines = commented(header(run, options, title, assumes), "#")
    if left_out:
        lines.append(f"# {left_out} value(s) left out: a comma, a quote or a formula start")
    if not values:
        lines.append("# no indicators left after filtering")
    return "\n".join([*lines, "data", *values]) + "\n"
