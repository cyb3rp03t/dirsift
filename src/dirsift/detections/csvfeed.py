"""A generic CSV for the list and feed import screens of SOAR and TIP products.

CSV has no comment syntax, so nothing but the header row precedes the data:
the label and the run travel in their own columns on every row. There is no
``sep=`` line and no byte order mark: importers would read either as data.

A CSV is also opened in spreadsheets, and a cell that starts with ``=``, ``+``,
``-``, ``@``, a tab or a carriage return is run there as a formula. File names,
URLs and the run name come from someone else's server, so two things are done:

* A cell that starts with one of those gets a leading apostrophe (the OWASP
  CSV injection advice), and every cell is quoted.
* Quoting is not enough on its own. A spreadsheet set to a ``;`` list
  separator (the Turkish and most European defaults) splits the row on ``;``
  and ignores the quotes, so ``a;=1+1;b.txt`` becomes a cell that starts with
  ``=``. A cell that holds a separator (``;``, ``,``, a tab, a line break) and
  a formula character anywhere is percent-encoded: ``%`` becomes ``%25``,
  ``;`` ``%3B``, ``,`` ``%2C``, tab ``%09``, CR ``%0D`` and LF ``%0A``. After
  that no separator is left inside it, so no split can start a formula.

The ``escaped`` column names what was changed, separated by spaces: ``value``
for a leading apostrophe, ``value:pct`` for percent-encoding. An importer
strips exactly one leading ``'`` from the first, then percent-decodes the
second, and gets the value back byte for byte. Percent-encoding is already a
valid way to write a URL, and the file paths come from URLs. None of the
columns is numeric, so a cell that looks like a negative number is text here
and is escaped like the rest.
"""

from __future__ import annotations

import csv
import io

from .collect import collect
from .meta import Run
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "email", "sha256", "md5")

COLUMNS = ("type", "value", "source_file", "first_seen", "tlp", "run", "label", "escaped")

ASSUMES = [
    "a CSV import with a header row; several source files are joined with ' | '",
    "cells a spreadsheet would run as a formula start with ' and are named in escaped",
    "cells with a separator and a formula character are percent-encoded, named as column:pct",
]

#: What a spreadsheet takes for the start of a formula.
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

#: What a spreadsheet may split a row on, whatever the file says.
SEPARATORS = (";", ",", "\t", "\r", "\n")

#: Percent-encoding for a cell that holds both. ``%`` goes first so the
#: encoding can be undone by any percent-decoder.
PERCENT = (("%", "%25"), (";", "%3B"), (",", "%2C"), ("\t", "%09"), ("\r", "%0D"), ("\n", "%0A"))

#: How several source files are joined into one cell.
JOIN = " | "


def safe_cell(value: str) -> tuple[str, bool]:
    """The cell as written, and whether it had to be escaped."""
    if value.startswith(FORMULA_START):
        return "'" + value, True
    return value, False


def needs_percent(value: str) -> bool:
    """Whether a split on some separator could leave a piece that starts a formula.

    Fails closed: any separator together with any formula character anywhere
    in the cell, and every tab or line break, whatever surrounds it.
    """
    if any(char in value for char in ("\t", "\r", "\n")):
        return True
    return any(char in value for char in (";", ",")) and any(
        char in value for char in ("=", "+", "-", "@")
    )


def percent(value: str) -> str:
    for char, code in PERCENT:
        value = value.replace(char, code)
    return value


def neutral_cell(column: str, value: str) -> tuple[str, list[str]]:
    """The cell as written, and the ``escaped`` tokens that undo it."""
    tokens = []
    if needs_percent(value):
        value = percent(value)
        tokens.append(column + ":pct")
    value, quoted = safe_cell(value)
    if quoted:
        tokens.insert(0, column)
    return value, tokens


def render(run: Run, options: Options) -> str:
    collected = collect(run.result, options)
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_ALL)
    writer.writerow(COLUMNS)
    for item in collected.indicators:
        cells = {
            "type": item.kind,
            "value": options.show(item.value),
            "source_file": JOIN.join(item.sources),
            "first_seen": collected.first_seen,
            "tlp": options.tlp_label,
            "run": run.name,
            "label": item.label or ("partial read" if item.partial else ""),
        }
        escaped: list[str] = []
        for column, value in cells.items():
            cells[column], tokens = neutral_cell(column, value)
            escaped += tokens
        writer.writerow([*cells.values(), " ".join(escaped)])
    return buffer.getvalue()
