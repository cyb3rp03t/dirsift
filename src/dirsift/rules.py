"""YARA rules built from what the scan actually read.

Two rules come out of a selection, because they answer different questions.

* An **exact** rule, for the files DirSift read whole: sha256 equality through
  the hash module. It identifies those files and nothing else.
* A **content** rule, from the head bytes and the strings that were read. It is
  the one that might catch the next build, and the one that might catch
  something innocent, so it is kept small and the meta says where it came from.

A bounded read cannot produce a rule over a whole file. That limit is written
into the rule rather than left for the next reader to discover.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .extract import defang
from .models import Entry, ScanResult

#: How many bytes of a head go into a content rule.
HEAD_BYTES_IN_RULE = 12

#: How many strings one file may contribute.
STRINGS_PER_FILE = 3

#: Strings shorter than this catch too much to be worth a line in a rule.
MIN_STRING = 12

#: And longer than this is usually one specific machine's path or a whole line
#: of noise, so it is trimmed.
MAX_STRING = 80


def _identifier(text: str) -> str:
    """A YARA identifier: letters, digits and underscores, never leading a digit."""
    safe = "".join(char if char.isalnum() else "_" for char in text).strip("_")
    return safe if safe and not safe[0].isdigit() else "r_" + safe


def _quote(text: str) -> str:
    """Escape a string for a YARA double quoted literal."""
    return text.replace(chr(92), chr(92) * 2).replace('"', chr(92) + '"')


def _head_bytes(entry: Entry) -> str | None:
    if not entry.head_hex:
        return None
    data = bytes.fromhex(entry.head_hex)[:HEAD_BYTES_IN_RULE]
    if not data:
        return None
    return " ".join(format(byte, "02x") for byte in data)


def _strings_from(entry: Entry) -> list[str]:
    """Lines worth keeping: long enough to mean something, trimmed, deduplicated."""
    if not entry.text_preview:
        return []
    picked: list[str] = []
    for line in entry.text_preview.split(chr(10)):
        candidate = line.strip()
        if len(candidate) < MIN_STRING or not candidate.isprintable():
            continue
        candidate = candidate[:MAX_STRING]
        if candidate not in picked:
            picked.append(candidate)
        if len(picked) == STRINGS_PER_FILE:
            break
    return picked


def build_rules(result: ScanResult, entries: list[Entry], run_name: str) -> str:
    """One YARA file covering the selected entries."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    base = _identifier("dirsift_" + run_name)[:60]
    hashed = [entry for entry in entries if entry.sha256]
    lines: list[str] = []

    if hashed:
        lines.append('import "hash"')
        lines.append("")
        lines.append("rule " + base + "_exact")
        lines.append("{")
        lines.append("    meta:")
        lines.append('        author = "cyb3rp03t"')
        lines.append('        tool = "dirsift"')
        lines.append('        run = "' + _quote(run_name) + '"')
        lines.append('        target = "' + _quote(defang(result.root_url)) + '"')
        lines.append('        created = "' + stamp + '"')
        lines.append(
            '        description = "Files read whole during the scan, by digest."'
        )
        for number, entry in enumerate(hashed, start=1):
            lines.append(
                "        sample_" + str(number) + ' = "' + _quote(entry.name) + '"'
            )
        lines.append("    condition:")
        conditions = [
            'hash.sha256(0, filesize) == "' + entry.sha256 + '"' for entry in hashed
        ]
        lines.append("        " + (chr(10) + "        or ").join(conditions))
        lines.append("}")
        lines.append("")

    strings: list[str] = []
    notes: list[str] = []
    partial = False
    for number, entry in enumerate(entries, start=1):
        head = _head_bytes(entry)
        if head:
            strings.append(
                "        $h" + str(number) + " = { " + head + " }  // head of " + entry.name
            )
        for index, value in enumerate(_strings_from(entry), start=1):
            strings.append(
                "        $s"
                + str(number)
                + "_"
                + str(index)
                + ' = "'
                + _quote(value)
                + '" ascii'
            )
        notes.append(entry.name)
        partial = partial or entry.truncated

    lines.append("rule " + base + "_content")
    lines.append("{")
    lines.append("    meta:")
    lines.append('        author = "cyb3rp03t"')
    lines.append('        tool = "dirsift"')
    lines.append('        run = "' + _quote(run_name) + '"')
    lines.append('        target = "' + _quote(defang(result.root_url)) + '"')
    lines.append('        created = "' + stamp + '"')
    lines.append(
        '        description = "Head bytes and strings from '
        + _quote(", ".join(notes))
        + '."'
    )
    if partial:
        lines.append(
            '        caveat = "Built from a partial read: DirSift stops at the peek '
            'ceiling, so this covers the head of the file, not all of it."'
        )
    else:
        lines.append(
            '        caveat = "Built from the bytes the scan read, which is the head '
            'of each file rather than the whole of it."'
        )
    lines.append("    strings:")
    if strings:
        lines.extend(strings)
    else:
        lines.append('        $nothing = "dirsift: no bytes were kept for these files"')
    lines.append("    condition:")
    lines.append("        any of them")
    lines.append("}")
    return chr(10).join(lines) + chr(10)
