"""YARA rules built from what the scan actually read.

One rule per file, and the rule matches on the indicators that file carries:
the addresses it calls, the paths it writes, the mutex it takes. The digests go
into meta as identity rather than into the condition, because a hash matches one
build and nothing else, while the address inside it usually survives the next
one. That mapping, this hash carried these indicators, is the thing worth
keeping after the directory goes away.

When a file gave up no indicators, the rule falls back to the strings the scan
read, and after that to the first bytes, anchored at offset zero. A head that
every file of its kind carries, an MZ or a PK, is not a rule at all: that file
is named in a comment with the reason instead, because a rule matching every
Windows binary is worse than no rule. A bounded read cannot produce a rule over
a whole file, so each rule says where it came from rather than implying more.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .extract import defang
from .models import Entry, Ioc, ScanResult

#: How many bytes of a head go into a fallback rule.
HEAD_BYTES_IN_RULE = 12

#: Indicator types worth a string, and the prefix each gets in the rule.
IOC_PREFIX = {
    "url": "url",
    "ipv4": "ip",
    "ipv6": "ip",
    "domain": "dom",
    "email": "mail",
    "path": "path",
    "mutex": "mutex",
    "secret": "secret",
    "btc": "wallet",
}

#: Shorter than this catches half the internet, so it is left out.
MIN_IOC = 7

#: Headers every file of that kind carries. A rule on one of these would match
#: every Windows binary, every zip, every PNG: a finding about nothing.
GENERIC_HEADS = {
    "4d5a": "a PE (Windows executable) header",
    "7f454c46": "an ELF header",
    "504b0304": "a zip header",
    "89504e47": "a PNG header",
    "25504446": "a PDF header",
    "47494638": "a GIF header",
    "ffd8ff": "a JPEG header",
    "1f8b": "a gzip header",
    "52617221": "a RAR header",
    "377abcaf": "a 7z header",
    "cafebabe": "a Java class header",
}

#: Lines from a file's own text, when it carried no indicators.
STRINGS_PER_FILE = 3
MIN_STRING = 12
MAX_STRING = 80

#: More than this in one rule is noise; the strongest are the longest.
MAX_IOCS_PER_FILE = 12


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


def _generic_head(entry: Entry) -> str | None:
    """The name of the format this head belongs to, if it is one everyone shares."""
    if not entry.head_hex:
        return None
    for prefix, description in GENERIC_HEADS.items():
        if entry.head_hex.lower().startswith(prefix):
            return description
    return None


def _strings_from(entry: Entry) -> list[str]:
    """Lines worth keeping: long enough to mean something, trimmed, deduplicated."""
    if not entry.text_preview:
        return []
    picked: list[str] = []
    for line in entry.text_preview.split(chr(10)):
        candidate = line.strip()[:MAX_STRING]
        if len(candidate) < MIN_STRING or not candidate.isprintable():
            continue
        if candidate not in picked:
            picked.append(candidate)
        if len(picked) == STRINGS_PER_FILE:
            break
    return picked


def _iocs_of(entry: Entry, iocs: list[Ioc]) -> list[Ioc]:
    """The indicators this file carried, longest first, deduplicated."""
    seen: set[str] = set()
    picked: list[Ioc] = []
    for ioc in sorted(iocs, key=lambda item: len(item.value), reverse=True):
        if not ioc.found_in(entry.url) or ioc.ioc_type not in IOC_PREFIX:
            continue
        if len(ioc.value) < MIN_IOC or ioc.value in seen:
            continue
        seen.add(ioc.value)
        picked.append(ioc)
        if len(picked) == MAX_IOCS_PER_FILE:
            break
    return picked


def _literal(ioc: Ioc, entry: Entry) -> str:
    """The form of the indicator that is actually in the file.

    The extractor refangs on the way in, so a note written as
    hxxp://panel[.]example[.]net carries the live spelling in the run. YARA
    matches bytes, so the rule has to carry the spelling the file uses, or it
    will never fire on the file it came from.

    The spelling the extractor recorded for this file comes first: it was read
    off the file itself, in whatever defanged form the file used, and each file
    gets its own. A run saved before spellings were recorded falls back to
    looking for the live value, then DirSift's own defanged form, in the text.
    """
    recorded = ioc.spellings.get(entry.url)
    if recorded:
        return recorded
    text = entry.text_preview or ""
    if ioc.value and ioc.value in text:
        return ioc.value
    if ioc.defanged and ioc.defanged in text:
        return ioc.defanged
    return ioc.value


def _meta(entry: Entry, result: ScanResult, run_name: str, stamp: str) -> list[str]:
    lines = [
        "    meta:",
        '        author = "cyb3rp03t"',
        '        tool = "dirsift"',
        '        run = "' + _quote(run_name) + '"',
        '        target = "' + _quote(defang(result.root_url)) + '"',
        '        file = "' + _quote(entry.name) + '"',
        '        created = "' + stamp + '"',
    ]
    if entry.sha256:
        lines.append('        sha256 = "' + entry.sha256 + '"')
    if entry.md5:
        lines.append('        md5 = "' + entry.md5 + '"')
    if entry.truncated:
        lines.append(
            '        caveat = "The scan stopped at the peek ceiling, so this describes '
            'the head of the file, not all of it."'
        )
    else:
        lines.append(
            '        caveat = "Built from the bytes the scan read, which is the head of '
            'the file rather than the whole of it."'
        )
    return lines


def _rule_for(entry: Entry, result: ScanResult, run_name: str, stamp: str) -> list[str]:
    base = _identifier("dirsift_" + run_name + "_" + entry.name)[:96]
    lines = ["rule " + base, "{"]
    lines.extend(_meta(entry, result, run_name, stamp))
    lines.append("    strings:")

    carried = _iocs_of(entry, result.iocs)
    if carried:
        counts: dict[str, int] = {}
        for ioc in carried:
            prefix = IOC_PREFIX[ioc.ioc_type]
            counts[prefix] = counts.get(prefix, 0) + 1
            lines.append(
                "        $"
                + prefix
                + str(counts[prefix])
                + ' = "'
                + _quote(_literal(ioc, entry))
                + '" ascii'
            )
        lines.append("    condition:")
        lines.append("        2 of them" if len(carried) > 2 else "        any of them")
        lines.append("}")
        return lines

    quoted = _strings_from(entry)
    if quoted:
        for number, value in enumerate(quoted, start=1):
            lines.append('        $s' + str(number) + ' = "' + _quote(value) + '" ascii')
        lines.append("    condition:")
        lines.append("        2 of them" if len(quoted) > 2 else "        any of them")
        lines.append("}")
        return lines

    generic = _generic_head(entry)
    head = _head_bytes(entry)
    if head and not generic:
        lines.append("        $head = { " + head + " }")
        lines.append("    condition:")
        lines.append("        $head at 0")
        lines.append("}")
        return lines

    reason = (
        "its first bytes are " + generic + ", which every file of that kind carries"
        if generic
        else "the scan kept no bytes from it"
    )
    return [
        "// No rule for " + entry.name + ": it gave up no indicators and " + reason + ".",
        "// Read more of it before writing one; a rule on that alone would match",
        "// everything of its kind and tell you nothing.",
    ]


def build_rules(result: ScanResult, entries: list[Entry], run_name: str) -> str:
    """One YARA rule per selected file, keyed to the indicators it carried."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    header = [
        "// Built by dirsift from a scan of " + defang(result.root_url),
        "// Run " + run_name + ", " + stamp,
        "// Each rule matches on the indicators its file carried. The digests are in",
        "// meta: identity for the sample the indicators came from, not the condition.",
        "",
    ]
    blocks = [_rule_for(entry, result, run_name, stamp) for entry in entries]
    if not blocks:
        return chr(10).join(header) + "// Nothing was selected." + chr(10)
    body = (chr(10) + chr(10)).join(chr(10).join(block) for block in blocks)
    return chr(10).join(header) + body + chr(10)
