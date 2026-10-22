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

from .extract import SecretPieces, defang
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
    "btc": "wallet",
}
# A secret is never written into a rule: a rule is a file meant for sharing,
# and a credential found on someone else's server does not travel further.

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


def _holds_secret(entry: Entry, iocs: list[Ioc]) -> bool:
    """Whether the run found a secret in this file."""
    return any(ioc.ioc_type == "secret" and ioc.found_in(entry.url) for ioc in iocs)


def _printable(data: bytes) -> bool:
    """Whether every byte is printable ASCII or ordinary whitespace: text, not a header."""
    return all(32 <= byte < 127 or byte in (9, 10, 13) for byte in data)


def _strings_from(entry: Entry, secrets: SecretPieces | None = None) -> list[str]:
    """Lines worth keeping: long enough to mean something, trimmed, deduplicated.

    A line holding any piece of a secret is skipped whole, not cut: the rest
    of it is the secret's context and would point straight at it.
    """
    if not entry.text_preview:
        return []
    secrets = secrets or SecretPieces([])
    picked: list[str] = []
    for line in entry.text_preview.split(chr(10)):
        if secrets.carried_by(line):
            continue
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
    secrets = SecretPieces(iocs)
    for ioc in sorted(iocs, key=lambda item: len(item.value), reverse=True):
        if not ioc.found_in(entry.url) or ioc.ioc_type not in IOC_PREFIX:
            continue
        if secrets.carried_by(ioc.value) or secrets.carried_by(_literal(ioc, entry)):
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
    """
    text = entry.text_preview or ""
    if ioc.value and ioc.value in text:
        return ioc.value
    if ioc.defanged and ioc.defanged in text:
        return ioc.defanged
    return ioc.value


def _meta(
    entry: Entry, result: ScanResult, run_name: str, stamp: str, tlp: str | None = None
) -> list[str]:
    lines = [
        "    meta:",
        '        author = "cyb3rp03t"',
        '        tool = "dirsift"',
        '        run = "' + _quote(run_name) + '"',
        '        target = "' + _quote(defang(result.root_url)) + '"',
        '        file = "' + _quote(entry.name) + '"',
        '        created = "' + stamp + '"',
    ]
    if tlp:
        lines.append('        tlp = "' + _quote(tlp) + '"')
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


def _rule_for(
    entry: Entry, result: ScanResult, run_name: str, stamp: str, tlp: str | None = None
) -> list[str]:
    base = _identifier("dirsift_" + run_name + "_" + entry.name)[:96]
    lines = ["rule " + base, "{"]
    lines.extend(_meta(entry, result, run_name, stamp, tlp))
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

    # Fail closed: a file the run found a secret in gets no rule from its own
    # text or its first bytes, whatever the detector thought the secret's
    # edges were. Its indicators above are the only way it gets a rule.
    if _holds_secret(entry, result.iocs):
        return _no_rule(
            entry, "it holds a secret, and a rule from its text would carry part of it"
        )

    secrets = SecretPieces(result.iocs)
    quoted = _strings_from(entry, secrets)
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
        data = bytes.fromhex(head.replace(" ", ""))
        # A head that is all text is the text path's job, not this one: a
        # text file's first bytes are its first line, secret or not.
        if _printable(data):
            return _no_rule(
                entry,
                "it gave up no indicators and its first bytes are plain text "
                "with nothing long enough to match on",
            )
        if secrets.carried_by(data.decode("latin-1")):
            return _no_rule(
                entry, "its first bytes carry part of a secret the run found"
            )
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
    return _no_rule(entry, "it gave up no indicators and " + reason)


def _no_rule(entry: Entry, reason: str) -> list[str]:
    """The comment a file gets in place of a rule, with the reason."""
    return [
        "// No rule for " + entry.name + ": " + reason + ".",
        "// Read more of it before writing one; a rule on that alone would match",
        "// everything of its kind and tell you nothing.",
    ]


def build_rules(
    result: ScanResult, entries: list[Entry], run_name: str, *, tlp: str | None = None
) -> str:
    """One YARA rule per selected file, keyed to the indicators it carried.

    ``tlp`` is a label such as "TLP:AMBER"; given, it goes into the header and
    into every rule's meta.
    """
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    header = [
        "// Built by dirsift from a scan of " + defang(result.root_url),
        "// Run " + run_name + ", " + stamp + (", " + tlp if tlp else ""),
        "// Each rule matches on the indicators its file carried. The digests are in",
        "// meta: identity for the sample the indicators came from, not the condition.",
        "",
    ]
    blocks = [_rule_for(entry, result, run_name, stamp, tlp) for entry in entries]
    if not blocks:
        return chr(10).join(header) + "// Nothing was selected." + chr(10)
    body = (chr(10) + chr(10)).join(chr(10).join(block) for block in blocks)
    return chr(10).join(header) + body + chr(10)
