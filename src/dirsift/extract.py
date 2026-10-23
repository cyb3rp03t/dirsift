"""Pull indicators out of file contents.

Scope note: this reads the text DirSift already fetched. It does not resolve,
query or enrich anything. A lookup is a second request against a third party
and it leaks what you are looking at, so enrichment is a decision for the
analyst, not a side effect of triage.

Three things matter more than the regex list:

* **Refanging on input.** Operators and the analysts before you both defang.
  ``hxxp://cdn[.]example[.]org`` and ``http://cdn.example.org`` are the same
  indicator and must dedupe to one row.
* **Defanging on output.** Everything that leaves this tool is defanged, in
  the report, in the terminal and in the JSON, because the output gets pasted
  into chats and posts where a live link is a liability.
* **Context over volume.** A bare IP in a list is worth little; the line it
  sat on is most of the value, so every indicator carries one.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlparse

from .models import Ioc

# Refang

#: Every defanged way of writing each piece of an indicator, as regex
#: alternatives, keyed by what it stands for. ``refang`` reads them one way and
#: ``spelling_pattern`` the other, so a notation added here is understood by
#: both. The order is the order refang applies them in.
DEFANG_VARIANTS: dict[str, list[str]] = {
    "http": [r"h\s*x\s*x\s*p"],
    ".": [r"\[\s*\.\s*\]", r"\(\s*\.\s*\)", r"\{\s*\.\s*\}", r"\s+dot\s+"],
    ":": [r"\[\s*:\s*\]", r"\(\s*:\s*\)"],
    "@": [r"\[\s*@\s*\]", r"\(\s*@\s*\)", r"\s+at\s+"],
    "/": [r"\[\s*/\s*\]"],
}

_REFANG_PATTERNS = [
    (re.compile("|".join(variants), re.I), live) for live, variants in DEFANG_VARIANTS.items()
]


def refang(text: str) -> str:
    """Turn analyst-safe notation back into the real thing, for matching only."""
    for pattern, replacement in _REFANG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def spelling_pattern(value: str) -> re.Pattern[str]:
    """A pattern for every way the source could have written a live value.

    The extractor matches on refanged text, so it knows ``evil.com`` but not
    whether the file said ``evil[.]com``, ``evil(.)com`` or ``evil dot com``.
    YARA matches bytes, so a rule needs the form the file used. Each piece of
    the value that has defanged forms accepts the live form or any of them.
    """
    parts: list[str] = []
    index = 0
    while index < len(value):
        if index == 0 and value[:4].lower() == "http":
            parts.append("(?:http|" + "|".join(DEFANG_VARIANTS["http"]) + ")")
            index += 4
            continue
        char = value[index]
        if char in DEFANG_VARIANTS:
            parts.append("(?:" + "|".join([re.escape(char), *DEFANG_VARIANTS[char]]) + ")")
        else:
            parts.append(re.escape(char))
        index += 1
    return re.compile("".join(parts), re.I)


def spelling_in(text: str, value: str) -> str:
    """How the source actually wrote a value: live if it can, else its defanged form.

    Live as written first, then live in another case, then any defanged form.
    When nothing matches, the live value stands in.
    """
    if value in text:
        return value
    for pattern in (re.compile(re.escape(value), re.I), spelling_pattern(value)):
        match = pattern.search(text)
        if match:
            return match.group(0)
    return value


#: Indicator types that are live if pasted somewhere that linkifies them.
NETWORK_TYPES = {"url", "domain", "ipv4", "ipv6", "email"}


def defang_text(text: str) -> str:
    """Defang every address, URL and hostname inside a block of prose.

    Used on the context lines that travel with each indicator. A context line
    is quoted from the target's own files, so it arrives live, and it ends up
    in reports and chat windows where a live link is a liability.
    """
    text = re.sub(r"\bhttp(s?)://", r"hxxp\1://", text, flags=re.I)
    text = re.sub(r"\bftp://", "fxp://", text, flags=re.I)
    text = _IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    text = _DOMAIN.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    # A host whose suffix is not on the list above is still a host when it
    # sits after an @, after a scheme, or before a port or a path.
    text = _MAIL_HOST.sub(lambda m: m.group(1) + m.group(2).replace(".", "[.]"), text)
    text = _HOST_IN_PLACE.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    text = _IPV6_LOOSE.sub(_defang_ipv6, text)
    return text


#: The domain after an @, whatever its suffix.
_MAIL_HOST = re.compile(r"(@)((?:[a-z0-9-]+\.)+[a-z]{2,63})(?![\w-])", re.I)
#: A dotted name right after ``//`` or right before a port or a path.
_HOST_IN_PLACE = re.compile(
    r"(?:(?<=//)(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![\w-])"
    r"|(?<![\w.\[\]-])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?=:\d|/))",
    re.I,
)
#: Anything shaped like an IPv6 address, compressed or not; checked before it is touched.
_IPV6_LOOSE = re.compile(r"(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])", re.I)


def _defang_ipv6(match: re.Match[str]) -> str:
    candidate = match.group(0)
    try:
        if ipaddress.ip_address(candidate).version == 6 and any(
            char.isalnum() for char in candidate
        ):
            return candidate.replace(":", "[:]")
    except ValueError:
        pass
    return candidate


def defang(value: str) -> str:
    """The inverse, applied to everything DirSift prints or writes."""
    value = re.sub(r"^http(s?)://", r"hxxp\1://", value, flags=re.I)
    value = re.sub(r"^ftp://", "fxp://", value, flags=re.I)
    value = value.replace(".", "[.]")
    return value.replace("hxxp[.]", "hxxp.").replace("hxxps[.]", "hxxps.")


# Patterns

_IPV4 = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}(?![\w:])")
_URL = re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}\\|^`]+", re.I)
_DOMAIN = re.compile(
    r"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|top|xyz|info|biz|online|site|shop|club|icu|cc|su|pw|"
    r"gq|tk|ml|cf|ga|live|app|dev|cloud|space|fun|store|work|link|host|press|"
    r"duckdns\.org|ddns\.net|no-ip\.org|hopto\.org|serveo\.net|ngrok\.io|"
    r"trycloudflare\.com|onion))(?![\w-])",
    re.I,
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

_MUTEX = re.compile(r"\b(?:Global|Local)\\\\?[A-Za-z0-9_.{}-]{3,64}")
_WINPATH = re.compile(
    r"(?:%(?:TEMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|USERPROFILE|SystemRoot|ALLUSERSPROFILE)%"
    r"(?:\\\\?[^\s\"'<>|*?,;]{0,120})?"
    r"|[A-Za-z]:\\\\?(?:Users|Windows|ProgramData|Temp)\\\\?[^\s\"'<>|*?]{0,120})",
    re.I,
)

#: A whole line that is nothing but ``user:password``, the shape of a dump.
_CREDENTIAL_PAIR = re.compile(
    r"^[ \t]*(?P<user>[A-Za-z0-9._%+@-]{3,64}):(?P<secret>[^\s:/\\]{4,64})[ \t]*$",
    re.M,
)
_REGKEY = re.compile(
    r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\\\?[A-Za-z0-9\\\\_.-]{4,160}", re.I
)

#: Credential shapes worth naming individually. Order matters, first wins.
_SECRETS: list[tuple[str, re.Pattern[str]]] = [
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b")),
    # The whole block, BEGIN to END, or to the end of what was read when the
    # read stopped inside it: the body is the secret, not the header line.
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?"
            r"(?:-----)?[\s\S]*?"
            r"(?:-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?"
            r"PRIVATE KEY(?: BLOCK)?-----|\Z)"
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "discord_webhook",
        re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\S+", re.I),
    ),
]

#: Assignments like ``password = "hunter2"``, ``"api_key": "..."`` or
#: ``aws_secret_access_key = ...``. The key is any name; whether it names a
#: secret is decided word by word in ``_names_secret``.
_ASSIGNED_SECRET = re.compile(
    r"""(?<![\w.])(?P<key>[A-Za-z_][\w.-]{0,63})["']?
        \s*[:=]\s*["']?(?P<value>[^\s"',;}]{6,120})""",
    re.X,
)

#: A word that makes the key a secret wherever it stands in it.
_SECRET_WORDS = {
    "password", "passwd", "passphrase", "pwd", "secret", "token", "apikey",
    "credential", "credentials",
}
#: A word that does so only as the last word of the key: ``db_pass`` is a
#: secret, ``pass_through`` is not.
_SECRET_LAST_WORDS = {"pass", "auth", "license", "serial", "webhook"}
#: Two words that do so side by side.
_SECRET_PAIRS = {("api", "key"), ("license", "key"), ("bot", "token")}
#: A last word that says the value is about the secret, not the secret itself
#: (``token_url``, ``password_policy``), or a file name (``secret_santa.txt``).
_NOT_SECRET_LAST_WORDS = {
    "url", "uri", "endpoint", "host", "file", "path", "dir", "policy", "length",
    "len", "min", "max", "hint", "prompt", "label", "field", "name", "type", "mode",
    "id", "expiry", "expires", "expiration", "ttl", "timeout", "enabled", "required",
    "reset", "format", "pattern", "regex", "header", "count", "size", "version",
    "algorithm", "method", "list",
    "txt", "log", "csv", "bak", "zip", "pdf", "doc", "docx", "html", "htm", "php",
    "js", "py", "sh", "ps1", "json", "xml", "yml", "yaml", "ini", "cfg", "conf",
}


def _key_words(key: str) -> list[str]:
    """``aws_secret_access_key``, ``x-api-key`` and ``dbPassword``, split into words."""
    words: list[str] = []
    for part in re.split(r"[_.\-]+", key):
        words += [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", part)]
    return words


def _names_secret(key: str) -> bool:
    """Whether a key such as ``client_secret`` or ``DB_PASSWORD`` names a secret."""
    words = _key_words(key)
    if not words or words[-1] in _NOT_SECRET_LAST_WORDS:
        return False
    if words[-1] in _SECRET_LAST_WORDS or any(word in _SECRET_WORDS for word in words):
        return True
    return any(pair in _SECRET_PAIRS for pair in zip(words, words[1:], strict=False))

#: Execution tells: not indicators, but they say what the script is for.
EXECUTION_TELLS = [
    "powershell", "-enc", "-encodedcommand", "-nop", "-w hidden", "invoke-expression",
    "iex ", "downloadstring", "downloadfile", "certutil", "bitsadmin", "mshta",
    "rundll32", "regsvr32", "wscript", "cscript", "schtasks", "at.exe", "sc create",
    "reg add", "vssadmin", "bcdedit", "netsh", "wmic", "curl ", "wget ", "start ",
    "chmod +x", "nohup", "crontab", "systemctl", "base64 -d", "msiexec",
]

_NOISE_DOMAINS = {
    "example.com", "example.org", "example.net", "localhost", "schemas.xmlsoap.org",
    "www.w3.org", "microsoft.com", "www.microsoft.com", "go.microsoft.com",
    "schemas.microsoft.com", "python.org", "www.python.org", "github.com",
    "raw.githubusercontent.com", "golang.org", "npmjs.com", "sourceforge.net",
}

_NOISE_SECRET_VALUES = {
    "password", "changeme", "your_token_here", "xxxxx", "none", "null", "true",
    "false", "undefined", "your_api_key", "insert_key_here", "todo",
}


def _assignments(text: str) -> list[re.Match[str]]:
    """Every ``key = value`` whose key names a secret.

    A key that names nothing secret gives its value back to the search, so the
    ``token=`` inside ``url=http://host/?token=...`` is still found.
    """
    found = []
    position = 0
    while match := _ASSIGNED_SECRET.search(text, position):
        if _names_secret(match.group("key")):
            found.append(match)
            position = match.end()
        else:
            position = match.end("key")
    return found


#: How a comment line starts, after its indentation, across the languages a kit
#: is written in: shell and Python, C-like code, ini files, batch, HTML, and the
#: body lines of a /* block. Compared in lower case, so REM matches rem too.
COMMENT_PREFIXES = ("#", "//", ";", "rem ", "::", "<!--", "/*", "*")


def _line_at(text: str, start: int) -> str:
    """The line a match starts on, without its line ending, whichever one it was."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    return text[line_start : line_end if line_end != -1 else len(text)].rstrip("\r")


def is_comment(line: str) -> bool:
    """Whether a line is a comment rather than something the kit runs or reads.

    A shebang starts with # and is the opposite of a comment: it says how the
    file runs.
    """
    stripped = line.lstrip().lower()
    if stripped.startswith("#!"):
        return False
    return stripped.startswith(COMMENT_PREFIXES)


def _is_link(value: str) -> bool:
    return value.lower().startswith(("http://", "https://", "ftp://"))


def _is_interesting_ip(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return not (
        ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved
    )


def _context(text: str, start: int, end: int, width: int = 90) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line = text[line_start : line_end if line_end != -1 else len(text)]
    line = line.strip()
    if len(line) <= width:
        return line
    offset = start - line_start
    left = max(0, offset - width // 2)
    return ("..." if left else "") + line[left : left + width].strip() + "..."


def extract_iocs(text: str, source_url: str) -> list[Ioc]:
    """Lift indicators out of one file's text. Deduped within the file."""
    if not text:
        return []

    working = refang(text)
    found: dict[tuple[str, str], Ioc] = {}

    def add(ioc_type: str, value: str, start: int, end: int, label: str | None = None) -> None:
        value = value.rstrip(".,;:)\"'")
        if chr(10) in value:
            # A block over several lines: the context is its first line only,
            # so the body does not travel in the context as well.
            value = value.strip()
            end = start + value.find(chr(10))
        if not value:
            return
        comment = is_comment(_line_at(working, start))
        existing = found.get((ioc_type, value.lower()))
        if existing is not None:
            # The first mention keeps its context; later ones are only counted,
            # and one mention outside a comment is enough to make it code.
            existing.occurrences += 1
            existing.in_comment = existing.in_comment and comment
            return
        # The form this file used, which is what a YARA rule has to carry. Only
        # network indicators have a defanged form to look for.
        spelling = spelling_in(text, value) if ioc_type in NETWORK_TYPES else value
        ioc = Ioc(
            ioc_type=ioc_type,
            value=value,
            # Only what is clickable needs neutering: the network indicators,
            # and a secret that is itself a link, such as a webhook. Defanging
            # a file path just makes it wrong.
            defanged=defang(value) if ioc_type in NETWORK_TYPES or _is_link(value) else value,
            source_url=source_url,
            sources=[source_url],
            context=defang_text(_context(working, start, end)),
            label=label,
            in_comment=comment,
            spellings={source_url: spelling},
            # Live when the file wrote it live, in whatever case. Matching runs
            # on refanged text, so the spelling is the only honest witness.
            seen_live=spelling.lower() == value.lower(),
        )
        found[ioc.key()] = ioc

    for match in _URL.finditer(working):
        url = match.group(0)
        host = urlparse(url).hostname or ""
        if host in _NOISE_DOMAINS:
            continue
        add("url", url, *match.span())

    for match in _IPV4.finditer(working):
        address, port = match.group(1), match.group(2)
        if not _is_interesting_ip(address):
            continue
        value = f"{address}:{port}" if port and 0 < int(port) < 65536 else address
        add("ipv4", value, *match.span())

    for match in _IPV6.finditer(working):
        if _is_interesting_ip(match.group(0)):
            add("ipv6", match.group(0), *match.span())

    for match in _DOMAIN.finditer(working):
        domain = match.group(1).lower()
        if domain in _NOISE_DOMAINS or domain.endswith(tuple(_NOISE_DOMAINS)):
            continue
        add("domain", domain, *match.span())

    for match in _EMAIL.finditer(working):
        add("email", match.group(0), *match.span())

    for pattern, ioc_type in ((_BTC, "btc"), (_ETH, "eth"), (_XMR, "xmr")):
        for match in pattern.finditer(working):
            add(ioc_type, match.group(0), *match.span())

    for label, pattern in _SECRETS:
        for match in pattern.finditer(working):
            add("secret", match.group(0), *match.span(), label=label)

    for match in _assignments(working):
        value = match.group("value")
        if value.lower() in _NOISE_SECRET_VALUES or value.startswith(("$", "%", "{", "<")):
            continue
        if "(" in value:
            # A lookup such as os.environ.get( names where the secret is kept.
            continue
        add("secret", value, *match.span(), label=match.group("key").lower())

    for match in _CREDENTIAL_PAIR.finditer(working):
        secret = match.group("secret")
        if secret.lower() in _NOISE_SECRET_VALUES or secret.isdigit():
            continue
        add("secret", match.group(0).strip(), *match.span(), label="credential_pair")

    for match in _MUTEX.finditer(working):
        add("mutex", match.group(0), *match.span())

    for match in _REGKEY.finditer(working):
        add("registry", match.group(0), *match.span())

    for match in _WINPATH.finditer(working):
        add("path", match.group(0), *match.span())

    return list(found.values())


def dedupe_iocs(iocs: list[Ioc]) -> list[Ioc]:
    """Collapse indicators seen in several files.

    The first file keeps the context line, and every file that carried the
    indicator is listed in ``sources``: a family of builds usually shares its
    callback, and the second build's rule has to match on it as well. Mentions
    add up; it is a comment only if it was one everywhere, and live if it was
    written live anywhere.
    """
    out: dict[tuple[str, str], Ioc] = {}
    for ioc in iocs:
        kept = out.setdefault(ioc.key(), ioc)
        if kept is not ioc:
            for url, spelling in ioc.spellings.items():
                kept.spellings.setdefault(url, spelling)
            kept.occurrences += ioc.occurrences
            kept.in_comment = kept.in_comment and ioc.in_comment
            kept.seen_live = kept.seen_live or ioc.seen_live
        for url in ioc.sources or [ioc.source_url]:
            if url not in kept.sources:
                kept.sources.append(url)
    order = {
        "ipv4": 0, "ipv6": 1, "url": 2, "domain": 3, "email": 4, "secret": 5,
        "btc": 6, "eth": 7, "xmr": 8, "mutex": 9, "registry": 10, "path": 11,
    }
    return sorted(out.values(), key=lambda i: (order.get(i.ioc_type, 99), i.value))


#: How long a piece of a secret has to be before it counts as carrying it.
SECRET_PIECE = 8


def secret_material(ioc: Ioc) -> str:
    """The part of a secret indicator that is actually secret.

    A link keeps everything after its host (``https://`` and the host name are
    public); a private key block keeps its body, not the BEGIN and END lines
    every key shares. Anything else is secret whole.
    """
    value = ioc.value
    if _is_link(value):
        parsed = urlparse(value)
        return value.split(parsed.netloc, 1)[-1] if parsed.netloc else value
    if ioc.label == "private_key":
        body = [line for line in value.splitlines() if not line.startswith("-----")]
        return "\n".join(body)
    return value


class SecretPieces:
    """Every piece of the run's secrets, to ask whether a text carries any of one.

    Fails closed: eight characters of a secret in a text is enough, so a rule
    or a list built from a line cut around the secret still trips it.
    """

    def __init__(self, iocs: list[Ioc]) -> None:
        self.pieces: set[str] = set()
        self.short: set[str] = set()
        for ioc in iocs:
            if ioc.ioc_type != "secret" or not ioc.value:
                continue
            for part in secret_material(ioc).splitlines() or [ioc.value]:
                part = part.strip()
                if not part:
                    continue
                if len(part) < SECRET_PIECE:
                    self.short.add(part)
                    continue
                for start in range(len(part) - SECRET_PIECE + 1):
                    self.pieces.add(part[start : start + SECRET_PIECE])

    def __bool__(self) -> bool:
        return bool(self.pieces or self.short)

    def carried_by(self, text: str) -> bool:
        if not text:
            return False
        if any(part in text for part in self.short):
            return True
        if not self.pieces:
            return False
        return any(
            text[start : start + SECRET_PIECE] in self.pieces
            for start in range(len(text) - SECRET_PIECE + 1)
        )


def execution_tells(text: str) -> list[str]:
    """Which command-shaped strings appear in this file, in order of appearance."""
    lowered = text.lower()
    hits = [(lowered.find(tell), tell.strip()) for tell in EXECUTION_TELLS if tell in lowered]
    return [tell for _, tell in sorted(hits)]



#: How many characters of a known opening a shown secret keeps. Each is the
#: fixed part every key of that kind starts with, never the secret itself, and
#: all are shorter than ``SECRET_PIECE``.
_FIXED_OPENING = {
    "aws_access_key": 4,
    "github_token": 4,
    "slack_token": 5,
    "google_api_key": 4,
    "stripe_key": 7,
    "jwt": 3,
}

#: What stands in for a line that carries part of a secret it does not hold whole.
WITHHELD = "withheld: carries part of a secret"


def _secret_opening(ioc: Ioc) -> str:
    """The part of a secret that says what it is and is not secret."""
    value = ioc.value.strip()
    if ioc.label == "private_key":
        # The BEGIN line every key of the kind shares, without its dashes, and
        # only that: a key escaped into one JSON line goes on after it.
        header = re.search(r"BEGIN [A-Z ]*?PRIVATE KEY(?: BLOCK)?", value)
        return header.group(0) if header else ""
    if _is_link(value):
        parsed = urlparse(value)
        if not parsed.netloc:
            return ""
        base = f"{parsed.scheme}://{parsed.netloc}/"
        if "/api/webhooks/" in parsed.path:
            base += "api/webhooks/"
        return defang(base)
    keep = _FIXED_OPENING.get(ioc.label or "", 0)
    return value[:keep]


def secret_shown(ioc: Ioc) -> str:
    """A secret as it may be shown or exported: one line, none of it quoted.

    The kind, the fixed opening that says what it is (a PEM BEGIN line, ``AKIA``,
    the webhook path), its length and the start of its sha256, so two runs or
    two files holding the same secret can be matched without either quoting it.
    """
    value = ioc.value.strip()
    label = re.sub(r"[^a-z0-9_.-]+", "_", (ioc.label or "secret").lower()) or "secret"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    parts = [label, _secret_opening(ioc), f"{len(value)} chars", f"sha256:{digest}"]
    return "  ".join(part for part in parts if part)


class SecretMask:
    """Shows a run's indicators and context lines with every secret named, not quoted.

    A secret held whole in a text is replaced by its shown form. A text left
    with a piece of a secret after that is withheld whole: fails closed, like
    ``SecretPieces``. The run itself is not changed; this is for display and
    export only.
    """

    def __init__(self, iocs: list[Ioc]) -> None:
        secrets = [ioc for ioc in iocs if ioc.ioc_type == "secret" and ioc.value.strip()]
        self.pieces = SecretPieces(secrets).pieces
        self.forms: dict[str, str] = {}
        for ioc in secrets:
            shown = secret_shown(ioc)
            # As stored, and as a context line carries it: the prose pass
            # defangs the dots of a token, so ``eyJ...`` reads ``eyJ...[.]``.
            forms = (ioc.value, ioc.defanged, defang_text(ioc.value.strip()))
            for form in {*forms, *(form.strip() for form in forms)}:
                if form:
                    self.forms.setdefault(form, shown)
        ordered = sorted(self.forms, key=len, reverse=True)
        self.pattern = re.compile("|".join(map(re.escape, ordered))) if ordered else None

    def _carries_piece(self, text: str) -> bool:
        return any(
            text[start : start + SECRET_PIECE] in self.pieces
            for start in range(len(text) - SECRET_PIECE + 1)
        )

    def text(self, text: str | None) -> str:
        """A line safe to show: secrets named in brackets, or withheld whole."""
        if not text:
            return ""
        if self.pattern is None:
            return text
        whole = self.forms.get(text.strip())
        if whole:
            return whole
        if self._carries_piece(self.pattern.sub(chr(0), text)):
            return WITHHELD
        return self.pattern.sub(lambda match: "[" + self.forms[match.group(0)] + "]", text)

    def indicator(self, ioc: Ioc) -> str:
        """An indicator as a list shows it: defanged, and a secret by its shown form."""
        if ioc.ioc_type == "secret":
            return secret_shown(ioc)
        return self.text(ioc.defanged)
