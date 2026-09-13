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

import ipaddress
import re
from urllib.parse import urlparse

from .models import Ioc

# --- refang ---------------------------------------------------------------

_REFANG_PATTERNS = [
    (re.compile(r"h\s*x\s*x\s*p", re.I), "http"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\s+dot\s+", re.I), "."),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)|\s+at\s+", re.I), "@"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
]


def refang(text: str) -> str:
    """Turn analyst-safe notation back into the real thing, for matching only."""
    for pattern, replacement in _REFANG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


#: Indicator types that are live if pasted somewhere that linkifies them.
NETWORK_TYPES = {"url", "domain", "ipv4", "ipv6", "email"}


def defang_text(text: str) -> str:
    """Defang every address, URL and hostname inside a block of prose.

    Used on the context lines that travel with each indicator. A context line
    is quoted from the target's own files, so it arrives live, and it ends up
    in reports and chat windows where a live link is a liability.
    """
    text = re.sub(r"\bhttp(s?)://", r"hxxp\1://", text, flags=re.I)
    text = _IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    text = _DOMAIN.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    return text


def defang(value: str) -> str:
    """The inverse, applied to everything DirSift prints or writes."""
    value = re.sub(r"^http(s?)://", r"hxxp\1://", value, flags=re.I)
    value = re.sub(r"^ftp://", "fxp://", value, flags=re.I)
    value = value.replace(".", "[.]")
    return value.replace("hxxp[.]", "hxxp.").replace("hxxps[.]", "hxxps.")


# --- patterns -------------------------------------------------------------

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
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "discord_webhook",
        re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\S+", re.I),
    ),
]

#: Assignments like ``password = "hunter2"`` or ``"api_key": "..."``.
_ASSIGNED_SECRET = re.compile(
    r"""(?P<key>\b(?:pass(?:word|wd)?|passwd|pwd|secret|api[_-]?key|apikey|token|
        auth|bot[_-]?token|license|serial|webhook)\b)
        \s*[:=]\s*["']?(?P<value>[^\s"',;}]{6,120})""",
    re.I | re.X,
)

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
        if not value:
            return
        ioc = Ioc(
            ioc_type=ioc_type,
            value=value,
            # Only network indicators are clickable, so only those need
            # neutering. Defanging a file path just makes it wrong.
            defanged=defang(value) if ioc_type in NETWORK_TYPES else value,
            source_url=source_url,
            context=defang_text(_context(working, start, end)),
            label=label,
        )
        found.setdefault(ioc.key(), ioc)

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

    for match in _ASSIGNED_SECRET.finditer(working):
        value = match.group("value")
        if value.lower() in _NOISE_SECRET_VALUES or value.startswith(("$", "%", "{", "<")):
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
    """Collapse indicators seen in several files, keeping the first context."""
    out: dict[tuple[str, str], Ioc] = {}
    for ioc in iocs:
        out.setdefault(ioc.key(), ioc)
    order = {
        "ipv4": 0, "ipv6": 1, "url": 2, "domain": 3, "email": 4, "secret": 5,
        "btc": 6, "eth": 7, "xmr": 8, "mutex": 9, "registry": 10, "path": 11,
    }
    return sorted(out.values(), key=lambda i: (order.get(i.ioc_type, 99), i.value))


def execution_tells(text: str) -> list[str]:
    """Which command-shaped strings appear in this file, in order of appearance."""
    lowered = text.lower()
    hits = [(lowered.find(tell), tell.strip()) for tell in EXECUTION_TELLS if tell in lowered]
    return [tell for _, tell in sorted(hits)]
