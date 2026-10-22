"""The indicators a shared file may carry, and the ones it may not.

Every target reads the same list, so one filter decides for all of them what
leaves the run. Each value that is kept out is counted with the reason, so the
person exporting it sees what was dropped and why instead of guessing.

Nothing here touches the network.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse

from ..extract import SecretPieces
from ..models import ScanResult
from ..stix import timestamp
from .options import Options, defang_value

#: The types a shared file may carry. Secrets, wallets, mutexes, registry keys
#: and paths never leave the run in a file meant for someone else.
SHAREABLE = ("ipv4", "ipv6", "domain", "url", "email", "sha256", "md5")

#: Why a value was kept out. The keys are fixed text the UI shows as is.
PRIVATE = "private or reserved address"
MULTICAST = "multicast address"
DOCUMENTATION = "documentation address"
RESERVED_NAME = "reserved name"
PROTOCOL = "protocol string"
SHARED = "shared hosting (host level)"
RESOLVER = "public resolver"
EMPTY_HASH = "empty file hash"
NOT_SHAREABLE = "not a shareable type"
SECRET_PART = "carries part of a secret"

REASONS = (
    PRIVATE,
    MULTICAST,
    DOCUMENTATION,
    RESERVED_NAME,
    PROTOCOL,
    SHARED,
    RESOLVER,
    EMPTY_HASH,
    NOT_SHAREABLE,
    SECRET_PART,
)

#: Address blocks set aside for examples and documentation (RFC 5737, RFC 3849,
#: RFC 9637). They never belong to anyone, so they match nothing real.
DOCUMENTATION_NETS = [
    ipaddress.ip_network(block)
    for block in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")
]

#: Names reserved for examples, tests and the local network (RFC 2606, RFC 6761, RFC 6762).
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
RESERVED_TLDS = ("example", "test", "invalid", "localhost", "local")

#: Text that looks like a mail address or a name but is a protocol identifier,
#: such as the SSH algorithm names curve25519-sha256@libssh.org.
PROTOCOL_DOMAINS = ("openssh.com", "libssh.org")

#: Hosts many unrelated people share. A block on the host would cut off
#: everyone on it, so these enter as full URLs only, never as a host, a domain
#: or an address.
SHARED_HOSTS = (
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org",
    "amazonaws.com", "cloudfront.net", "azureedge.net", "azurewebsites.net",
    "windows.net", "googleusercontent.com", "googleapis.com", "google.com",
    "appspot.com", "firebaseapp.com", "web.app", "dropbox.com",
    "dropboxusercontent.com", "live.com", "1drv.ms", "sharepoint.com",
    "onedrive.com", "discord.com", "discordapp.com", "discordapp.net",
    "pastebin.com", "telegram.org", "t.me", "mega.nz", "mediafire.com",
    "cloudflare.com", "workers.dev", "pages.dev", "r2.dev",
    "digitaloceanspaces.com", "backblazeb2.com", "archive.org", "sourceforge.net",
    "npmjs.com", "npmjs.org", "pypi.org", "pythonhosted.org", "python.org",
    "golang.org", "microsoft.com", "windowsupdate.com", "apple.com",
)

#: Public DNS resolvers. Malware asks them, so do all of the operator's users.
PUBLIC_RESOLVERS = frozenset(
    {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220", "2606:4700:4700::1111", "2001:4860:4860::8888",
    }
)

#: The digests of an empty file. A run full of zero byte files would otherwise
#: put the hash of nothing on a block list.
EMPTY_HASHES = frozenset(
    {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "d41d8cd98f00b204e9800998ecf8427e",
    }
)

HEX = frozenset("0123456789abcdef")


@dataclass
class Indicator:
    """One value ready for a shared file."""

    kind: str  # one of SHAREABLE
    value: str  # live
    sources: list[str] = field(default_factory=list)  # paths under the root
    label: str | None = None  # "target" for the directory's own host
    partial: bool = False  # came from a file the scan did not read whole

    @property
    def defanged(self) -> str:
        if self.kind in ("sha256", "md5"):
            return self.value
        return defang_value(self.value)


@dataclass
class Collected:
    """What survived the filter, and what did not, by type and reason."""

    indicators: list[Indicator]
    dropped: list[tuple[str, str]]  # (type, reason)
    first_seen: str

    def of(self, *kinds: str) -> list[Indicator]:
        return [item for item in self.indicators if item.kind in kinds]

    def left_out(self, kinds: tuple[str, ...] | None = None) -> dict[str, int]:
        counts = dict.fromkeys(REASONS, 0)
        for kind, reason in self.dropped:
            if kinds is None or kind in kinds:
                counts[reason] += 1
        return counts

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(SHAREABLE, 0)
        for item in self.indicators:
            out[item.kind] += 1
        return out


def _suffix(host: str, suffixes) -> bool:
    host = host.lower().rstrip(".")
    return any(host == suffix or host.endswith("." + suffix) for suffix in suffixes)


def _address_reason(value: str, options: Options) -> str | None:
    """Why an address is kept out, or None to keep it."""
    ip = ipaddress.ip_address(value)
    if value in PUBLIC_RESOLVERS or str(ip) in PUBLIC_RESOLVERS:
        return RESOLVER
    if not options.exclude_private:
        return None
    if any(ip in net for net in DOCUMENTATION_NETS if net.version == ip.version):
        return DOCUMENTATION
    if ip.is_multicast:
        return MULTICAST
    if not ip.is_global or ip.is_reserved or ip.is_unspecified:
        return PRIVATE
    return None


def _name_reason(host: str, options: Options) -> str | None:
    """Why a host name is kept out at host level, or None to keep it."""
    host = host.lower().rstrip(".")
    if options.exclude_protocol and _suffix(host, PROTOCOL_DOMAINS):
        return PROTOCOL
    if options.exclude_private and (
        _suffix(host, RESERVED_DOMAINS)
        or host.rsplit(".", 1)[-1] in RESERVED_TLDS
        or "." not in host
    ):
        return RESERVED_NAME
    if _suffix(host, SHARED_HOSTS):
        return SHARED
    return None


def _ip_version(value: str) -> int | None:
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        return None


def _host_kind(host: str) -> str:
    version = _ip_version(host)
    if version == 4:
        return "ipv4"
    if version == 6:
        return "ipv6"
    return "domain"


def _host_reason(host: str, options: Options) -> str | None:
    if _ip_version(host) is not None:
        return _address_reason(host, options)
    return _name_reason(host, options)


def _url_reason(url: str, options: Options) -> str | None:
    """A URL is only kept out when its host reaches nothing outside a network.

    A URL on shared hosting is the one precise way to name a thing there, so it
    stays: only the host is dropped from the host level lists.
    """
    host = urlparse(url).hostname or ""
    if not host:
        return RESERVED_NAME if options.exclude_private else None
    reason = _host_reason(host, options)
    return None if reason == SHARED else reason


def _relative(url: str, root: str) -> str:
    return unquote(url.removeprefix(root)) or url


class _Gather:
    """Keeps one indicator per value, merging the files each was found in."""

    def __init__(self) -> None:
        self.kept: dict[tuple[str, str], Indicator] = {}
        self.dropped: dict[tuple[str, str], str] = {}

    def drop(self, kind: str, value: str, reason: str) -> None:
        key = (kind, value.lower())
        if key not in self.kept:
            self.dropped.setdefault(key, reason)

    def keep(self, kind: str, value: str, sources, *, label=None, partial=False) -> None:
        key = (kind, value.lower() if kind != "url" else value)
        self.dropped.pop((kind, value.lower()), None)
        item = self.kept.get(key)
        if item is None:
            item = self.kept[key] = Indicator(kind=kind, value=value)
        for source in sources:
            if source not in item.sources:
                item.sources.append(source)
        if label and not item.label:
            item.label = label
        item.partial = item.partial or partial

    def host(self, host: str, sources, options: Options, *, label=None, partial=False) -> None:
        kind = _host_kind(host)
        if options.types is not None and kind not in options.types:
            return
        reason = _host_reason(host, options)
        if reason:
            self.drop(kind, host, reason)
        else:
            self.keep(kind, host.lower(), sources, label=label, partial=partial)


def collect(result: ScanResult, options: Options) -> Collected:
    """Every value a shared file may carry, after the filter, sorted the same way every time."""
    root = result.root_url
    truncated = {entry.url for entry in result.files if entry.truncated}
    gather = _Gather()
    wanted = options.types

    def selected(kind: str) -> bool:
        return wanted is None or kind in wanted

    # The directory itself, unless a single file was asked for.
    if options.source is None:
        host = urlparse(root).hostname or ""
        if host:
            gather.host(host, [], options, label="target")
            if result.target_ip and result.target_ip != host:
                if _host_reason(host, options) == SHARED:
                    gather.drop(_host_kind(result.target_ip), result.target_ip, SHARED)
                elif selected(_host_kind(result.target_ip)):
                    reason = _address_reason(result.target_ip, options)
                    if reason:
                        gather.drop(_host_kind(result.target_ip), result.target_ip, reason)
                    else:
                        gather.keep(
                            _host_kind(result.target_ip), result.target_ip, [], label="target"
                        )
        if selected("url"):
            reason = _url_reason(root, options)
            if reason:
                gather.drop("url", root, reason)
            else:
                gather.keep("url", root, [], label="target")

    # A webhook is a URL and a secret at once: the secret wins, and nothing
    # that carries a piece of one leaves the run.
    secrets = SecretPieces(result.iocs)
    for ioc in result.iocs:
        sources = ioc.sources or [ioc.source_url]
        if options.source is not None and options.source not in sources:
            continue
        paths = sorted({_relative(url, root) for url in sources})
        partial = any(url in truncated for url in sources)
        kind = ioc.ioc_type
        if kind not in SHAREABLE:
            gather.drop(kind, ioc.value, NOT_SHAREABLE)
            continue
        value = ioc.value
        if secrets.carried_by(value):
            if selected(kind):
                gather.drop(kind, value, SECRET_PART)
            continue
        if kind == "ipv4":
            value = value.split(":", 1)[0]
        if kind in ("ipv4", "ipv6"):
            if _ip_version(value) is None or not selected(kind):
                continue
            gather.host(value, paths, options, partial=partial)
        elif kind == "domain":
            if selected(kind):
                gather.host(value, paths, options, partial=partial)
        elif kind == "email":
            if not selected(kind):
                continue
            domain = value.rpartition("@")[2]
            reason = _name_reason(domain, options)
            if reason and reason != SHARED:
                gather.drop(kind, value, reason)
            else:
                gather.keep(kind, value, paths, partial=partial)
        elif kind == "url":
            reason = _url_reason(value, options)
            if reason:
                if selected(kind):
                    gather.drop(kind, value, reason)
                continue
            if selected(kind):
                gather.keep(kind, value, paths, partial=partial)
            host = urlparse(value).hostname
            if host:
                gather.host(host, paths, options, partial=partial)

    for entry in result.files:
        if not entry.sha256 or entry.truncated:
            continue
        if options.source is not None and entry.url != options.source:
            continue
        path = _relative(entry.url, root)
        for kind, digest in (("sha256", entry.sha256), ("md5", entry.md5)):
            if not digest or not selected(kind):
                continue
            digest = digest.lower()
            if len(set(digest) - HEX) or len(digest) != (64 if kind == "sha256" else 32):
                continue
            if digest in EMPTY_HASHES or len(set(digest)) == 1:
                gather.drop(kind, digest, EMPTY_HASH)
            else:
                gather.keep(kind, digest, [path])

    order = {kind: number for number, kind in enumerate(SHAREABLE)}
    indicators = sorted(
        gather.kept.values(), key=lambda item: (order[item.kind], item.value.lower(), item.value)
    )
    dropped = sorted((kind, reason) for (kind, _), reason in gather.dropped.items())
    return Collected(
        indicators=indicators, dropped=dropped, first_seen=timestamp(result.started_at)
    )
