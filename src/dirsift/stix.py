"""A saved run as a STIX 2.1 bundle, for OpenCTI, MISP and the like.

DirSift collects; it does not decide. The bundle keeps to that. It carries the
infrastructure that was walked, the files read whole with their hashes, and the
addresses, names and URLs lifted out of them, each with where it came from.
There is no Malware object and no ``malicious-activity``: whether any of this is
hostile is the analyst's call, made on the platform, not a default made here.

STIX is for machines, and a defanged value matches nothing on a platform, so
the bundle carries live values. That is why the command only ever writes it to
a file.

Identifiers are deterministic. Observables use the namespace the specification
fixes, so an address found in two runs, or by two tools, lands on one object.
Everything else is derived from the root URL and what the object describes, so
importing the same run twice adds nothing the second time.

Nothing here touches the network.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import UTC, datetime
from urllib.parse import unquote, urlparse

from .classify import mismatch
from .extract import SecretPieces
from .models import Entry, Ioc, Kind, ScanResult
from .pivots import internal_address

#: The namespace STIX 2.1 fixes for observable identifiers.
SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

#: DirSift's own namespace for every other identifier. Generated once and
#: written down, because the point of it is never changing: the same run must
#: always give the same identifiers, so a platform that sees it twice sees it
#: once.
DIRSIFT_NAMESPACE = uuid.UUID("5a260dc8-7914-4b8a-96a1-a6e013672546")


def canonical(value: object) -> str:
    """JSON in the canonical form identifiers are computed over (RFC 8785).

    Sorted keys, no whitespace, characters left as they are. For the strings
    and integers an observable's identity is made of, this is the whole of it.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def observable_id(kind: str, contributing: dict[str, object]) -> str:
    """The identifier an observable gets from its contributing properties."""
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, canonical(contributing))}"


def object_id(kind: str, root_url: str, key: str) -> str:
    """A stable identifier for a domain object, a relationship or the bundle.

    Derived from a name-based UUID over the root URL and what the object
    describes, so it never changes between exports. The version bits are then
    set to 4, because STIX asks for UUIDv4 on these objects and validators
    enforce it: the identifier is still entirely determined by its name.
    """
    derived = uuid.uuid5(DIRSIFT_NAMESPACE, f"{kind}|{root_url}|{key}")
    return f"{kind}--{uuid.UUID(bytes=derived.bytes, version=4)}"


def file_identity(name: str, hashes: dict[str, str]) -> dict[str, object]:
    """The properties a file's identifier is computed from.

    A file is identified by its name and by one hash, not by all of them, so
    that two tools holding different digests of one file still agree. The
    hash is picked in the order the specification gives.
    """
    for algorithm in ("MD5", "SHA-1", "SHA-256", "SHA-512"):
        if algorithm in hashes:
            return {"hashes": {algorithm: hashes[algorithm]}, "name": name}
    return {"name": name}


def timestamp(value: datetime) -> str:
    """RFC 3339 in UTC with milliseconds, the way every STIX timestamp is written.

    A time without a zone is taken as UTC, never as the local clock: the
    machine that exports a run should not change what the run says.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def pattern_string(value: str) -> str:
    """A value quoted for a STIX pattern: backslash and quote escaped, in that order."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


# The bundle

#: File kinds that make a directory a host for something that runs.
RUNNABLE = {Kind.PE, Kind.ELF, Kind.MACHO, Kind.SCRIPT}

#: Indicator types that become observables, and the observable each becomes.
#: Credentials, wallets, mutexes and paths stay out: a secret in particular
#: never leaves the run in a file meant for sharing.
EXPORTED = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name", "url": "url"}


class _Builder:
    """Collects objects by identifier, so the same thing is only written once."""

    def __init__(self, result: ScanResult, only=None) -> None:
        self.result = result
        self.root = result.root_url
        self.when = timestamp(result.started_at)
        self.objects: dict[str, dict] = {}
        # What the shared filter kept, as (kind, value, source paths), or None
        # for the whole run.
        self.only_items = (
            None
            if only is None
            else [(item.kind, item.value, tuple(item.sources)) for item in only.indicators]
        )
        self.only = (
            None if only is None else {(kind, value) for kind, value, _ in self.only_items}
        )

    def allowed(self, kind: str, value: str) -> bool:
        return self.only is None or (kind, value) in self.only

    def keep(self, obj: dict) -> str:
        self.objects.setdefault(obj["id"], obj)
        return obj["id"]

    def observable(self, kind: str, contributing: dict[str, object], **extra) -> str:
        return self.keep(
            {
                "type": kind,
                "spec_version": "2.1",
                "id": observable_id(kind, contributing),
                **contributing,
                **extra,
            }
        )

    def domain_object(self, kind: str, key: str, **fields) -> str:
        return self.keep(
            {
                "type": kind,
                "spec_version": "2.1",
                "id": object_id(kind, self.root, key),
                "created": self.when,
                "modified": self.when,
                **fields,
            }
        )

    def relate(self, kind: str, source: str, target: str) -> str:
        return self.domain_object(
            "relationship",
            f"{kind}|{source}|{target}",
            relationship_type=kind,
            source_ref=source,
            target_ref=target,
        )

    def address(self, value: str) -> str | None:
        """An ipv4-addr or ipv6-addr for an address, or None for anything else."""
        version = _ip_version(value)
        if version is None:
            return None
        return self.observable("ipv4-addr" if version == 4 else "ipv6-addr", {"value": value})


def _ip_version(value: str) -> int | None:
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        return None


def _infrastructure(build: _Builder) -> str:
    """The directory itself, described and not judged."""
    result = build.result
    parsed = urlparse(result.root_url)
    files = len(result.files)
    title = f', titled "{result.title}"' if result.title else ""
    description = (
        f"Open directory index ({result.listing_flavor or 'unknown flavour'}) served by "
        f"{result.server or 'a server that did not name itself'}{title}, listing "
        f"{files} file{'s' if files != 1 else ''}, walked by dirsift on "
        f"{build.when[:10]}. dirsift records what was served "
        "and makes no judgement about it."
    )
    runnable = any(entry.kind in RUNNABLE for entry in result.files)
    return build.domain_object(
        "infrastructure",
        "target",
        name=parsed.netloc + (parsed.path or "/"),
        description=description,
        infrastructure_types=["hosting-malware" if runnable else "unknown"],
        first_seen=build.when,
        last_seen=timestamp(result.finished_at or result.started_at),
    )


def _target(build: _Builder, infrastructure: str) -> str | None:
    """What the target is made of: its URL, its name, its address."""
    result = build.result
    host = urlparse(result.root_url).hostname or ""
    parts = []
    if build.allowed("url", result.root_url):
        parts.append(build.observable("url", {"value": result.root_url}))
    address = result.target_ip or host
    version = _ip_version(address) if address else None
    address_kind = "ipv4" if version == 4 else "ipv6"
    target_address = (
        build.address(address)
        if address and version and build.allowed(address_kind, address.lower())
        else None
    )
    if host and _ip_version(host) is None and build.allowed("domain", host.lower()):
        parts.append(build.observable("domain-name", {"value": host}))
    if target_address:
        parts.append(target_address)
        _network(build, target_address, result.target_asn, result.target_as_name)
    for part in parts:
        build.relate("consists-of", infrastructure, part)
    return target_address


def _network(build: _Builder, address: str, asn: int | None, name: str | None) -> None:
    """The AS an address was placed in, from the run's own table, as an edge."""
    if not asn:
        return
    extra = {"name": name} if name else {}
    system = build.observable("autonomous-system", {"number": asn}, **extra)
    build.relate("belongs-to", address, system)


def _relative(entry: Entry, root: str) -> str:
    """The file's path under the root, as hashes and the report print it."""
    return unquote(entry.url.removeprefix(root)) or entry.name


def _about(entry: Entry) -> str:
    """What the run knows about a file, without a word about whether it is hostile."""
    facts = [f"{entry.kind} file read whole by dirsift"]
    lie = mismatch(entry)
    if lie:
        facts.append(f"type mismatch, {lie}")
    if entry.cluster:
        facts.append(f"one build of the {entry.cluster} family")
    if entry.glue_score > 0:
        facts.append(f"entry point candidate, scored {entry.glue_score}/100")
    return "; ".join(facts) + "."


def _files(build: _Builder, infrastructure: str) -> dict[str, str]:
    """A file observable and a hash indicator for every file read whole.

    A file cut at the peek ceiling is left out: its hash describes the bytes
    that were read, which is not a file anyone else has. Returns the file
    observable for each file URL, so indicators can be tied to where they sat.
    """
    by_url: dict[str, str] = {}
    for entry in build.result.files:
        if not entry.sha256:
            continue
        if build.only is not None and (
            entry.truncated or not build.allowed("sha256", entry.sha256.lower())
        ):
            continue
        hashes = {"SHA-256": entry.sha256}
        if entry.md5 and build.allowed("md5", entry.md5.lower()):
            hashes = {"MD5": entry.md5, **hashes}
        extra: dict[str, object] = {"hashes": hashes}
        if entry.size is not None:
            extra["size"] = entry.size
        observed = build.observable("file", file_identity(entry.name, hashes), **extra)
        build.relate("consists-of", infrastructure, observed)
        by_url[entry.url] = observed

        path = _relative(entry, build.root)
        indicator = build.domain_object(
            "indicator",
            f"file|{path}|{entry.sha256}",
            name=path,
            description=_about(entry),
            pattern=f"[file:hashes.'SHA-256' = {pattern_string(entry.sha256)}]",
            pattern_type="stix",
            valid_from=build.when,
        )
        build.relate("indicates", indicator, infrastructure)
    return by_url


def _exportable(ioc: Ioc, secrets: SecretPieces | None = None) -> tuple[str, str] | None:
    """The observable type and live value for an indicator, or None to leave it out.

    An address with a port keeps only the address. An address nobody outside
    the operator's network can reach, or a URL pointing at one, is left out:
    it identifies nothing to a platform.
    """
    kind = EXPORTED.get(ioc.ioc_type)
    if kind is None:
        return None
    value = ioc.value
    if secrets is not None and secrets.carried_by(value):
        # A webhook is a URL and a secret at once; the secret wins.
        return None
    if ioc.ioc_type == "ipv4":
        value = value.split(":", 1)[0]
    host = urlparse(value).hostname if ioc.ioc_type == "url" else value
    if host and internal_address(host):
        return None
    return kind, value


def _private(ioc: Ioc) -> bool:
    """Whether an indicator was left out for pointing at a private address."""
    return ioc.ioc_type in EXPORTED and _exportable(ioc) is None


def _indicators(build: _Builder, infrastructure: str, files: dict[str, str]) -> None:
    """An observable and an indicator for every address, name and URL in the files.

    The description says which files it came from and nothing of the line it
    sat on: that line is the target's own text and can carry other live values.
    """
    if build.only is not None:
        _kept_indicators(build, infrastructure, files)
        return
    secrets = SecretPieces(build.result.iocs)
    for ioc in build.result.iocs:
        exported = _exportable(ioc, secrets)
        if exported is None:
            continue
        kind, value = exported
        observed = build.observable(kind, {"value": value})
        if kind in ("ipv4-addr", "ipv6-addr"):
            _network(build, observed, ioc.asn, ioc.as_name)

        sources = ioc.sources or [ioc.source_url]
        paths = sorted({_relative_url(url, build.root) for url in sources})
        indicator = build.domain_object(
            "indicator",
            f"{kind}|{value}",
            name=value,
            description=f"Found in {', '.join(paths)}; extracted from file contents by dirsift.",
            pattern=f"[{kind}:value = {pattern_string(value)}]",
            pattern_type="stix",
            valid_from=build.when,
        )
        build.relate("indicates", indicator, infrastructure)
        for url in sources:
            if url in files:
                build.relate("related-to", files[url], observed)


#: The shared filter's names for the types that become observables here.
FILTERED = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name", "url": "url"}


def _kept_indicators(build: _Builder, infrastructure: str, files: dict[str, str]) -> None:
    """One observable and one indicator for each value the shared filter kept.

    The filter has already decided what may travel: private, documentation and
    resolver addresses, shared hosts at host level and anything carrying a
    secret are gone, and a URL's host is there in its own right.
    """
    result = build.result
    by_path = {_relative(entry, build.root): entry.url for entry in result.files}
    placed: dict[str, tuple[int | None, str | None]] = {}
    for ioc in result.iocs:
        if ioc.asn and ioc.ioc_type in ("ipv4", "ipv6"):
            placed.setdefault(ioc.value.split(":", 1)[0], (ioc.asn, ioc.as_name))
    if result.target_ip and result.target_asn:
        placed.setdefault(result.target_ip, (result.target_asn, result.target_as_name))
    for kind, value, paths in build.only_items or []:
        sco = FILTERED.get(kind)
        if sco is None:
            continue
        observed = build.observable(sco, {"value": value})
        if sco in ("ipv4-addr", "ipv6-addr") and value in placed:
            _network(build, observed, *placed[value])
        where = ", ".join(paths) if paths else "the directory itself"
        indicator = build.domain_object(
            "indicator",
            f"{sco}|{value}",
            name=value,
            description=f"Found in {where}; extracted from file contents by dirsift.",
            pattern=f"[{sco}:value = {pattern_string(value)}]",
            pattern_type="stix",
            valid_from=build.when,
        )
        build.relate("indicates", indicator, infrastructure)
        for path in paths:
            url = by_path.get(path)
            if url in files:
                build.relate("related-to", files[url], observed)


def _relative_url(url: str, root: str) -> str:
    return unquote(url.removeprefix(root)) or url


def left_out(result: ScanResult) -> dict[str, int]:
    """What the bundle does not carry, counted for the person exporting it."""
    return {
        "files without a hash": sum(1 for e in result.files if not e.sha256),
        "private addresses": sum(1 for ioc in result.iocs if _private(ioc)),
    }


# Marking and authorship

#: The TLP marking definitions STIX 2.1 itself fixes (section 7.2.1.4). They are
#: TLP 1.0, so TLP:CLEAR is written as its 1.0 name, WHITE: a platform knows
#: these identifiers without being told.
TLP_MARKINGS = {
    "CLEAR": ("white", "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"),
    "GREEN": ("green", "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"),
    "AMBER": ("amber", "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"),
    "RED": ("red", "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"),
}

#: Who wrote the bundle. Fixed, so every run names the same author object.
AUTHOR_NAME = "cyb3rp03t"
AUTHOR_CREATED = "2026-09-13T00:00:00.000Z"


def tlp_marking(level: str) -> dict:
    colour, identifier = TLP_MARKINGS[level]
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": identifier,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:" + colour.upper(),
        "definition": {"tlp": colour},
    }


def author_identity() -> dict:
    derived = uuid.uuid5(DIRSIFT_NAMESPACE, "identity|" + AUTHOR_NAME)
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.UUID(bytes=derived.bytes, version=4)}",
        "created": AUTHOR_CREATED,
        "modified": AUTHOR_CREATED,
        "name": AUTHOR_NAME,
        "identity_class": "individual",
    }


def _mark(objects: dict[str, dict], level: str) -> None:
    """Label every object and name the author on every object that has one.

    Observables carry markings but no author: STIX gives them no
    ``created_by_ref``.
    """
    marking = tlp_marking(level)
    author = author_identity()
    for obj in objects.values():
        obj["object_marking_refs"] = [marking["id"]]
        if "created" in obj:
            obj["created_by_ref"] = author["id"]
    author["object_marking_refs"] = [marking["id"]]
    objects[author["id"]] = author
    objects[marking["id"]] = marking


def build_bundle(
    result: ScanResult, candidates, *, tlp: str | None = None, only=None
) -> dict:
    """Every object this run supports, as one bundle. Reads the run, changes nothing.

    With ``tlp`` (CLEAR, GREEN, AMBER or RED) every object carries that marking
    and every domain object and relationship names its author.

    ``only`` is the shared filter's result (``detections.collect``): given, the
    bundle carries exactly the values it kept and nothing else, so the rule
    pack's count and its file agree. Without it, the bundle is the whole run,
    as ``dirsift stix`` writes it.
    """
    build = _Builder(result, only)
    infrastructure = _infrastructure(build)
    _target(build, infrastructure)
    files = _files(build, infrastructure)
    _indicators(build, infrastructure, files)
    if tlp is not None:
        _mark(build.objects, tlp)
    return {
        "type": "bundle",
        "id": object_id("bundle", result.root_url, timestamp(result.started_at)),
        "objects": list(build.objects.values()),
    }


def bundle_json(bundle: dict) -> str:
    """The bundle as text: objects ordered by type then identifier, every time."""
    ordered = dict(bundle)
    ordered["objects"] = sorted(bundle["objects"], key=lambda obj: (obj["type"], obj["id"]))
    return json.dumps(ordered, ensure_ascii=False, indent=2) + "\n"
