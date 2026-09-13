"""What is this file?

Two sources of truth, in order of trust:

1. **Magic bytes** read off the wire. DirSift asks for the first few kilobytes
   of a file, not the file, so this costs one small request and cannot be
   faked by renaming.
2. **The extension**, which is what the operator typed and is therefore useful
   evidence about intent even when it is a lie.

When the two disagree that disagreement is the finding: ``invoice.pdf`` whose
first two bytes are ``MZ`` is the most interesting row in the listing, and
:func:`mismatch` is what the report keys on.
"""

from __future__ import annotations

from .models import Confidence, Entry, Kind

#: Magic signatures, longest first so that specific beats general.
_MAGIC: list[tuple[bytes, Kind, str]] = [
    (b"MZ", Kind.PE, "DOS/PE executable"),
    (b"\x7fELF", Kind.ELF, "ELF binary"),
    (b"\xca\xfe\xba\xbe", Kind.MACHO, "Mach-O fat binary"),
    (b"\xcf\xfa\xed\xfe", Kind.MACHO, "Mach-O 64-bit"),
    (b"\xfe\xed\xfa\xce", Kind.MACHO, "Mach-O 32-bit"),
    (b"PK\x03\x04", Kind.ARCHIVE, "ZIP (also jar, apk, docx, xlsx)"),
    (b"Rar!\x1a\x07", Kind.ARCHIVE, "RAR"),
    (b"7z\xbc\xaf\x27\x1c", Kind.ARCHIVE, "7-Zip"),
    (b"\x1f\x8b", Kind.ARCHIVE, "gzip"),
    (b"BZh", Kind.ARCHIVE, "bzip2"),
    (b"\xfd7zXZ\x00", Kind.ARCHIVE, "xz"),
    (b"ustar", Kind.ARCHIVE, "tar"),
    (b"%PDF-", Kind.DOCUMENT, "PDF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", Kind.DOCUMENT, "OLE2 (legacy Office)"),
    (b"{\\rtf", Kind.DOCUMENT, "RTF"),
    (b"\x89PNG\r\n\x1a\n", Kind.IMAGE, "PNG"),
    (b"\xff\xd8\xff", Kind.IMAGE, "JPEG"),
    (b"GIF8", Kind.IMAGE, "GIF"),
    (b"BM", Kind.IMAGE, "BMP"),
    (b"\x00\x00\x01\x00", Kind.IMAGE, "ICO"),
    (b"SQLite format 3\x00", Kind.DATA, "SQLite database"),
    (b"-----BEGIN CERTIFICATE-----", Kind.CERT, "PEM certificate"),
    (b"-----BEGIN RSA PRIVATE KEY", Kind.CERT, "PEM private key"),
    (b"-----BEGIN OPENSSH PRIVATE KEY", Kind.CERT, "OpenSSH private key"),
    (b"\x30\x82", Kind.CERT, "DER/PKCS structure"),
]

_EXT_KIND: dict[str, Kind] = {
    # executables
    "exe": Kind.PE, "dll": Kind.PE, "scr": Kind.PE, "sys": Kind.PE, "ocx": Kind.PE,
    "cpl": Kind.PE, "msi": Kind.PE, "com": Kind.PE, "efi": Kind.PE,
    "elf": Kind.ELF, "so": Kind.ELF, "ko": Kind.ELF, "bin": Kind.UNKNOWN,
    # scripts
    "bat": Kind.SCRIPT, "cmd": Kind.SCRIPT, "ps1": Kind.SCRIPT, "psm1": Kind.SCRIPT,
    "vbs": Kind.SCRIPT, "vbe": Kind.SCRIPT, "js": Kind.SCRIPT, "jse": Kind.SCRIPT,
    "wsf": Kind.SCRIPT, "hta": Kind.SCRIPT, "sh": Kind.SCRIPT, "bash": Kind.SCRIPT,
    "py": Kind.SCRIPT, "pyw": Kind.SCRIPT, "pl": Kind.SCRIPT, "rb": Kind.SCRIPT,
    "lnk": Kind.SCRIPT, "scpt": Kind.SCRIPT, "ahk": Kind.SCRIPT, "au3": Kind.SCRIPT,
    # web
    "php": Kind.WEB, "asp": Kind.WEB, "aspx": Kind.WEB, "jsp": Kind.WEB,
    "html": Kind.WEB, "htm": Kind.WEB, "phtml": Kind.WEB, "cgi": Kind.WEB,
    # archives
    "zip": Kind.ARCHIVE, "rar": Kind.ARCHIVE, "7z": Kind.ARCHIVE, "tar": Kind.ARCHIVE,
    "gz": Kind.ARCHIVE, "tgz": Kind.ARCHIVE, "bz2": Kind.ARCHIVE, "xz": Kind.ARCHIVE,
    "cab": Kind.ARCHIVE, "iso": Kind.ARCHIVE, "img": Kind.ARCHIVE, "jar": Kind.ARCHIVE,
    "apk": Kind.ARCHIVE, "vhd": Kind.ARCHIVE,
    # documents
    "pdf": Kind.DOCUMENT, "doc": Kind.DOCUMENT, "docx": Kind.DOCUMENT,
    "xls": Kind.DOCUMENT, "xlsx": Kind.DOCUMENT, "ppt": Kind.DOCUMENT,
    "pptx": Kind.DOCUMENT, "rtf": Kind.DOCUMENT, "one": Kind.DOCUMENT,
    # images
    "png": Kind.IMAGE, "jpg": Kind.IMAGE, "jpeg": Kind.IMAGE, "gif": Kind.IMAGE,
    "bmp": Kind.IMAGE, "ico": Kind.IMAGE, "webp": Kind.IMAGE, "svg": Kind.IMAGE,
    # config
    "json": Kind.CONFIG, "yaml": Kind.CONFIG, "yml": Kind.CONFIG, "ini": Kind.CONFIG,
    "conf": Kind.CONFIG, "cfg": Kind.CONFIG, "xml": Kind.CONFIG, "toml": Kind.CONFIG,
    "env": Kind.CONFIG, "properties": Kind.CONFIG, "plist": Kind.CONFIG,
    # certificates and keys
    "pem": Kind.CERT, "crt": Kind.CERT, "cer": Kind.CERT, "key": Kind.CERT,
    "pfx": Kind.CERT, "p12": Kind.CERT, "der": Kind.CERT, "jks": Kind.CERT,
    # data
    "txt": Kind.DATA, "log": Kind.DATA, "csv": Kind.DATA, "tsv": Kind.DATA,
    "db": Kind.DATA, "sqlite": Kind.DATA, "sql": Kind.DATA, "dat": Kind.DATA,
    "bak": Kind.DATA, "dmp": Kind.DATA, "pcap": Kind.DATA, "har": Kind.DATA,
}

#: Extensions whose contents are worth reading in full during triage.
TEXTUAL_KINDS = {Kind.SCRIPT, Kind.CONFIG, Kind.DATA, Kind.WEB, Kind.CERT}

#: Sniff results that only prove "this is not binary" and nothing more.
_WEAK_TEXT_KINDS = {Kind.DATA, Kind.WEB, Kind.CONFIG}

#: Names that usually mark the entry point of whatever is staged here.
INTERESTING_NAMES = {
    "readme", "readme.txt", "notes.txt", "todo.txt", "install", "setup",
    "run", "start", "build", "deploy", "main", "index", "config", "settings",
    ".env", ".git", ".bash_history", "id_rsa", "known_hosts", "passwords.txt",
    "creds.txt", "accounts.txt", "bot.py", "panel", "gate.php", "login.php",
}


def sniff(head: bytes) -> tuple[Kind, str] | None:
    """Match ``head`` against the magic table. Returns (kind, description)."""
    if not head:
        return None
    for signature, kind, description in _MAGIC:
        if signature == b"ustar":
            if head[257:262] == b"ustar":
                return kind, description
            continue
        if head.startswith(signature):
            return kind, description

    sample = head[:1024]
    if b"\x00" not in sample:
        stripped = sample.lstrip()
        if stripped.startswith((b"#!", b"<?php", b"<%", b"<script")):
            return Kind.SCRIPT, "script (shebang or tag)"
        if stripped.startswith((b"{", b"[")) and b'"' in sample:
            return Kind.CONFIG, "JSON-ish text"
        if stripped.startswith(b"<"):
            return Kind.WEB, "markup"
        return Kind.DATA, "plain text"
    return None


def kind_from_extension(ext: str) -> Kind:
    return _EXT_KIND.get(ext.lower(), Kind.UNKNOWN)


def classify(entry: Entry, head: bytes | None = None) -> Entry:
    """Set ``kind``, ``confidence`` and ``magic`` on ``entry`` in place."""
    if entry.is_dir:
        entry.kind = Kind.UNKNOWN
        entry.confidence = Confidence.NONE
        return entry

    sniffed = sniff(head) if head else None
    if sniffed is not None:
        kind, description = sniffed
        by_ext = kind_from_extension(entry.ext)

        # A ZIP is the container for a dozen formats; let a specific extension
        # refine it rather than flattening everything to "archive".
        if kind is Kind.ARCHIVE and entry.ext in ("docx", "xlsx", "pptx", "jar", "apk"):
            kind = by_ext
        # "Plain text" is a weak verdict. A .bat file is text, a .ps1 is text,
        # a stolen password dump is text. Where the bytes only prove it is not
        # binary, the extension carries the real information.
        elif kind in _WEAK_TEXT_KINDS and by_ext in TEXTUAL_KINDS:
            kind = by_ext
            description = f"{description}, .{entry.ext}"

        entry.kind = kind
        entry.magic = description
        entry.confidence = Confidence.SNIFFED
        return entry

    by_ext = kind_from_extension(entry.ext)
    entry.kind = by_ext
    entry.confidence = Confidence.EXTENSION if by_ext is not Kind.UNKNOWN else Confidence.NONE
    return entry


def mismatch(entry: Entry) -> str | None:
    """Describe a disagreement between the name and the bytes, if any.

    This is the row a triage analyst should look at first.
    """
    if entry.confidence is not Confidence.SNIFFED or not entry.ext:
        return None
    claimed = kind_from_extension(entry.ext)
    if claimed is Kind.UNKNOWN or claimed is entry.kind:
        return None
    # Text-shaped things are routinely mislabelled without meaning anything.
    benign = {Kind.DATA, Kind.CONFIG, Kind.WEB}
    if claimed in benign and entry.kind in benign:
        return None
    return f".{entry.ext} on disk, {entry.magic or entry.kind} on the wire"


def is_textual(entry: Entry) -> bool:
    """Whether the body is worth reading for references and indicators."""
    if entry.is_dir:
        return False
    if entry.kind in TEXTUAL_KINDS:
        return True
    return entry.confidence is Confidence.NONE and (entry.size or 0) < 512_000
