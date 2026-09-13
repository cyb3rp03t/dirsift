"""Directory listing parsers.

Every web server renders an index differently, and most of them have rendered
it the same way for twenty years, so the flavours are worth recognising by
name: the flavour tells you what the box is running before you have looked at
a single file.

Supported: Apache ``mod_autoindex`` (both the ``<pre>`` and the table layout),
nginx ``autoindex``, nginx/Caddy JSON autoindex, IIS, Python ``http.server``,
Caddy's ``file_server browse``, lighttpd, h5ai, and a generic fallback that
scrapes anchors out of anything else.

Two rules run through all of it:

* a link is only a candidate if the page actually contains it; nothing is
  constructed, appended or guessed;
* sort links, parent links, absolute links off-host and non-HTTP schemes are
  dropped before they ever reach the fetcher.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlparse

from bs4 import BeautifulSoup

from .fetcher import Response

#: Query strings Apache and friends put on column headers.
_SORT_QUERY = re.compile(r"^[?;](C=[NMSD];O=[AD]|N=[AD]|M=[AD]|S=[AD]|D=[AD])$", re.I)

# Accepts 4321, 4.2K, 842KiB, 1.4MB. The i in KiB is decoration: every server
# in this list means 1024 whichever way it spells it.
_SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([KMGTP])?i?B?$", re.I)
_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4, "P": 1024**5}

# "  12-Feb-2026 09:41   4.2K" / " 2026-02-12 09:41  4321" / "2/12/2026 9:41 AM  4321"
_NGINX_TAIL = re.compile(
    r"\s*(?P<date>\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?"
    r"|\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}(?:\s*[AP]M)?)"
    r"\s+(?P<size>[\d.]+\s*[KMGTP]?B?|<dir>|-)\s*$",
    re.I,
)


@dataclass
class RawEntry:
    """One row of a listing, before any classification."""

    name: str
    url: str
    is_dir: bool
    size: int | None = None
    modified: str | None = None


@dataclass
class Listing:
    flavor: str
    title: str | None
    entries: list[RawEntry]


def parse_size(raw: str | None) -> int | None:
    """Turn ``4.2K`` / ``4321`` / ``-`` into bytes, or None."""
    if not raw:
        return None
    raw = raw.strip().replace(",", "").replace("\xa0", " ")
    if raw in ("-", "", "<dir>", "&nbsp;"):
        return None
    match = _SIZE_RE.match(raw.replace(" ", ""))
    if not match:
        return None
    value, unit = match.group(1), match.group(2) or ""
    try:
        return int(float(value) * _UNITS[unit.upper()])
    except (ValueError, KeyError):
        return None


def detect_flavor(response: Response, soup: BeautifulSoup | None) -> str:
    """Name the index generator from headers plus a few tells in the markup."""
    server = response.headers.get("server", "").lower()
    body = response.text[:4000].lower()

    if response.content_type == "application/json":
        return "json"
    if "h5ai" in body:
        return "h5ai"

    # The Server header, when there is one, beats every guess drawn from markup:
    # Apache and nginx both emit "<h1>Index of" inside a <pre>, so body tells
    # alone cannot separate them.
    for needle, flavor in (
        ("apache", "apache"),
        ("nginx", "nginx"),
        ("microsoft-iis", "iis"),
        ("caddy", "caddy"),
        ("lighttpd", "lighttpd"),
        ("python", "python"),
    ):
        if needle in server:
            return flavor

    if "directory listing for" in body:
        return "python"
    if 'class="listing"' in body or "id=filelist" in body:
        return "caddy"
    if "mod_autoindex" in body or 'alt="[dir]"' in body:
        return "apache"
    if "<h1>index of" in body and "<pre>" in body:
        return "nginx"
    if soup is not None and soup.find("h1", string=re.compile(r"index of", re.I)):
        return "apache"
    return "generic"


def _is_followable(href: str, base_url: str) -> bool:
    """Reject sort links, parents, anchors, and anything leaving the host."""
    if not href or href.startswith("#"):
        return False
    if _SORT_QUERY.match(href):
        return False
    lowered = href.lower()
    if lowered.startswith(("mailto:", "javascript:", "data:", "tel:", "ftp:")):
        return False
    if href in ("../", "..", "./", "/"):
        return False

    target = urljoin(base_url, href)
    parsed = urlparse(target)
    base = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.netloc.lower() != base.netloc.lower():
        return False
    # A link that climbs above the directory being listed is a parent link.
    base_path = unquote(base.path)
    if not base_path.endswith("/"):
        base_path = base_path.rsplit("/", 1)[0] + "/"
    return unquote(parsed.path).startswith(base_path) and unquote(parsed.path) != base_path


def _entry_from_anchor(anchor, base_url: str) -> RawEntry | None:
    href = (anchor.get("href") or "").strip()
    if not _is_followable(href, base_url):
        return None

    url = urljoin(base_url, href)
    text = anchor.get_text(strip=True)
    # Apache truncates long names in the link text with an ellipsis; the href
    # is the truth.
    path_name = unquote(urlparse(url).path.rstrip("/").rsplit("/", 1)[-1])
    is_dir = href.endswith("/") or text.endswith("/")
    name = path_name or text.rstrip("/")
    if not name or name in (".", ".."):
        return None
    if text.strip().lower() in ("parent directory", "..", "up to higher level directory"):
        return None
    return RawEntry(name=name, url=url, is_dir=is_dir)


def _parse_json_listing(response: Response, base_url: str) -> list[RawEntry]:
    """nginx ``autoindex_format json`` and Caddy's JSON browse output."""
    try:
        payload = json.loads(response.text)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        payload = payload.get("files") or payload.get("entries") or payload.get("items") or []
    if not isinstance(payload, list):
        return []

    entries: list[RawEntry] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("Name") or "").strip()
        if not name or name in (".", ".."):
            continue
        raw_type = str(item.get("type") or item.get("mime") or "").lower()
        is_dir = raw_type in ("directory", "dir") or bool(item.get("is_dir") or item.get("IsDir"))
        size = item.get("size") or item.get("Size")
        entries.append(
            RawEntry(
                name=name,
                url=urljoin(base_url, name + ("/" if is_dir else "")),
                is_dir=is_dir,
                size=int(size) if isinstance(size, int | float) else parse_size(str(size or "")),
                modified=str(item.get("mtime") or item.get("ModTime") or "") or None,
            )
        )
    return entries


def _augment_from_pre(soup: BeautifulSoup, entries: dict[str, RawEntry]) -> None:
    """Pull the date and size that trail each anchor inside a <pre> block.

    Apache, nginx, IIS and lighttpd all emit ``<a>name</a>   date   size`` as
    plain text inside ``<pre>``, so one pass over the tail text covers them.
    """
    for pre in soup.find_all("pre"):
        for anchor in pre.find_all("a"):
            tail = ""
            node = anchor.next_sibling
            while node is not None and getattr(node, "name", None) != "a":
                text = node if isinstance(node, str) else node.get_text()
                tail += text
                if "\n" in tail:
                    break
                node = node.next_sibling
            tail = tail.split("\n")[0]
            match = _NGINX_TAIL.search(tail)
            if not match:
                continue
            href = (anchor.get("href") or "").strip()
            entry = entries.get(href)
            if entry is None:
                continue
            entry.modified = entry.modified or match.group("date").strip()
            entry.size = entry.size if entry.size is not None else parse_size(match.group("size"))


def _augment_from_table(soup: BeautifulSoup, entries: dict[str, RawEntry]) -> None:
    """Apache's table layout, Caddy, lighttpd and most themed indexes."""
    for row in soup.find_all("tr"):
        anchor = row.find("a", href=True)
        if anchor is None:
            continue
        entry = entries.get(anchor["href"].strip())
        if entry is None:
            continue
        cells = [c.get_text(strip=True).replace("\xa0", " ") for c in row.find_all(["td", "th"])]
        for cell in cells[1:]:
            if entry.size is None:
                size = parse_size(cell)
                if size is not None:
                    entry.size = size
                    continue
            if entry.modified is None and re.search(r"\d{4}|\d{2}:\d{2}", cell):
                entry.modified = cell


def parse_listing(response: Response, base_url: str) -> Listing:
    """Parse one directory index into rows.

    Returns an empty entry list when the page is not a listing at all, which is
    how the walker decides a URL was a file wearing a directory's clothes.
    """
    if response.content_type == "application/json":
        return Listing("json", None, _parse_json_listing(response, base_url))

    soup = BeautifulSoup(response.text, "lxml")
    flavor = detect_flavor(response, soup)
    title_tag = soup.find("title")
    title = title_tag.get_text(strip=True) if title_tag else None

    by_href: dict[str, RawEntry] = {}
    ordered: list[RawEntry] = []
    for anchor in soup.find_all("a", href=True):
        entry = _entry_from_anchor(anchor, base_url)
        if entry is None:
            continue
        href = anchor["href"].strip()
        if href in by_href or any(e.url == entry.url for e in ordered):
            continue
        by_href[href] = entry
        ordered.append(entry)

    _augment_from_pre(soup, by_href)
    _augment_from_table(soup, by_href)

    return Listing(flavor=flavor, title=title, entries=ordered)


def looks_like_listing(response: Response, listing: Listing) -> bool:
    """Decide whether a fetched page really was an index.

    A single link on a page full of prose is a website. A page whose links are
    nearly all relative siblings, or whose title says so, is an index.
    """
    if listing.flavor == "json":
        return bool(listing.entries)
    text = response.text[:2000].lower()
    if re.search(r"index of |directory listing for |<title>\s*index of", text):
        return True
    if not listing.entries:
        return False
    body_text = BeautifulSoup(response.text, "lxml").get_text(" ", strip=True)
    link_chars = sum(len(e.name) for e in listing.entries)
    # An index is mostly filenames; a page is mostly words.
    return len(listing.entries) >= 3 and link_chars > 0.25 * max(len(body_text), 1)
