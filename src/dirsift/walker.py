"""Walk an open directory breadth-first and build a :class:`ScanResult`.

The walk is bounded on four axes at once, because the thing on the other end
is not a friendly server and a runaway crawler is both rude and conspicuous:
depth, total entries, total requests, and the bytes read per file.

Breadth-first is deliberate. If the budget runs out, what you have is the top
of the tree, which is where the entry point almost always sits: the loader,
the batch file, the panel. Depth-first would spend the budget in
``/img/icons/`` and never come back.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from .classify import classify, is_textual
from .fetcher import AuthWall, PoliteFetcher, Scope, ScopeError, normalize_url
from .listing import looks_like_listing, parse_listing
from .models import Entry, ScanError, ScanResult

#: Text kept per file for the reference and indicator passes.
PREVIEW_CHARS = 200_000

#: Bytes kept per file for the hex view. They were fetched anyway.
HEAD_BYTES = 256


@dataclass
class ScanOptions:
    depth: int = 2
    max_entries: int = 1000
    max_requests: int = 600
    delay: float = 1.0
    timeout: float = 20.0
    peek: bool = True
    peek_bytes: int = 65_536
    allow_private: bool = False
    verify_tls: bool = False
    proxy: str | None = None
    progress: Callable[[str, str], None] | None = field(default=None, repr=False)

    def as_dict(self) -> dict[str, object]:
        return {
            k: v for k, v in self.__dict__.items() if k != "progress"
        }


def _say(options: ScanOptions, event: str, detail: str) -> None:
    if options.progress is not None:
        options.progress(event, detail)


def scan(root_url: str, options: ScanOptions | None = None) -> ScanResult:
    """Walk ``root_url`` and return everything learned about it."""
    options = options or ScanOptions()
    root = normalize_url(root_url)
    if not root.endswith("/"):
        root += "/"

    scope = Scope(root=root, allow_private=options.allow_private)
    result = ScanResult(root_url=root, options=options.as_dict())

    with PoliteFetcher(
        scope,
        delay=options.delay,
        timeout=options.timeout,
        peek_bytes=max(options.peek_bytes, 8192),
        verify_tls=options.verify_tls,
        proxy=options.proxy,
    ) as fetcher:
        queue: deque[tuple[str, int]] = deque([(root, 0)])
        seen_dirs: set[str] = {root}
        seen_files: set[str] = set()
        pending_peek: list[Entry] = []

        # --- phase 1: walk the tree ---------------------------------------
        while queue:
            if fetcher.requests_made >= options.max_requests:
                result.errors.append(
                    ScanError(url=root, stage="walk", detail="request budget exhausted")
                )
                break
            if len(result.entries) >= options.max_entries:
                result.errors.append(
                    ScanError(url=root, stage="walk", detail="entry budget exhausted")
                )
                break

            url, depth = queue.popleft()
            _say(options, "listing", url)

            try:
                response = fetcher.get(url, max_bytes=2_000_000)
            except AuthWall as exc:
                result.errors.append(ScanError(url=url, stage="walk", detail=str(exc)))
                continue
            except (ScopeError, httpx.HTTPError) as exc:
                result.errors.append(
                    ScanError(url=url, stage="walk", detail=f"{type(exc).__name__}: {exc}")
                )
                continue

            if response.status >= 400:
                result.errors.append(
                    ScanError(url=url, stage="walk", detail=f"HTTP {response.status}")
                )
                continue

            listing = parse_listing(response, url)

            if url == root:
                result.server = response.headers.get("server")
                result.listing_flavor = listing.flavor
                result.title = listing.title
                if not looks_like_listing(response, listing):
                    result.errors.append(
                        ScanError(
                            url=url,
                            stage="walk",
                            detail=(
                                "the root does not look like a directory index; "
                                "parsing it anyway, results may be noise"
                            ),
                        )
                    )

            for raw in listing.entries:
                if len(result.entries) >= options.max_entries:
                    break
                target = normalize_url(raw.url)
                if raw.is_dir and target.rstrip("/") + "/" in seen_dirs:
                    continue
                if not raw.is_dir and target in seen_files:
                    continue

                entry = Entry(
                    url=target,
                    name=raw.name,
                    is_dir=raw.is_dir,
                    depth=depth + 1,
                    parent_url=url,
                    size=raw.size,
                    modified=raw.modified,
                )
                result.entries.append(entry)

                if raw.is_dir:
                    normalized_dir = target.rstrip("/") + "/"
                    seen_dirs.add(normalized_dir)
                    if depth + 1 <= options.depth:
                        queue.append((normalized_dir, depth + 1))
                else:
                    seen_files.add(target)
                    if options.peek:
                        pending_peek.append(entry)

        # --- phase 2: look at the files -----------------------------------
        for entry in pending_peek:
            if fetcher.requests_made >= options.max_requests:
                result.errors.append(
                    ScanError(url=entry.url, stage="peek", detail="request budget exhausted")
                )
                break

            _say(options, "peek", entry.name)
            try:
                response = fetcher.get(entry.url, max_bytes=options.peek_bytes)
            except AuthWall as exc:
                result.errors.append(ScanError(url=entry.url, stage="peek", detail=str(exc)))
                continue
            except (ScopeError, httpx.HTTPError) as exc:
                result.errors.append(
                    ScanError(
                        url=entry.url, stage="peek", detail=f"{type(exc).__name__}: {exc}"
                    )
                )
                continue

            if response.status >= 400:
                result.errors.append(
                    ScanError(url=entry.url, stage="peek", detail=f"HTTP {response.status}")
                )
                continue

            entry.content_type = response.content_type or None
            entry.fetched_bytes = len(response.body)
            entry.sha256 = response.sha256
            entry.md5 = response.md5
            entry.truncated = response.truncated
            entry.head_hex = response.body[:HEAD_BYTES].hex()
            classify(entry, response.body[:8192])

            # A listing can link to a subdirectory without a trailing slash.
            # If what came back is itself an index, treat it as one.
            if entry.kind.value in ("web", "unknown") and "html" in (entry.content_type or ""):
                sub = parse_listing(response, entry.url)
                if looks_like_listing(response, sub):
                    entry.is_dir = True
                    entry.kind = entry.kind.__class__.UNKNOWN
                    continue

            if is_textual(entry):
                entry.text_preview = response.text[:PREVIEW_CHARS]

        result.requests_made = fetcher.requests_made
        result.bytes_fetched = fetcher.bytes_fetched

    result.finished_at = datetime.now(UTC)
    return result
