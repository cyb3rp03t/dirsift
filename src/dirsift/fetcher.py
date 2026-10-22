"""The HTTP layer, and the place where the rules of engagement live.

DirSift points at infrastructure that belongs to someone else, so the limits
are in the code rather than in the README where they are easy to ignore:

* **GET and HEAD only.** No other method is reachable from this module.
* **No path guessing.** Every URL requested must have been linked from a
  listing DirSift already parsed. There is no wordlist, no brute force, no
  ``/admin`` probe. Reading what a server volunteers is a different act from
  discovering what it does not.
* **No credentials, ever.** A 401 or a 407 ends that branch of the walk. The
  client carries no auth and will not accept any.
* **Stay under the root.** A link that leaves the host, the scheme or the
  starting path is recorded and not followed.
* **Slow on purpose.** One request per second by default, with Retry-After
  honoured, because a scan should not read as a denial of service.
* **Bounded reads.** File bodies are streamed and cut off after a small
  ceiling; DirSift wants the first bytes for a magic check, not the payload.

The rate limiter and the scope check are not configurable away. The delay can
be raised but not dropped to zero, and the scope can be widened to other paths
on the same host but never to another host.
"""

from __future__ import annotations

import hashlib
import ipaddress
import random
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import unquote, urljoin, urlparse, urlunparse

import httpx

USER_AGENT = "dirsift/0.1 (open directory triage; +https://github.com/cyb3rp03t/dirsift)"

#: Bodies are streamed and cut here. Enough for a magic check and a script read.
DEFAULT_PEEK_BYTES = 256 * 1024

#: Floor on the politeness delay. Not a suggestion.
MIN_DELAY = 0.2


class ScopeError(Exception):
    """Raised when a URL falls outside the agreed scope."""


class PrivateTargetError(ScopeError):
    """The root resolves to a private or loopback address and that was not allowed."""

    def __init__(self, host: str) -> None:
        self.host = host
        super().__init__(
            f"{host} resolves to a private or loopback address. "
            "Pass allow_private=True (CLI: --allow-private) if that is deliberate."
        )


class AuthWall(Exception):
    """The server asked for credentials. DirSift does not have any and stops."""


def normalize_url(url: str) -> str:
    """Lowercase scheme and host, drop fragments, keep the path as given."""
    parsed = urlparse(url.strip())
    if not parsed.scheme:
        parsed = urlparse("http://" + url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ScopeError(f"unsupported scheme: {parsed.scheme!r}")
    netloc = parsed.netloc.lower()
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, ""))


def is_private_host(host: str) -> bool:
    """True for loopback, RFC1918, link-local and other non-public targets."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False
        addrs = {info[4][0] for info in infos}
        return any(is_private_host(a) for a in addrs)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


@dataclass
class Scope:
    """What this run is allowed to touch."""

    root: str
    allow_private: bool = False
    _root_parts: tuple[str, str, str] = field(init=False)

    def __post_init__(self) -> None:
        parsed = urlparse(self.root)
        path = parsed.path
        if not path.endswith("/"):
            # A root of /files/index.html means the directory /files/.
            path = path.rsplit("/", 1)[0] + "/"
        self._root_parts = (parsed.scheme, parsed.netloc.lower(), path)
        if not self.allow_private and is_private_host(parsed.hostname or ""):
            raise PrivateTargetError(parsed.hostname or "")

    def contains(self, url: str) -> bool:
        scheme, netloc, path = self._root_parts
        parsed = urlparse(url)
        if parsed.netloc.lower() != netloc:
            return False
        if parsed.scheme not in ("http", "https"):
            return False
        # http -> https on the same host is fine; anything else is not.
        if scheme == "https" and parsed.scheme == "http":
            return False
        return unquote(parsed.path).startswith(unquote(path))

    def check(self, url: str) -> None:
        if not self.contains(url):
            raise ScopeError(f"out of scope: {url}")


@dataclass
class Response:
    """The part of an HTTP response DirSift keeps."""

    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool
    elapsed: float
    #: The words after the status code. A middlebox that answers instead of the
    #: target usually says so here, and that is the difference between "the
    #: server refused" and "your own machine refused on its behalf".
    reason: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def sha256(self) -> str | None:
        """Only meaningful for a body that was not cut off."""
        return None if self.truncated else hashlib.sha256(self.body).hexdigest()

    @property
    def md5(self) -> str | None:
        """Same rule as sha256: half a file hashes to nothing anyone can look up."""
        return None if self.truncated else hashlib.md5(self.body).hexdigest()


class PoliteFetcher:
    """A deliberately slow, read-only HTTP client with a fixed scope."""

    def __init__(
        self,
        scope: Scope,
        *,
        delay: float = 1.0,
        timeout: float = 20.0,
        peek_bytes: int = DEFAULT_PEEK_BYTES,
        jitter: float = 0.3,
        max_retries: int = 2,
        verify_tls: bool = False,
        proxy: str | None = None,
    ) -> None:
        self.scope = scope
        self.delay = max(delay, MIN_DELAY)
        self.peek_bytes = peek_bytes
        self.jitter = jitter
        self.max_retries = max_retries
        self.requests_made = 0
        self.bytes_fetched = 0
        self._last_request = 0.0
        # Attacker infrastructure runs self-signed or expired certificates as a
        # matter of course. Verifying would drop exactly the hosts worth looking
        # at, and there is no secret to protect on this connection: DirSift
        # sends no credentials and reads a public listing.
        self._client = httpx.Client(
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            timeout=timeout,
            follow_redirects=False,
            verify=verify_tls,
            proxy=proxy,
            trust_env=True,
        )

    # Lifecycle

    def __enter__(self) -> PoliteFetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    # Internals

    def _wait(self) -> None:
        gap = time.monotonic() - self._last_request
        sleep_for = self.delay - gap
        if sleep_for > 0:
            time.sleep(sleep_for + random.uniform(0, self.jitter))
        self._last_request = time.monotonic()

    def _retry_after(self, response: httpx.Response) -> float | None:
        raw = response.headers.get("retry-after")
        if not raw:
            return None
        try:
            return min(float(raw), 120.0)
        except ValueError:
            return 30.0

    # Public surface

    def get(self, url: str, *, max_bytes: int | None = None) -> Response:
        """Fetch ``url``, streaming the body and cutting it at ``max_bytes``.

        Redirects are followed manually so that every hop is scope-checked.
        """
        limit = self.peek_bytes if max_bytes is None else max_bytes
        current = normalize_url(url)
        seen: set[str] = set()

        for _ in range(6):  # redirect budget
            self.scope.check(current)
            if current in seen:
                raise httpx.HTTPError(f"redirect loop at {current}")
            seen.add(current)

            response = self._request_once(current, limit)

            if response.status in (401, 407):
                raise AuthWall(
                    f"{current} requires credentials ({response.status}); "
                    "DirSift does not authenticate and stops here"
                )

            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    return response
                current = normalize_url(urljoin(current, location))
                continue

            return response

        raise httpx.HTTPError(f"too many redirects starting at {url}")

    def _request_once(self, url: str, limit: int) -> Response:
        attempt = 0
        while True:
            self._wait()
            started = time.monotonic()
            try:
                with self._client.stream("GET", url) as stream:
                    self.requests_made += 1
                    if stream.status_code in (429, 503) and attempt < self.max_retries:
                        wait = self._retry_after(stream) or (2**attempt) * 5
                        attempt += 1
                        time.sleep(wait)
                        continue

                    chunks: list[bytes] = []
                    total = 0
                    truncated = False
                    for chunk in stream.iter_bytes(chunk_size=16384):
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= limit:
                            truncated = True
                            break

                    body = b"".join(chunks)[:limit]
                    self.bytes_fetched += len(body)
                    return Response(
                        url=str(stream.url),
                        status=stream.status_code,
                        reason=stream.reason_phrase or "",
                        headers={k.lower(): v for k, v in stream.headers.items()},
                        body=body,
                        truncated=truncated,
                        elapsed=time.monotonic() - started,
                    )
            except (httpx.TimeoutException, httpx.TransportError):
                if attempt >= self.max_retries:
                    raise
                attempt += 1
                time.sleep((2**attempt) * 2)
