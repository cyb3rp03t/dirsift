"""The rules of engagement, tested.

These are the promises the README makes. If one of them breaks, the tool is
doing something to someone else's server that it said it would not do, so they
get tests rather than trust.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import time
from pathlib import Path

import pytest

from dirsift.fetcher import MIN_DELAY, PoliteFetcher, Scope, ScopeError, normalize_url
from dirsift.walker import ScanOptions, scan

# Scope


def test_scope_refuses_another_host():
    scope = Scope(root="http://a.test/files/", allow_private=True)
    assert not scope.contains("http://b.test/files/x")
    with pytest.raises(ScopeError):
        scope.check("http://b.test/files/x")


def test_scope_refuses_climbing_above_the_root():
    scope = Scope(root="http://a.test/files/deep/", allow_private=True)
    assert not scope.contains("http://a.test/files/")
    assert not scope.contains("http://a.test/etc/passwd")
    assert scope.contains("http://a.test/files/deep/sub/x.exe")


def test_scope_refuses_a_downgrade_to_http():
    scope = Scope(root="https://a.test/files/", allow_private=True)
    assert not scope.contains("http://a.test/files/x")


def test_scope_root_given_as_a_file_means_its_directory():
    scope = Scope(root="http://a.test/files/index.html", allow_private=True)
    assert scope.contains("http://a.test/files/other.exe")


def test_private_targets_are_refused_unless_asked_for():
    with pytest.raises(ScopeError):
        Scope(root="http://127.0.0.1:8000/")
    Scope(root="http://127.0.0.1:8000/", allow_private=True)


def test_non_http_schemes_are_refused():
    for url in ("ftp://a.test/x", "file:///etc/passwd", "gopher://a.test"):
        with pytest.raises(ScopeError):
            normalize_url(url)


def test_normalize_lowercases_host_and_drops_fragments():
    assert normalize_url("HTTP://A.TEST/Files/#frag") == "http://a.test/Files/"


# The live rules


class _Handler(http.server.SimpleHTTPRequestHandler):
    """Serves a fixture tree, demands credentials for /private/, logs methods."""

    methods: list[str] = []
    root: str = ""

    def translate_path(self, path):  # noqa: N802 - stdlib name
        import posixpath
        from urllib.parse import unquote as _unquote

        rel = posixpath.normpath(_unquote(path.split("?", 1)[0])).lstrip("/")
        return str(Path(self.root) / rel)

    def do_GET(self):  # noqa: N802 - stdlib name
        type(self).methods.append("GET")
        if self.path.startswith("/private"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="x"')
            self.end_headers()
            return
        super().do_GET()

    def do_HEAD(self):  # noqa: N802 - stdlib name
        type(self).methods.append("HEAD")
        super().do_HEAD()

    def do_POST(self):  # noqa: N802 - stdlib name
        type(self).methods.append("POST")
        self.send_error(405)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture
def server(tmp_path: Path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "private").mkdir()
    (tmp_path / "sub" / "note.txt").write_text("c2 at 1.2.3.44:8081\n")
    (tmp_path / "private" / "secret.txt").write_text("nope")
    (tmp_path / "run.bat").write_text('@echo off\nstart "" sub\\note.txt\n')
    (tmp_path / "loader.exe").write_bytes(b"MZ\x90\x00" + b"\x00" * 64)

    _Handler.root = str(tmp_path)
    _Handler.methods = []
    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
    httpd.server_close()


def test_only_get_ever_reaches_the_target(server):
    scan(server, ScanOptions(depth=2, delay=MIN_DELAY, allow_private=True))
    assert set(_Handler.methods) == {"GET"}


def test_an_auth_wall_ends_that_branch(server):
    result = scan(server, ScanOptions(depth=2, delay=MIN_DELAY, allow_private=True))
    assert any("requires credentials" in e.detail for e in result.errors)
    # and nothing behind the wall was recorded
    assert not any("secret.txt" == e.name for e in result.entries)


def test_no_path_is_ever_guessed(server):
    """Every URL requested must correspond to a link that was in a listing."""
    result = scan(server, ScanOptions(depth=2, delay=MIN_DELAY, allow_private=True))
    names = {e.name for e in result.entries}
    assert names == {"sub", "private", "run.bat", "loader.exe", "note.txt", "secret.txt"} - {
        "secret.txt"
    }


def test_depth_zero_does_not_descend(server):
    result = scan(server, ScanOptions(depth=0, delay=MIN_DELAY, allow_private=True))
    assert not any(e.name == "note.txt" for e in result.entries)


def test_request_budget_is_a_hard_stop(server):
    result = scan(
        server, ScanOptions(depth=3, delay=MIN_DELAY, allow_private=True, max_requests=2)
    )
    assert result.requests_made <= 2
    assert any("budget exhausted" in e.detail for e in result.errors)


def test_the_delay_cannot_be_dialled_to_zero(server):
    scope = Scope(root=server, allow_private=True)
    with PoliteFetcher(scope, delay=0.0) as fetcher:
        assert fetcher.delay == MIN_DELAY
        started = time.monotonic()
        fetcher.get(server)
        fetcher.get(server)
        assert time.monotonic() - started >= MIN_DELAY


def test_bodies_are_cut_at_the_peek_ceiling(server):
    scope = Scope(root=server, allow_private=True)
    with PoliteFetcher(scope, delay=MIN_DELAY, peek_bytes=8) as fetcher:
        response = fetcher.get(server + "loader.exe", max_bytes=8)
    assert len(response.body) == 8
    assert response.truncated
    assert response.sha256 is None  # a partial read has no meaningful hash


def test_a_full_read_gets_a_hash(server):
    scope = Scope(root=server, allow_private=True)
    with PoliteFetcher(scope, delay=MIN_DELAY) as fetcher:
        response = fetcher.get(server + "run.bat")
    assert response.sha256 is not None


def test_end_to_end_finds_the_driver_and_the_indicator(server):
    from dirsift.analyze import analyze

    result = scan(server, ScanOptions(depth=2, delay=MIN_DELAY, allow_private=True))
    result, candidates = analyze(result)
    assert candidates[0].entry.name == "run.bat"
    assert any(i.value == "1.2.3.44:8081" for i in result.iocs)
