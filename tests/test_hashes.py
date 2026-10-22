"""Hashes and the first bytes: what DirSift can say about a file it only peeked at."""

from __future__ import annotations

import hashlib
import http.server
import socketserver
import threading
from functools import partial
from pathlib import Path

import pytest

from dirsift.fetcher import MIN_DELAY, Response
from dirsift.models import Entry, ScanResult
from dirsift.report import render_markdown
from dirsift.walker import ScanOptions, scan

LOADER = b"@echo off\nstart payload.exe\n"
PAYLOAD = b"MZ\x90\x00" + b"\x00" * 4096


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass


@pytest.fixture
def server(tmp_path: Path):
    (tmp_path / "loader.bat").write_bytes(LOADER)
    (tmp_path / "payload.exe").write_bytes(PAYLOAD)
    handler = partial(_Quiet, directory=str(tmp_path))
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()
    httpd.server_close()


def response(body: bytes, *, truncated: bool) -> Response:
    return Response(
        url="http://a.test/files/x",
        status=200,
        headers={},
        body=body,
        truncated=truncated,
        elapsed=0.0,
    )


# The hashes themselves


def test_a_whole_file_gets_both_hashes():
    read = response(LOADER, truncated=False)
    assert read.sha256 == hashlib.sha256(LOADER).hexdigest()
    assert read.md5 == hashlib.md5(LOADER).hexdigest()


def test_a_cut_read_has_neither_hash():
    """Half a file hashes to nothing anyone can look up, so DirSift reports none."""
    read = response(PAYLOAD[:16], truncated=True)
    assert read.sha256 is None
    assert read.md5 is None


# What the walker records


def test_the_walker_records_both_hashes_and_the_first_bytes(server):
    result = scan(server, ScanOptions(depth=1, delay=MIN_DELAY, allow_private=True))
    loader = next(e for e in result.entries if e.name == "loader.bat")
    assert loader.sha256 == hashlib.sha256(LOADER).hexdigest()
    assert loader.md5 == hashlib.md5(LOADER).hexdigest()
    assert loader.truncated is False
    assert loader.head_hex == LOADER[:256].hex()


def test_a_file_cut_at_the_ceiling_is_marked_partial(server):
    result = scan(
        server, ScanOptions(depth=1, delay=MIN_DELAY, allow_private=True, peek_bytes=16)
    )
    payload = next(e for e in result.entries if e.name == "payload.exe")
    assert payload.truncated is True
    assert payload.sha256 is None
    assert payload.md5 is None
    assert payload.head_hex == PAYLOAD[:16].hex()


# The report


def test_the_report_lists_the_hashes_it_has():
    result = ScanResult(root_url="http://a.test/files/")
    result.entries.append(
        Entry(
            url="http://a.test/files/run.bat",
            name="run.bat",
            depth=1,
            fetched_bytes=len(LOADER),
            sha256="a" * 64,
            md5="b" * 32,
        )
    )
    result.entries.append(
        Entry(
            url="http://a.test/files/big.exe",
            name="big.exe",
            depth=1,
            fetched_bytes=16,
            truncated=True,
        )
    )
    markdown = render_markdown(result, [])
    assert "## Hashes" in markdown
    assert "a" * 64 in markdown
    assert "b" * 32 in markdown
    assert "big.exe" not in markdown.split("## Hashes", 1)[1].split("##", 1)[0]
