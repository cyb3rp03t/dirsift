"""The one place DirSift talks to something other than the target.

Every test here runs against a stub transport: the suite never reaches the
network, and the assertions are about what would be sent if it did.
"""

from __future__ import annotations

import httpx
import pytest

from dirsift.enrich import VT_URL, MissingKey, lookup_hash

DIGEST = "a" * 64


def transport(handler):
    return httpx.MockTransport(handler)


def test_a_lookup_sends_the_hash_and_nothing_else():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("x-apikey")
        seen["body"] = request.content
        seen["method"] = request.method
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    lookup_hash(DIGEST, api_key="secret", transport=transport(handler))

    assert seen["method"] == "GET"
    assert seen["url"] == VT_URL + DIGEST
    assert seen["key"] == "secret"
    assert seen["body"] == b""


def test_a_known_file_comes_back_with_a_score():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 6,
                            "suspicious": 1,
                            "undetected": 57,
                            "harmless": 0,
                            "timeout": 0,
                            "type-unsupported": 3,
                        },
                        "last_analysis_date": 1757980800,
                    }
                }
            },
        )

    verdict = lookup_hash(DIGEST, api_key="secret", transport=transport(handler))

    assert verdict.found is True
    assert verdict.malicious == 6
    assert verdict.total == 64  # malicious, suspicious, undetected and harmless
    assert verdict.analysed.startswith("2025") or verdict.analysed.startswith("2026")


def test_a_file_nobody_has_seen_says_so():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    verdict = lookup_hash(DIGEST, api_key="secret", transport=transport(handler))

    assert verdict.found is False
    assert verdict.malicious == 0


def test_without_a_key_nothing_leaves_the_machine():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("a request was made without a key")

    with pytest.raises(MissingKey):
        lookup_hash(DIGEST, api_key=None, transport=transport(handler))
