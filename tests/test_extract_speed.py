"""Extraction stays linear on a long line, whatever the line is made of.

A file under analysis decides what its lines look like, and a single 256 KB
line packed with credentialed links, addresses or one very long link must not
stall a scan. Each case is timed at two sizes: a fourfold longer line may take
about four times as long, not sixteen. An absolute bound on the long line,
generous for slow CI runners, catches a constant that is merely large.
"""

from __future__ import annotations

import time

import pytest

from dirsift.extract import extract_iocs

SOURCE = "http://203.0.113.24/files/long.txt"
SMALL = 64 * 1024
LARGE = 256 * 1024
#: Four times the input; linear work takes about four times as long and
#: quadratic work sixteen, so ten keeps them apart with room for a busy runner.
MAX_GROWTH = 10.0
#: Seconds for the 256 KB line. Locally each case takes a fraction of this.
MAX_SECONDS = 5.0


def fill(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


CASES = {
    "many credentialed links": lambda size: fill("ftp://u:Passw0rd99@198.51.100.2/ ", size),
    "passwords with a space": lambda size: fill("//u:a b@h ", size),
    "addresses": lambda size: fill("198.51.100.2 ", size),
    "links": lambda size: fill("http://198.51.100.2/a ", size),
    "percent signs": lambda size: fill("http://%zz:%zz@%zz/", size),
    "one link with a long path": lambda size: "http://u:pw@198.51.100.1/" + fill("a/@", size),
    "credentials without a scheme": lambda size: fill("-u user:NoSchemePw77@db.example.net ", size),
    "labels before emails": lambda size: fill("Name:jane@example.org a:b@c ", size),
    "a long chain after a bare login": lambda size: "a:b@" + fill("x.", size) + "com",
}


def timed(text: str) -> float:
    started = time.perf_counter()
    extract_iocs(text, SOURCE)
    return time.perf_counter() - started


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_long_line_is_read_in_linear_time(name):
    make = CASES[name]
    timed(make(SMALL // 8))  # warm the regex cache
    small = min(timed(make(SMALL)) for _ in range(2))
    # Best of two on both sizes, so one scheduling spike does not set the ratio.
    large = min(timed(make(LARGE)) for _ in range(2))
    assert large < MAX_SECONDS, f"{name}: {large:.2f} s for 256 KB"
    # A floor keeps a very fast small run from making the ratio noise.
    assert large / max(small, 0.01) < MAX_GROWTH, f"{name}: {small:.3f} s, then {large:.3f} s"
