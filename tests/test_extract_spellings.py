"""How each file wrote an indicator, so a rule can carry the same bytes.

The extractor reads refanged text and knows the live value. These tests hold the
other direction: from the live value back to whatever form the file used, built
from the same table of defanged forms that refang reads.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from dirsift.extract import (
    DEFANG_VARIANTS,
    dedupe_iocs,
    extract_iocs,
    refang,
    spelling_in,
    spelling_pattern,
)
from dirsift.models import Ioc, ScanResult

SOURCE = "http://203.0.113.24/files/a.txt"

#: One written form per defanged notation the table knows, with its live value.
WRITTEN = {
    "hxxp://evil.com/x": "http://evil.com/x",
    "hXXps://evil.com/x": "https://evil.com/x",
    "evil[.]com": "evil.com",
    "evil[ . ]com": "evil.com",
    "evil(.)com": "evil.com",
    "evil{.}com": "evil.com",
    "evil dot com": "evil.com",
    "http[:]//evil.com/x": "http://evil.com/x",
    "http(:)//evil.com/x": "http://evil.com/x",
    "user[@]evil.com": "user@evil.com",
    "user(@)evil.com": "user@evil.com",
    "user at evil.com": "user@evil.com",
    "http:[/]/evil.com/x": "http://evil.com/x",
    "hxxps[:]//evil[.]com/gate": "https://evil.com/gate",
}


def test_every_notation_in_the_table_has_an_example_here():
    """Otherwise a notation could be added to refang and never checked below."""
    for piece, variants in DEFANG_VARIANTS.items():
        for variant in variants:
            assert any(re.search(variant, written, re.I) for written in WRITTEN), (piece, variant)


def test_refang_and_spelling_pattern_read_the_same_table_both_ways():
    for written, live in WRITTEN.items():
        assert refang(written) == live, written
        found = spelling_pattern(live).search(f"before {written} after")
        assert found is not None, written
        assert found.group(0) == written


def test_the_live_spelling_is_preferred_when_the_file_has_both():
    assert spelling_in("evil[.]com and evil.com", "evil.com") == "evil.com"
    assert spelling_in("EVIL.COM", "evil.com") == "EVIL.COM"
    assert spelling_in("evil[.]com only", "evil.com") == "evil[.]com"
    assert spelling_in("nothing here", "evil.com") == "evil.com"


def test_extraction_records_the_spelling_of_this_file():
    found = {i.value: i for i in extract_iocs("beacon hxxps[:]//evil[.]com/gate\n", SOURCE)}
    url = found["https://evil.com/gate"]
    assert url.spellings == {SOURCE: "hxxps[:]//evil[.]com/gate"}
    assert not url.seen_live
    assert found["evil.com"].spellings == {SOURCE: "evil[.]com"}


def test_a_live_spelling_makes_it_live():
    (found,) = [i for i in extract_iocs("ping evil.com\n", SOURCE) if i.value == "evil.com"]
    assert found.spellings == {SOURCE: "evil.com"}
    assert found.seen_live


def test_non_network_indicators_are_spelled_as_they_are():
    (found,) = [i for i in extract_iocs("set password = hunter2-secret\n", SOURCE)]
    assert found.spellings == {SOURCE: "hunter2-secret"}


def test_dedupe_merges_spellings_and_keeps_the_first_per_file():
    other = "http://203.0.113.24/files/b.ini"
    first = extract_iocs("ping evil[.]com\n", SOURCE)
    second = extract_iocs("host=evil.com\n", other)
    again = extract_iocs("ping evil(.)com\n", SOURCE)
    (merged,) = [i for i in dedupe_iocs(first + second + again) if i.value == "evil.com"]
    assert merged.spellings == {SOURCE: "evil[.]com", other: "evil.com"}
    assert merged.seen_live


def test_windows_line_endings_do_not_change_the_spelling():
    text = "@echo off\r\nREM backup hxxp://evil[.]com/x\r\ncurl evil(.)com\r\n"
    found = {i.value: i for i in extract_iocs(text, SOURCE)}
    assert found["http://evil.com/x"].spellings[SOURCE] == "hxxp://evil[.]com/x"
    assert found["evil.com"].spellings[SOURCE] == "evil[.]com"


def test_a_non_ascii_line_does_not_upset_the_search():
    text = "# сервер: hxxp://evil[.]com/x, ödeme şekli\n"
    found = {i.value: i for i in extract_iocs(text, SOURCE)}
    assert found["http://evil.com/x"].spellings[SOURCE] == "hxxp://evil[.]com/x"


def test_an_old_run_without_spellings_loads(tmp_path: Path):
    old = {
        "root_url": "http://203.0.113.24/files/",
        "iocs": [
            {
                "ioc_type": "domain",
                "value": "evil.com",
                "defanged": "evil[.]com",
                "source_url": SOURCE,
            }
        ],
    }
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old), encoding="utf-8")
    loaded = ScanResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert loaded.iocs[0].spellings == {}
    assert isinstance(loaded.iocs[0], Ioc)
