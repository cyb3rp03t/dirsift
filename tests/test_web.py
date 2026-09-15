"""The local triage UI: what a page says when there is little or nothing to show."""

from __future__ import annotations

import re
import time
from pathlib import Path

from fastapi.testclient import TestClient

from dirsift.models import Entry, ScanError, ScanResult
from dirsift.web import create_app

BACK_TO_DASHBOARD = re.compile(r'<a[^>]*href="/"[^>]*>(?:(?!</a>).)*Back to Dashboard', re.S)


def save_run(runs_dir: Path, result: ScanResult, name: str = "run") -> str:
    (runs_dir / f"{name}.json").write_text(result.model_dump_json(), encoding="utf-8")
    return name


def header_of(html: str) -> str:
    match = re.search(r"<header>(.*?)</header>", html, re.S)
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
    assert re.search(r'<a[^>]*href="/"[^>]*>\s*DIRSIFT\s*</a>', header)
    assert re.search(r'<a[^>]*href="/"[^>]*>\s*dashboard\s*</a>', header)
    assert not re.search(r">\s*runs\s*</a>", header)
