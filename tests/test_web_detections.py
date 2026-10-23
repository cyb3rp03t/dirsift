"""The detection routes: what they return, what they refuse, and what they never show live."""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_detections import LIVE, ROOT, SECRET, fixture_result

from dirsift.detections import TARGETS
from dirsift.web import create_app

TEMPLATES = Path(__file__).parents[1] / "src" / "dirsift" / "web" / "templates"
needs_templates = pytest.mark.skipif(
    not (TEMPLATES / "_detection.html").exists() or not (TEMPLATES / "_detections.html").exists(),
    reason="the detection templates are not in place yet",
)

LOOSE = {"exclude_private": "false"}


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    (tmp_path / "golden-run.json").write_text(fixture_result().model_dump_json(), encoding="utf-8")
    return TestClient(create_app(tmp_path), base_url="http://127.0.0.1")


def test_the_list_names_every_target_with_its_links(client):
    reply = client.get("/runs/golden-run/detections.json")
    assert reply.status_code == 200
    body = reply.json()
    assert body["run"] == "golden-run"
    assert [t["id"] for t in body["targets"]] == list(TARGETS)
    assert body["options"]["tlp"] == "AMBER"
    assert body["tlp_levels"] == ["CLEAR", "GREEN", "AMBER", "RED"]
    for target in body["targets"]:
        assert target["preview_url"].startswith(f"/runs/golden-run/detections/{target['id']}?")
        assert "/download?" in target["download_url"]
    assert body["zip_url"].startswith("/runs/golden-run/detections.zip?")
    # The console re-reads the run, so these are the indicators the extractor
    # finds in the fixture's text, not the fixture's own list.
    sources = {source["path"]: source for source in body["sources"]}
    assert "loader.sh" in sources
    assert sources["loader.sh"]["url"] == ROOT + "loader.sh"
    assert sources["loader.sh"]["count"] >= 6
    assert body["left_out"]["not a shareable type"] >= 1


def test_the_list_carries_the_options_into_every_link(client):
    body = client.get(
        "/runs/golden-run/detections.json",
        params={"tlp": "red", "types": "domain", "exclude_private": "false"},
    ).json()
    assert body["options"]["tlp"] == "RED"
    assert body["options"]["types"] == ["domain"]
    assert "tlp=RED" in body["targets"][0]["download_url"]
    assert "types=domain" in body["zip_url"]
    assert "exclude_private=false" in body["zip_url"]


@pytest.mark.parametrize("target_id", sorted(TARGETS))
def test_the_text_preview_is_defanged(client, target_id):
    reply = client.get(
        f"/runs/golden-run/detections/{target_id}",
        params={**LOOSE, "format": "text", "pick": ROOT + "loader.sh"},
    )
    assert reply.status_code == 200
    assert reply.headers["content-type"].startswith("text/plain")
    for value in LIVE:
        assert value not in reply.text, value
    assert SECRET not in reply.text


@pytest.mark.parametrize("target_id", ["sigma", "splunk", "kql", "csv", "stix", "blocklist-ipv4"])
def test_the_download_is_live_and_an_attachment(client, target_id):
    reply = client.get(f"/runs/golden-run/detections/{target_id}/download", params=LOOSE)
    assert reply.status_code == 200
    target = TARGETS[target_id]
    disposition = reply.headers["content-disposition"]
    assert disposition == f'attachment; filename="dirsift_golden-run_{target_id}.{target.ext}"'
    assert reply.headers["cache-control"] == "no-store"
    assert reply.headers["x-content-type-options"] == "nosniff"
    assert reply.headers["content-type"].split(";")[0] == target.media_type.split(";")[0]
    assert "203.0.113.9" in reply.text
    assert SECRET not in reply.text


def test_the_yara_download_needs_a_pick_and_keeps_secrets_out(client):
    empty = client.get("/runs/golden-run/detections/yara/download")
    assert "nothing was selected" in empty.text
    picked = client.get(
        "/runs/golden-run/detections/yara/download", params={"pick": ROOT + "loader.sh"}
    )
    assert "rule dirsift_golden_run_loader_sh" in picked.text
    assert SECRET not in picked.text
    assert 'tlp = "TLP:AMBER"' in picked.text


def test_the_zip_holds_every_file_and_a_manifest(client):
    reply = client.get("/runs/golden-run/detections.zip", params={"tlp": "green"})
    assert reply.status_code == 200
    assert reply.headers["content-type"] == "application/zip"
    assert reply.headers["content-disposition"] == (
        'attachment; filename="dirsift_golden-run_detections.zip"'
    )
    with zipfile.ZipFile(io.BytesIO(reply.content)) as archive:
        names = archive.namelist()
        assert "MANIFEST.txt" in names
        assert "dirsift_golden-run_yara.yar" not in names
        assert "TLP:GREEN" in archive.read("MANIFEST.txt").decode()
        for name in names:
            assert SECRET.encode() not in archive.read(name)


def test_the_zip_takes_a_subset(client):
    reply = client.get("/runs/golden-run/detections.zip", params={"targets": "sigma,csv"})
    with zipfile.ZipFile(io.BytesIO(reply.content)) as archive:
        assert sorted(archive.namelist()) == [
            "MANIFEST.txt", "dirsift_golden-run_csv.csv", "dirsift_golden-run_sigma.yml"
        ]
    assert client.get("/runs/golden-run/detections.zip", params={"targets": "x"}).status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/runs/golden-run/detections/nope",
        "/runs/golden-run/detections/nope/download",
    ],
)
def test_an_unknown_target_is_a_404(client, path):
    reply = client.get(path)
    assert reply.status_code == 404
    assert reply.text == "No such detection target."


@pytest.mark.parametrize(
    "params", [{"tlp": "white"}, {"types": "secret"}, {"profile": "cisco"}]
)
def test_a_bad_option_is_a_400_that_does_not_echo(client, params):
    reply = client.get("/runs/golden-run/detections/csv/download", params=params)
    assert reply.status_code == 400
    assert list(params.values())[0] not in reply.text


def test_a_source_the_run_never_listed_is_a_404(client):
    reply = client.get(
        "/runs/golden-run/detections.json", params={"source": "http://elsewhere.example/x"}
    )
    assert reply.status_code == 404


def test_a_missing_run_is_a_404(client):
    assert client.get("/runs/nope/detections.json").status_code == 404
    assert client.get("/runs/nope/detections/csv/download").status_code == 404


def test_one_source_narrows_the_files(client):
    reply = client.get(
        "/runs/golden-run/detections/blocklist-domain/download",
        params={"source": ROOT + "loader.sh", "profile": "bare"},
    )
    assert reply.text.splitlines() == ["c2.evil-update.top", "cdn.panel-gate.xyz"]


def test_the_routes_only_answer_get(client):
    assert client.post("/runs/golden-run/detections/csv/download").status_code == 405
    assert client.post("/runs/golden-run/detections.zip").status_code == 405


@needs_templates
def test_the_panel_renders(client):
    reply = client.get("/runs/golden-run/detections", headers={"hx-request": "true"})
    assert reply.status_code == 200
    assert reply.headers["content-type"].startswith("text/html")
    # File URLs sit in form values, as they do in the listing; no indicator does.
    for value in ("203.0.113.9", "c2.evil-update.top", "cdn.panel-gate.xyz", "ops@evil-update.top"):
        assert value not in reply.text, value


@needs_templates
@pytest.mark.parametrize("target_id", sorted(TARGETS))
def test_the_html_preview_renders_defanged(client, target_id):
    reply = client.get(
        f"/runs/golden-run/detections/{target_id}",
        params={**LOOSE, "pick": ROOT + "loader.sh"},
        headers={"hx-request": "true"},
    )
    assert reply.status_code == 200
    assert reply.headers["content-type"].startswith("text/html")
    for value in LIVE:
        assert value not in reply.text, value


def test_a_hidden_false_before_a_ticked_box_reads_as_ticked(client):
    ticked = client.get(
        "/runs/golden-run/detections.json?exclude_private=false&exclude_private=true"
    ).json()
    unticked = client.get("/runs/golden-run/detections.json?exclude_private=false").json()
    assert ticked["options"]["exclude_private"] is True
    assert unticked["options"]["exclude_private"] is False


def test_defang_shown_leaves_nothing_live_in_a_context_line():
    """The run page defangs a context line when it shows it, not when it saved it."""
    from dirsift.models import Ioc, ScanResult
    from dirsift.web import defang_shown

    result = ScanResult(
        root_url="http://203.0.113.9/drop/",
        iocs=[
            Ioc(
                ioc_type="email",
                value="ops@evil-panel.co",
                defanged="ops@evil-panel[.]co",
                source_url="http://203.0.113.9/drop/a.txt",
            ),
            Ioc(
                ioc_type="ipv6",
                value="2a03:2880:f12f:83::1",
                defanged="2a03[:]2880[:]f12f[:]83[:][:]1",
                source_url="http://203.0.113.9/drop/a.txt",
            ),
        ],
    )
    line = (
        "mail ops@evil-panel.co, fall back to [2a03:2880:f12f:83::1]:443 "
        "or relay.evil-panel.co:8080/up then 2001:db8::7 and http://x.co/a"
    )
    shown = defang_shown(line, result)
    for live in (
        "ops@evil-panel.co",
        "evil-panel.co",
        "2a03:2880:f12f:83::1",
        "2001:db8::7",
        "http://",
        "x.co",
    ):
        assert live not in shown, (live, shown)
    assert "evil-panel[.]co" in shown
    assert "2a03[:]2880" in shown
    assert defang_shown(None, result) == ""
    assert defang_shown("", result) == ""
    # A second call on the same run reuses the values and gives the same text.
    assert defang_shown(line, result) == shown


def test_the_panel_without_htmx_is_a_whole_page(client):
    """With the script off, the link opens a page, not a bare fragment."""
    reply = client.get("/runs/golden-run/detections")
    assert reply.status_code == 200
    text = reply.text
    assert text.lstrip().lower().startswith("<!doctype html>")
    assert '<html lang="en">' in text
    assert "<title>Rule pack: hxxp://panel-gate[.]xyz/files/</title>" in text
    assert text.count("<h1") == 1
    assert '<main id="main"' in text
    assert 'href="/runs/golden-run#detections"' in text
    assert 'id="det-panel"' in text
    assert "/static/dirsift.css" in text


def test_the_panel_for_htmx_is_still_the_fragment(client):
    reply = client.get("/runs/golden-run/detections", headers={"HX-Request": "true"})
    assert reply.status_code == 200
    assert "<html" not in reply.text
    assert "<h1" not in reply.text
    assert 'id="det-panel"' in reply.text


def test_the_page_keeps_the_filter_without_the_script(client):
    reply = client.get("/runs/golden-run/detections", params={"tlp": "red", "types": "domain"})
    assert reply.status_code == 200
    assert "<html" in reply.text
    assert 'value="domain"' in reply.text


@needs_templates
def test_the_network_group_has_a_name_and_its_own_formats(client):
    page = client.get("/runs/golden-run/detections", params={"group": "network"})
    assert page.status_code == 200
    assert "IDS and DNS" in page.text
    assert 'value="suricata"' in page.text and 'value="rpz"' in page.text
    # Every group the panel offers carries a visible name.
    assert not re.search(r'name="group" value="[a-z]+"[^>]*> </label>', page.text)


@needs_templates
@pytest.mark.parametrize(("target", "shown"), [("blocklist-ipv4", True),
                                               ("qradar-set-ip", False), ("suricata", False)])
def test_the_comment_style_select_is_only_for_firewall_lists(client, target, shown):
    page = client.get("/runs/golden-run/detections", params={"target": target})
    assert page.status_code == 200
    assert ('id="det-profile"' in page.text) is shown
