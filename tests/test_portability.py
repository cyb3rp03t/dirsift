"""Things that break on one platform and not the other.

DirSift is pure Python and has no platform-specific code, but "no platform
specific code" is a claim, not a measurement. These tests pin the two places
where the claim is most likely to be wrong: text that leaves the tool, and
filenames that come off a hostile server.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from dirsift.analyze import analyze
from dirsift.extract import extract_iocs
from dirsift.models import Entry, ScanResult
from dirsift.report import render_markdown
from dirsift.report_model import build_report

#: Names a real open directory has handed out: Cyrillic, Chinese, an RTL
#: override used to disguise an extension, a combining accent, an emoji.
HOSTILE_NAMES = [
    "отчет.exe",
    "发票.pdf",
    "invoice‮gpj.exe",
    "café.bat",
    "payload\U0001f480.bin",
    "naïve résumé.docx",
]


def _result_with(names: list[str]) -> ScanResult:
    root = "http://203.0.113.10:8080/files/"
    result = ScanResult(root_url=root)
    for name in names:
        result.entries.append(
            Entry(url=root + name, name=name, depth=1, parent_url=root, size=1024)
        )
    return result


def test_report_renders_hostile_filenames():
    result, candidates = analyze(_result_with(HOSTILE_NAMES))
    markdown = render_markdown(build_report(result, candidates))
    for name in HOSTILE_NAMES:
        assert name in markdown


def test_report_encodes_to_utf8_whatever_the_console_is():
    """The report must survive being written out on a non-UTF-8 code page."""
    result, candidates = analyze(_result_with(HOSTILE_NAMES))
    markdown = render_markdown(build_report(result, candidates))
    assert markdown.encode("utf-8").decode("utf-8") == markdown


def test_run_json_round_trips_hostile_filenames(tmp_path):
    result, _ = analyze(_result_with(HOSTILE_NAMES))
    path = tmp_path / "run.json"
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    reloaded = ScanResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert [e.name for e in reloaded.entries] == HOSTILE_NAMES


def test_indicators_survive_crlf_line_endings():
    """A file fetched from an IIS box arrives with CRLF; context must not keep it."""
    text = 'c2 = "http://1.2.3.44:8081/g"\r\nmutex = "Global\\\\x"\r\n'
    iocs = extract_iocs(text, "u")
    assert any(i.value == "1.2.3.44:8081" for i in iocs)
    assert all("\r" not in (i.context or "") for i in iocs)


def test_cli_prints_hostile_names_through_a_pipe(tmp_path):
    """End to end: the report command must not die writing to a redirected stdout.

    Run as a subprocess so the real stdout encoding path is exercised, which is
    where a Windows console code page would bite.
    """
    result, _ = analyze(_result_with(HOSTILE_NAMES))
    run = tmp_path / "run.json"
    run.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    # Inherit the real environment: Windows needs it to start Python at all.
    # What the test takes away is the encoding overrides, because the point is
    # to exercise whatever the platform would have used on its own.
    env = dict(os.environ)
    env["DIRSIFT_NO_BANNER"] = "1"
    env.pop("PYTHONIOENCODING", None)
    env.pop("PYTHONUTF8", None)

    completed = subprocess.run(
        [sys.executable, "-m", "dirsift", "report", str(run)],
        capture_output=True,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    out = completed.stdout.decode("utf-8")
    for name in HOSTILE_NAMES:
        assert name in out
