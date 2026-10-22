"""The leak oracle: no part of a secret leaves the run through any rule output.

The run is built the way a scan builds it: real file text, the real extractor,
and a head taken from the same bytes. Every output that can carry a YARA rule
is then read whole: the rule builder, every detection target as a download and
as a preview, the zip, the console's POST /yara and GET /rule.yar, and the
``dirsift rules`` command. Hex strings are turned back into bytes before the
search, because a rule can carry a secret as ``{ 41 4b 49 41 }`` as easily as
in quotes.

The oracle does not ask the extractor what the secrets are. It holds its own
list (every line of the private key block, the access key, each password, the
webhook, the token) and fails on any eight character piece of any of them.
"""

from __future__ import annotations

import hashlib
import html
import io
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from rich.console import Console
from typer.testing import CliRunner

from dirsift import cli
from dirsift.analyze import analyze
from dirsift.detections import TARGETS, Options, Run, preview, render, zip_bytes
from dirsift.extract import SecretMask, dedupe_iocs, extract_iocs, secret_shown
from dirsift.models import Entry, ScanResult
from dirsift.rules import build_rules
from dirsift.web import create_app

ROOT = "http://203.0.113.9/drop/"
RUN = "leak-run"
PIECE = 8

PEM_LINES = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn7ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB",
    "aNrIn9qJnSbyFm5S3DqhnlLvKvKqGkf0q2EqJfc0XLWfRZGjcxkkuRZsS9KHPXwJ",
    "Qm4vT2xKcGhVb1N3ZXJ0eVBhc3N3b3JkMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1u",
    "-----END RSA PRIVATE KEY-----",
]
AWS_KEY = "AKIAIOSFODNN7EXAMPL3"
PASSWORDS = ["Sup3rSecretPw", "Wint3r2026Hunt"]
ENV_KEY = "AKIAZZQQ7766LLKKJJHH"
ENV_TOKEN = "s3cr3tT0kenValue991"
WEBHOOK_TOKEN = "1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
WEBHOOK = "https://discord.com/api/webhooks/" + WEBHOOK_TOKEN
JWT = (
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvcjEiLCJyb2xlIjoiYWRtaW4ifQ"
    ".Zm9vYmFyYmF6cXV4c2lnbmF0dXJlMTIz"
)
C2 = "http://c2.evil-update.top/gate.php"
#: Secrets named only by the key in front of them, the way a config file or an
#: environment file holds them: an underscore, a dash or a prefix around the word.
AWS_SECRET = "Zm9vYmFyQmF6UXV4U2VjcmV0QWNjZXNzS2V5MDA5OQ"
NAMED = {
    "SECRET_KEY": "Dj4ngoS3cretKeyValue77",
    "DB_PASSWORD": "PgPassw0rdProd2026x",
    "client_secret": "Cl1entS3cretValueXyz",
    "x-api-key": "XApiK3yValue0042zz",
    "api_secret": "ApiS3cretValue5150q",
    "dbPassword": "CamelPw0rdValue88q",
}

#: What the oracle looks for, independent of what the extractor recognises. For
#: the webhook that is the part after the host: ``https://`` and ``discord.``
#: are public and would make the oracle cry wolf.
SECRETS = [
    *PEM_LINES[1:4], AWS_KEY, *PASSWORDS, ENV_KEY, ENV_TOKEN, WEBHOOK_TOKEN, JWT,
    AWS_SECRET, *NAMED.values(),
]

FILES = {
    "id_rsa": "\n".join(PEM_LINES) + "\n",
    "aws.txt": AWS_KEY + "\n",
    "creds.txt": f"admin:{PASSWORDS[0]}\nbackup_op:{PASSWORDS[1]}\n",
    ".env": f"AWS_KEY={ENV_KEY}\nTOKEN={ENV_TOKEN}\nDEBUG=1\nPORT=80\n",
    "hook.txt": WEBHOOK + "\n",
    "jwt.txt": JWT + "\n",
    "config.ini": f"[panel]\ngate = {C2}\napi_key = {ENV_TOKEN}\nretry = 3\n",
    "prod.ini": f"[prod]\naws_secret_access_key = {AWS_SECRET}\nregion = eu-west-1\n",
    "app.env": (
        f"SECRET_KEY={NAMED['SECRET_KEY']}\n"
        f"DB_PASSWORD={NAMED['DB_PASSWORD']}\n"
        f"client_secret: \"{NAMED['client_secret']}\"\n"
        f"\"x-api-key\": \"{NAMED['x-api-key']}\"\n"
        f"api_secret = {NAMED['api_secret']}\n"
        f"dbPassword: '{NAMED['dbPassword']}'\n"
        "LOG_LEVEL=debug\n"
    ),
}


def leak_result() -> ScanResult:
    entries = []
    iocs = []
    for name, text in FILES.items():
        data = text.encode()
        entries.append(
            Entry(
                url=ROOT + name,
                name=name,
                parent_url=ROOT,
                kind="data",
                size=len(data),
                fetched_bytes=len(data),
                head_hex=data[:64].hex(),
                text_preview=text,
                sha256=format(abs(hash(name)), "064x")[:64],
            )
        )
        iocs += extract_iocs(text, ROOT + name)
    return ScanResult(
        root_url=ROOT,
        started_at=datetime(2026, 10, 1, 9, 0, tzinfo=UTC),
        entries=entries,
        iocs=dedupe_iocs(iocs),
    )


_HEX = re.compile(r"\{([0-9a-fA-F ?\[\]\-|()~]+)\}")


def readable(output: str) -> str:
    """The output plus every hex string in it turned back into bytes."""
    text = html.unescape(output)
    decoded = []
    for match in _HEX.finditer(text):
        digits = re.sub(r"[^0-9a-fA-F]", "", match.group(1))
        if len(digits) % 2 == 0 and digits:
            decoded.append(bytes.fromhex(digits).decode("latin-1"))
    return text + "\n" + "\n".join(decoded)


def leaks(output: str) -> list[str]:
    """Every piece of a secret the output carries, as plain text or as hex."""
    text = readable(output)
    found = []
    for secret in SECRETS:
        for start in range(len(secret) - PIECE + 1):
            piece = secret[start : start + PIECE]
            if piece in text:
                found.append(f"{piece!r} of {secret[:12]}...")
                break
    return found


def test_the_oracle_catches_a_secret_in_hex_and_in_quotes():
    """The oracle itself: it must see what it is meant to see."""
    as_hex = " ".join(format(byte, "02x") for byte in AWS_KEY.encode()[:12])
    assert leaks("$head = { " + as_hex + " }")
    assert leaks('$s1 = "' + PEM_LINES[2][5:40] + '" ascii')
    assert not leaks('$url1 = "' + C2 + '" ascii')


ALL = [ROOT + name for name in FILES]


def test_build_rules_carries_no_piece_of_a_secret():
    result = leak_result()
    rules = build_rules(result, result.files, RUN)
    assert leaks(rules) == []
    # The config still gets a rule from the address it calls.
    assert C2 in rules


@pytest.mark.parametrize("target_id", sorted(TARGETS))
@pytest.mark.parametrize("live", [True, False], ids=["download", "preview"])
def test_no_target_carries_a_piece_of_a_secret(target_id, live):
    result = leak_result()
    run = Run(result=result, name=RUN)
    options = Options(pick=tuple(ALL), exclude_private=False)
    text = render(TARGETS[target_id], run, options) if live else preview(
        TARGETS[target_id], run, options
    )
    assert leaks(text) == []


def test_the_zip_carries_no_piece_of_a_secret():
    result = leak_result()
    run = Run(result=result, name=RUN)
    data = zip_bytes(run, Options(pick=tuple(ALL)), list(TARGETS.values()))
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            assert leaks(archive.read(name).decode("utf-8")) == [], name


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    (tmp_path / f"{RUN}.json").write_text(leak_result().model_dump_json(), encoding="utf-8")
    return TestClient(create_app(tmp_path))


def test_the_console_routes_carry_no_piece_of_a_secret(client):
    posted = client.post(f"/runs/{RUN}/yara", data={"pick": ALL})
    assert posted.status_code == 200
    assert leaks(posted.text) == []

    fetched = client.get(f"/runs/{RUN}/rule.yar", params={"pick": ALL})
    assert fetched.status_code == 200
    assert leaks(fetched.text) == []

    for target_id in TARGETS:
        params = {"pick": ALL, "exclude_private": "false"}
        down = client.get(f"/runs/{RUN}/detections/{target_id}/download", params=params)
        shown = client.get(f"/runs/{RUN}/detections/{target_id}", params=params)
        assert leaks(down.text) == [], target_id
        assert leaks(shown.text) == [], target_id

    archive = client.get(f"/runs/{RUN}/detections.zip", params={"pick": ALL})
    with zipfile.ZipFile(io.BytesIO(archive.content)) as opened:
        for name in opened.namelist():
            assert leaks(opened.read(name).decode("utf-8")) == [], name


def test_the_rules_command_carries_no_piece_of_a_secret(tmp_path: Path):
    path = tmp_path / f"{RUN}.json"
    path.write_text(leak_result().model_dump_json(), encoding="utf-8")
    reply = CliRunner().invoke(cli.app, ["rules", str(path)])
    assert reply.exit_code == 0, reply.output
    assert leaks(reply.output) == []
    # The command reruns the passes over the run; so does the analysis here.
    assert leaks(build_rules(analyze(leak_result())[0], leak_result().files, RUN)) == []


def test_a_file_that_holds_a_secret_is_named_with_the_reason():
    result = leak_result()
    rules = build_rules(result, [f for f in result.files if f.name == "aws.txt"], RUN)
    assert "No rule for aws.txt" in rules
    assert "holds a secret" in rules


def test_the_private_key_is_one_indicator_over_the_whole_block():
    found = extract_iocs(FILES["id_rsa"], ROOT + "id_rsa")
    keys = [ioc for ioc in found if ioc.label == "private_key"]
    assert len(keys) == 1
    assert keys[0].value.startswith(PEM_LINES[0])
    assert keys[0].value.rstrip().endswith(PEM_LINES[-1])
    # The context line names the block, it does not quote the body.
    assert PEM_LINES[1][:PIECE] not in (keys[0].context or "")


def test_a_private_key_without_its_end_runs_to_the_end_of_what_was_read():
    text = "\n".join(PEM_LINES[:3]) + "\n"
    keys = [ioc for ioc in extract_iocs(text, ROOT + "cut") if ioc.label == "private_key"]
    assert len(keys) == 1
    assert PEM_LINES[2] in keys[0].value


def test_a_binary_head_still_gets_a_head_rule():
    data = bytes([0x00, 0x13, 0x37, 0xC0, 0xDE, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    result = ScanResult(
        root_url=ROOT,
        entries=[Entry(url=ROOT + "blob", name="blob", parent_url=ROOT, head_hex=data.hex())],
    )
    assert "$head = { 00 13 37 c0" in build_rules(result, result.files, RUN)


def test_a_text_head_is_never_a_head_rule():
    data = b"user=someone pass=nothing"
    result = ScanResult(
        root_url=ROOT,
        entries=[Entry(url=ROOT + "t", name="t", parent_url=ROOT, head_hex=data.hex())],
    )
    rules = build_rules(result, result.files, RUN)
    assert "$head" not in rules
    assert "No rule for t" in rules


# Keys that name the secret with a prefix or an underscore around the word.


@pytest.mark.parametrize(
    ("line", "value"),
    [
        (f"aws_secret_access_key = {AWS_SECRET}", AWS_SECRET),
        ("client_secret=Cl1entS3cretValueXyz", "Cl1entS3cretValueXyz"),
        ('"api_secret": "ApiS3cretValue5150q"', "ApiS3cretValue5150q"),
        ("SECRET_KEY = 'Dj4ngoS3cretKeyValue77'", "Dj4ngoS3cretKeyValue77"),
        ("secret_key: Dj4ngoS3cretKeyValue77", "Dj4ngoS3cretKeyValue77"),
        ("DB_PASSWORD=PgPassw0rdProd2026x", "PgPassw0rdProd2026x"),
        ("x-api-key: XApiK3yValue0042zz", "XApiK3yValue0042zz"),
        ("GITHUB_TOKEN=s3cr3tT0kenValue991", "s3cr3tT0kenValue991"),
        ("token: s3cr3tT0kenValue991", "s3cr3tT0kenValue991"),
        ("export ACCESS_TOKEN=s3cr3tT0kenValue991", "s3cr3tT0kenValue991"),
        ("spring.datasource.password=PgPassw0rdProd2026x", "PgPassw0rdProd2026x"),
        ("dbPassword: 'CamelPw0rdValue88q'", "CamelPw0rdValue88q"),
    ],
)
def test_a_secret_named_by_its_key_is_recognised(line, value):
    found = [
        ioc.value for ioc in extract_iocs(line + "\n", ROOT + "k") if ioc.ioc_type == "secret"
    ]
    assert found == [value]


@pytest.mark.parametrize(
    "line",
    [
        "secret_santa.txt",
        "-rw-r--r-- 1 www www 912 Oct 1 secret_santa.txt",
        "secret_santa.txt = gifts_for_everyone",
        "The secret is that nobody reads the logs.",
        "token_url = https://auth.example.org/oauth/token",
        "password_policy = strict_enough",
        "min_password_length = 1200000",
        "secretariat = Cumhuriyet",
        "password = changeme",
        "TOKEN=${TOKEN_FROM_VAULT}",
        "api_key = os.environ.get('API_KEY')",
    ],
)
def test_text_that_only_mentions_a_secret_word_is_not_a_secret(line):
    found = [ioc for ioc in extract_iocs(line + "\n", ROOT + "k") if ioc.ioc_type == "secret"]
    assert found == []


def test_a_file_with_only_a_named_secret_gets_no_rule():
    result = leak_result()
    for name in ("prod.ini", "app.env"):
        rules = build_rules(result, [f for f in result.files if f.name == name], RUN)
        assert leaks(rules) == [], name
        assert f"No rule for {name}" in rules


# Where indicators are shown or exported: a secret is named, never quoted.

SHOWN = re.compile(r"^[a-z0-9_.-]+(?:  \S(?:.*\S)?)?  \d+ chars  sha256:[0-9a-f]{12}$")


def secret_iocs(result: ScanResult):
    return [ioc for ioc in result.iocs if ioc.ioc_type == "secret"]


def test_every_secret_has_a_one_line_shown_form_that_carries_no_piece_of_it():
    result = leak_result()
    shown = [secret_shown(ioc) for ioc in secret_iocs(result)]
    assert len(shown) >= 14
    for line in shown:
        assert SHOWN.match(line), line
        assert leaks(line) == [], line


def test_the_shown_form_keeps_only_a_prefix_that_is_not_secret():
    result = leak_result()
    by_label = {ioc.label: secret_shown(ioc) for ioc in secret_iocs(result)}
    key = by_label["private_key"]
    assert key.startswith("private_key  BEGIN RSA PRIVATE KEY  ")
    assert f"  {len(FILES['id_rsa'].strip())} chars  " in key
    assert by_label["aws_access_key"].startswith("aws_access_key  AKIA  20 chars  ")
    assert by_label["discord_webhook"].startswith(
        "discord_webhook  hxxps://discord[.]com/api/webhooks/  "
    )
    assert by_label["jwt"].startswith("jwt  eyJ  ")
    assert by_label["aws_secret_access_key"].startswith(
        f"aws_secret_access_key  {len(AWS_SECRET)} chars  sha256:"
    )
    digest = hashlib.sha256(AWS_SECRET.encode()).hexdigest()[:12]
    assert by_label["aws_secret_access_key"].endswith("sha256:" + digest)


def test_a_key_escaped_into_one_line_shows_only_its_begin_line():
    escaped = "\\n".join(PEM_LINES)
    text = '{"private_key": "' + escaped + '\\n"}\n'
    keys = [ioc for ioc in extract_iocs(text, ROOT + "sa.json") if ioc.label == "private_key"]
    assert len(keys) == 1
    shown = secret_shown(keys[0])
    assert shown.startswith("private_key  BEGIN RSA PRIVATE KEY  ")
    assert leaks(shown) == []


def test_the_run_page_quotes_no_secret(client):
    page = client.get(f"/runs/{RUN}")
    assert page.status_code == 200
    assert leaks(page.text) == []
    assert "private_key  BEGIN RSA PRIVATE KEY" in html.unescape(page.text)


def test_the_preview_lists_no_secret_among_its_indicators(client):
    shown = client.get(f"/runs/{RUN}/file", params={"url": ROOT + "app.env"})
    assert shown.status_code == 200
    listed = re.findall(r'data-copy="([^"]*)"', shown.text)
    assert any(item.startswith("client_secret  20 chars  sha256:") for item in listed)
    assert leaks("\n".join(listed)) == []


def test_the_indicators_file_is_one_line_per_indicator_and_quotes_no_secret(client):
    text = client.get(f"/runs/{RUN}/iocs.txt").text
    assert leaks(text) == []
    lines = text.splitlines()
    result = analyze(leak_result())[0]
    assert len(lines) == len(result.iocs)
    secrets = [line for line in lines if "sha256:" in line]
    # A webhook is a URL and a secret at once: both rows name it, neither quotes it.
    assert len(secrets) >= len(secret_iocs(result))
    assert all(SHOWN.match(line) for line in secrets), secrets


def test_the_markdown_report_quotes_no_secret(client):
    text = client.get(f"/runs/{RUN}/report.md").text
    assert leaks(text) == []
    assert "private_key  BEGIN RSA PRIVATE KEY" in text


@pytest.mark.parametrize(
    "args", [["iocs"], ["iocs", "--fanged"], ["iocs", "-t", "secret"], ["report"]]
)
def test_the_indicator_commands_quote_no_secret(tmp_path: Path, args):
    path = tmp_path / f"{RUN}.json"
    path.write_text(leak_result().model_dump_json(), encoding="utf-8")
    reply = CliRunner().invoke(cli.app, [args[0], str(path), *args[1:]])
    assert reply.exit_code == 0, reply.output
    assert leaks(reply.output) == []
    assert "BEGIN RSA PRIVATE KEY  " in reply.output


def test_the_comparison_quotes_no_secret(tmp_path: Path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(ScanResult(root_url=ROOT).model_dump_json(), encoding="utf-8")
    new.write_text(leak_result().model_dump_json(), encoding="utf-8")
    saved = tmp_path / "cmp.json"
    reply = CliRunner().invoke(cli.app, ["diff", str(old), str(new), "--json", str(saved)])
    assert reply.exit_code == 0, reply.output
    assert leaks(reply.output) == []
    assert leaks(saved.read_text(encoding="utf-8")) == []


def test_the_scan_summary_quotes_no_secret(monkeypatch):
    out = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=out, width=200))
    result, candidates = analyze(leak_result())
    cli._summary(result, candidates)
    assert leaks(out.getvalue()) == []


def test_a_context_line_around_a_secret_is_masked_too():
    result = analyze(leak_result())[0]
    mask = SecretMask(result.iocs)
    for ioc in result.iocs:
        assert leaks(mask.text(ioc.context or "")) == [], ioc.context
        assert leaks(mask.indicator(ioc)) == [], ioc.value
    # Text that carries a piece of a secret without the whole of it is withheld.
    assert leaks(mask.text("prefix " + AWS_SECRET[3:20] + " suffix")) == []
