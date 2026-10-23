"""A password written into a link's userinfo is a secret, not an indicator.

``ftp://user:pass@host/`` names a host worth keeping and a password that must
never be quoted. The link becomes one ``url_credentials`` secret; the host, the
address and the link without its userinfo stay ordinary indicators.
"""

from __future__ import annotations

import hashlib
import time
from urllib.parse import urlparse

import pytest

from dirsift.analyze import analyze
from dirsift.extract import (
    SecretMask,
    SecretPieces,
    defang,
    extract_iocs,
    secret_material,
    secret_shown,
)
from dirsift.models import Entry, ScanResult

SOURCE = "http://203.0.113.24/files/links.txt"


def found(text: str):
    return extract_iocs(text + "\n", SOURCE)


def secrets(text: str):
    return [ioc for ioc in found(text) if ioc.ioc_type == "secret"]


def plain(text: str):
    return [ioc for ioc in found(text) if ioc.ioc_type != "secret"]


@pytest.mark.parametrize(
    ("link", "password"),
    [
        ("ftp://user:S3cretPass@203.0.113.10/", "S3cretPass"),
        ("https://admin:hunter2xyz@panel.example.com/panel", "hunter2xyz"),
        ("http://op:Gate.Pass.77@198.51.100.4:8080/gate.php", "Gate.Pass.77"),
        ("mysql://root:pw@198.51.100.7:3306/db", "pw"),
        ("postgres://app:Pg0nly4Me@db.example.com:5432/prod", "Pg0nly4Me"),
        ("redis://:R3disOnlyPass@198.51.100.8:6379/0", "R3disOnlyPass"),
        ("smb://corp;svc:Sm8Passw0rd@203.0.113.30/share", "Sm8Passw0rd"),
        # A raw @ in the password: the userinfo runs to the last @ before the host.
        ("https://admin:p@ssW0rdLong@panel.example.com/x", "p@ssW0rdLong"),
        ("ftp://admin:Xy@ssW0rdLong@ftp.example.com/x", "Xy@ssW0rdLong"),
        # A slash in the password, as a generated or base64 password has.
        ("https://admin:abc/DEFgh12xy@panel.example.com/x", "abc/DEFgh12xy"),
        ("ftp://admin:abc/DEFgh12xy@ftp.example.com/x", "abc/DEFgh12xy"),
        ("ftp://admin:a/b@c/Def12345@203.0.113.31/x", "a/b@c/Def12345"),
        # A quote, angle brackets or a tab in the password.
        ("https://admin:Quo'tePassw0rd@panel.example.com/", "Quo'tePassw0rd"),
        ("https://admin:Lt<GtPassw0rd@panel.example.com/", "Lt<GtPassw0rd"),
        ("https://admin:TabPassw0rd\t@panel.example.com/", "TabPassw0rd"),
        # Brackets, a backslash, a pipe or a brace in the password.
        ("https://admin:Br[ack]etPw77@panel.example.com/", "Br[ack]etPw77"),
        ("https://admin:Pipe|Brace{Pw77@panel.example.com/", "Pipe|Brace{Pw77"),
        ("https://user:Ipv6HostPw78@[2001:db8::1]:8443/pub", "Ipv6HostPw78"),
    ],
)
def test_a_link_with_a_password_is_one_secret(link, password):
    found_secrets = secrets(f"conn = {link}")
    assert [ioc.label for ioc in found_secrets] == ["url_credentials"]
    ioc = found_secrets[0]
    assert ioc.value == link
    assert password in secret_material(ioc)
    # Nothing else built from the text carries the password.
    for other in plain(f"conn = {link}"):
        assert password not in other.value, other
        assert password not in other.defanged, other
        assert defang(password) not in other.defanged, other


def test_the_shown_form_names_the_scheme_and_host_but_not_the_password():
    link = "ftp://user:S3cretPass@203.0.113.10/"
    ioc = secrets(link)[0]
    shown = secret_shown(ioc)
    digest = hashlib.sha256(link.encode()).hexdigest()[:12]
    opening = "fxp://203[.]0[.]113[.]10/"
    assert shown == f"url_credentials  {opening}  {len(link)} chars  sha256:{digest}"
    assert "S3cretPass" not in shown
    assert "user" not in shown


def test_the_shown_form_keeps_the_port_and_defangs_the_host():
    ioc = secrets("https://admin:hunter2xyz@panel.example.com:8443/panel")[0]
    shown = secret_shown(ioc)
    assert shown.startswith("url_credentials  hxxps://panel[.]example[.]com:8443/  ")
    assert "hunter2xyz" not in shown


def test_the_host_and_the_bare_link_stay_indicators():
    text = "mirror ftp://user:S3cretPass@203.0.113.10/pub/\npanel http://op:hunter2xyz@c2.evil-update.top/gate.php"
    by_type = {(ioc.ioc_type, ioc.value) for ioc in plain(text)}
    assert ("ipv4", "203.0.113.10") in by_type
    assert ("url", "ftp://203.0.113.10/pub/") in by_type
    assert ("url", "http://c2.evil-update.top/gate.php") in by_type
    assert ("domain", "c2.evil-update.top") in by_type
    assert not any(ioc_type == "email" for ioc_type, _ in by_type)


def test_no_email_is_built_from_the_password_and_the_host():
    text = "https://admin:hunter2xyz@panel.example.com/panel"
    assert [ioc for ioc in found(text) if ioc.ioc_type == "email"] == []


def test_a_defanged_link_with_a_password_is_still_a_secret():
    text = "hxxps://admin:hunter2xyz@panel[.]example[.]com/panel"
    assert [ioc.label for ioc in secrets(text)] == ["url_credentials"]
    assert all("hunter2xyz" not in ioc.value for ioc in plain(text))


@pytest.mark.parametrize(
    "text",
    [
        "ftp://anonymous@203.0.113.10/pub/",
        "https://panel.example.com:8443/login",
        "git+ssh://git@example.com/repo.git",
        "ftp://user:@203.0.113.10/",
    ],
)
def test_a_link_without_a_password_is_not_a_secret(text):
    assert secrets(text) == []


def test_a_user_without_a_password_keeps_the_old_indicators():
    values = {ioc.value for ioc in plain("contact ops@evil-update.top or ftp://anonymous@203.0.113.10/")}
    assert "ops@evil-update.top" in values
    assert "203.0.113.10" in values


@pytest.mark.parametrize(
    ("line", "password"),
    [
        ("mirror ftp://user:S3cretPass@203.0.113.10/ every night", "S3cretPass"),
        ("DATABASE_URL=mysql://root:My.SqlR00t.Pw@198.51.100.7:3306/shop", "My.SqlR00t.Pw"),
        ("panel = https://admin:hunter2xyz@panel.example.com/panel # keep", "hunter2xyz"),
    ],
)
def test_the_context_line_is_masked_by_the_secret_mask(line, password):
    iocs = found(line)
    mask = SecretMask(iocs)
    for ioc in iocs:
        shown = mask.text(ioc.context)
        assert password not in shown, shown
        assert defang(password) not in shown, shown
        assert password not in mask.indicator(ioc)


def test_secret_pieces_catch_the_password_on_its_own():
    pieces = SecretPieces(secrets("ftp://user:S3cretPass@203.0.113.10/"))
    assert pieces.carried_by("the password was S3cretPass all along")
    assert not pieces.carried_by("ftp://203.0.113.10/")


def test_a_short_password_is_blocked_wherever_it_is_written_whole():
    pieces = SecretPieces(secrets("mysql://root:Zq7x@198.51.100.7:3306/db"))
    assert pieces.carried_by("http://198.51.100.9/Zq7x/dump.php")
    assert not pieces.carried_by("http://198.51.100.9/dump.php")


def test_a_password_under_four_characters_does_not_block_every_line():
    pieces = SecretPieces(secrets("mysql://root:pw@198.51.100.7:3306/db"))
    assert pieces.carried_by("root:pw")
    assert not pieces.carried_by("wget http://198.51.100.9/pwn.sh")


# A raw @ or a slash in the password: the tail never becomes a link or an email.


@pytest.mark.parametrize(
    ("text", "tail"),
    [
        ("https://admin:p@ssW0rdLong@panel.example.com/x", "ssW0rdLong"),
        ("ftp://admin:Xy@ssW0rdLong@ftp.example.com/x", "ssW0rdLong"),
        ("https://admin:abc/DEFgh12xy@panel.example.com/x", "DEFgh12xy"),
        ("ftp://admin:abc/DEFgh12xy@ftp.example.com/x", "DEFgh12xy"),
        ("https://admin:Quo'tePassw0rd@panel.example.com/", "tePassw0rd"),
        ('https://admin:Dq"uotePassw0rd@panel.example.com/', "uotePassw0rd"),
        ("https://admin:Lt<GtPassw0rd@panel.example.com/", "GtPassw0rd"),
        ("https://admin:TabPassw0rd\t@panel.example.com/", "TabPassw0rd"),
    ],
)
def test_no_piece_of_the_password_escapes_as_a_link_or_an_email(text, tail):
    for ioc in plain(text):
        assert tail not in ioc.value, ioc
        assert "admin" not in ioc.value, ioc
    by_type = {(ioc.ioc_type, ioc.value) for ioc in plain(text)}
    assert not any(ioc_type == "email" for ioc_type, _ in by_type)


@pytest.mark.parametrize(
    ("text", "url"),
    [
        ("https://admin:p@ssW0rdLong@panel.example.com/x", "https://panel.example.com/x"),
        ("https://admin:abc/DEFgh12xy@panel.example.com/x", "https://panel.example.com/x"),
        ("https://admin:Br[ack]etPw77@panel.example.com/", "https://panel.example.com/"),
        ("https://admin:Back\\slashPw77@panel.example.com/", "https://panel.example.com/"),
        ("https://admin:Pipe|Brace{Pw77@panel.example.com/", "https://panel.example.com/"),
        ("https://user:Ipv6HostPw78@[2001:db8::1]:8443/pub", "https://[2001:db8::1]:8443/pub"),
    ],
)
def test_the_link_without_its_userinfo_is_still_a_url(text, url):
    urls = [ioc.value for ioc in plain(text) if ioc.ioc_type == "url"]
    assert urls == [url]


def test_no_url_indicator_has_an_empty_host():
    urls = [ioc.value for ioc in found("https://user:Ipv6HostPw78@[2001:db8::1]:8443/pub")]
    assert "https://" not in urls


def test_a_link_with_no_scheme_is_still_a_secret():
    text = "<script src=//user:ProtoRelPw77@cdn.example.com/a.js></script>"
    assert [ioc.label for ioc in secrets(text)] == ["url_credentials"]
    assert secret_shown(secrets(text)[0]).startswith("url_credentials  //cdn[.]example[.]com/  ")
    for ioc in plain(text):
        assert "ProtoRelPw77" not in ioc.value, ioc


@pytest.mark.parametrize(
    "text",
    [
        # A port and a path with an @ further on is a plain link, not a login.
        "http://panel.example.com:8080/path@x",
        "http://198.51.100.4:8080/a@b.example.com",
        "https://panel.example.com:8443/files/user@example.net/",
        "proxy http://panel.example.com:8080/x and user:bob@example.net",
        "http://panel.example.com/a:b@c",
        "https://panel.example.com/path?next=x:y@panel.example.com",
        "jdbc:mysql://198.51.100.7:3306/db?user=root",
        "s3://bucket/a:b@c",
        "see http://panel.example.com/x?time=12:30@noon",
        "git@github.com:org/repo.git",
    ],
)
def test_a_port_or_a_path_is_not_taken_for_a_password(text):
    assert secrets(text) == []


# A password the strict pattern cannot hold (a double quote, a space) is still
# a secret, so the context line around it is masked like any other.


@pytest.mark.parametrize(
    ("line", "password"),
    [
        ('proxy=http://user:p"assW0rdLong@198.51.100.21:3128', 'p"assW0rdLong'),
        ('{"u":"http://user:Ab\\"cdW0rdLong9@198.51.100.21/"}', 'Ab\\"cdW0rdLong9'),
        ("http://user:pass W0rdLong9@198.51.100.21/", "pass W0rdLong9"),
        # Digits and a slash read as a port, but the @ and a whole host after
        # them say it is a password.
        ("http://user:12345/W0rdLong9@198.51.100.21/", "12345/W0rdLong9"),
    ],
)
def test_a_password_outside_the_strict_pattern_is_still_masked(line, password):
    iocs = found(line)
    assert [ioc.label for ioc in iocs if ioc.ioc_type == "secret"] == ["url_credentials"]
    tail = password[-9:]
    for ioc in iocs:
        if ioc.ioc_type != "secret":
            assert tail not in ioc.value, ioc
    mask = SecretMask(iocs)
    for ioc in iocs:
        assert tail not in mask.text(ioc.context), ioc.context
        assert tail not in mask.indicator(ioc)
    hosts = {ioc.value for ioc in iocs if ioc.ioc_type == "ipv4"}
    assert hosts & {"198.51.100.21", "198.51.100.21:3128"}


def test_the_rest_of_the_line_keeps_its_indicators():
    line = (
        'proxy=http://user:p"assW0rdLong@198.51.100.21:3128 contact admin@panel.example.net'
        " http://198.51.100.22/x"
    )
    values = {ioc.value for ioc in plain(line)}
    assert {"198.51.100.21:3128", "admin@panel.example.net", "http://198.51.100.22/x"} <= values


@pytest.mark.parametrize(
    "text",
    [
        "http://panel.example.com:8080/a@b",
        "http://198.51.100.4:8080/a@b.html",
        "http://panel.example.com:8080/x/y@z.png also http://198.51.100.5/ok",
        "http://localhost:8080/a@b.example.com",
        "http://[2001:db8::2]:8080/a@b",
        "https://198.51.100.11:443/x?redir=https://198.51.100.12/",
    ],
)
def test_a_host_with_a_port_and_an_at_in_its_path_is_not_a_secret(text):
    assert secrets(text) == []


def test_a_bracketed_host_is_never_read_as_a_user():
    urls = [ioc.value for ioc in plain("http://[2001:db8::2]:8080/a@b") if ioc.ioc_type == "url"]
    assert urls == ["http://[2001:db8::2]:8080/a@b"]


# A bracketed host that is no IPv6 address must not stop the run.


@pytest.mark.parametrize(
    "text",
    [
        "http://[1.2.3.4]/",
        "http://[2001:db8::7]x",
        "see http://[2001:db8::1]a.example.com/x",
        "http://u:p@[1.2.3.4]/",
        "http://[1:2]/",
        "https://u:Ipv6Passw0rd@[1:2]:8443/x",
        "http://panel.example.com:99999/x",
    ],
)
def test_a_broken_bracketed_host_is_skipped_not_raised(text):
    iocs = found(text)
    for ioc in iocs:
        if ioc.ioc_type == "url":
            parsed = urlparse(ioc.value)
            assert parsed.hostname
            assert parsed.port is None or parsed.port < 65536
    result = ScanResult(
        root_url=SOURCE,
        entries=[Entry(url=SOURCE, name="links.txt", parent_url=SOURCE, text_preview=text)],
        iocs=iocs,
    )
    analyze(result)


# A port-shaped password counts only when a real host follows the @.


@pytest.mark.parametrize(
    "text",
    [
        "http://nas:5000/img/icon@2x.png",
        "http://intranet:8080/users/@me",
        "http://intranet:8080/~bob@team/x",
        "http://cache:6379/a@b",
    ],
)
def test_a_port_and_a_path_with_no_real_host_after_the_at_keep_their_url(text):
    assert secrets(text) == []
    urls = [ioc.value for ioc in plain(text) if ioc.ioc_type == "url"]
    assert urls == [text]


@pytest.mark.parametrize(
    "text",
    [
        # By the rule a real host follows the @, so these stay secrets: the
        # reading that hides a password wins over the one that shows a path.
        "http://jenkins:8080/job/a@b.example.com",
        "http://web01:80/a@198.51.100.64",
        "redis://cache:6379/0@198.51.100.62",
        "http://user:12345/W0rdLong9@[2001:db8::4]/",
    ],
)
def test_a_port_shaped_password_before_a_real_host_is_a_secret(text):
    assert [ioc.label for ioc in secrets(text)] == ["url_credentials"]


def test_a_long_hostile_line_is_read_in_linear_time():
    line = "http://a.b:1/@c" * (256 * 1024 // 15)
    started = time.perf_counter()
    found(line)
    assert time.perf_counter() - started < 1.5
