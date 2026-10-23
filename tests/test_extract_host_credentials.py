"""A password written as ``user:password@host`` with no scheme is a secret.

The shape is everywhere in ordinary text: times, labels in front of an email,
git remotes. Only a user with a letter in it, a password with no space before
it and a real host after the @ make a secret; the rest stays what it was.
"""

from __future__ import annotations

import hashlib

import pytest

from dirsift.analyze import analyze
from dirsift.detections import TARGETS, Options, Run, render
from dirsift.extract import (
    SecretMask,
    SecretPieces,
    dedupe_iocs,
    defang,
    extract_iocs,
    secret_shown,
)
from dirsift.models import Entry, ScanResult

SOURCE = "http://203.0.113.24/files/conf.txt"


def found(text: str):
    return extract_iocs(text + "\n", SOURCE)


def secrets(text: str):
    return [ioc for ioc in found(text) if ioc.ioc_type == "secret"]


def plain(text: str):
    return [ioc for ioc in found(text) if ioc.ioc_type != "secret"]


@pytest.mark.parametrize(
    ("text", "value", "password", "host"),
    [
        ("conn user:NoSchemePw77@db.example.net", "user:NoSchemePw77@db.example.net",
         "NoSchemePw77", None),
        ("conn user:NoSchemePw77@db.evil-update.top", "user:NoSchemePw77@db.evil-update.top",
         "NoSchemePw77", "db.evil-update.top"),
        ("curl -u deploy:CurlUserPw88@203.0.113.91 -T loot.tar",
         "deploy:CurlUserPw88@203.0.113.91", "CurlUserPw88", "203.0.113.91"),
        ('{"dsn": "app:JsonDsnPassw0rd@db.example.org:3306/shop"}',
         "app:JsonDsnPassw0rd@db.example.org:3306/shop", "JsonDsnPassw0rd", None),
        ("DSN=svc:Sch3me.LessPw@198.51.100.90:5432/app",
         "svc:Sch3me.LessPw@198.51.100.90:5432/app", "Sch3me.LessPw", "198.51.100.90:5432"),
        ("proxy op:Br4ck3tPw@[2001:db8::5]:3128", "op:Br4ck3tPw@[2001:db8::5]:3128",
         "Br4ck3tPw", None),
        ("root:pw@198.51.100.7", "root:pw@198.51.100.7", "pw", "198.51.100.7"),
    ],
)
def test_a_password_before_a_host_with_no_scheme_is_a_secret(text, value, password, host):
    found_secrets = secrets(text)
    assert [(ioc.label, ioc.value) for ioc in found_secrets] == [("host_credentials", value)]
    others = plain(text)
    for ioc in others:
        assert password not in ioc.value, ioc
        assert defang(password) not in ioc.defanged, ioc
    assert not [ioc for ioc in others if ioc.ioc_type == "email"]
    if host:
        assert host in {ioc.value for ioc in others}
    mask = SecretMask(found(text))
    for ioc in found(text):
        assert password not in mask.text(ioc.context)
        assert defang(password) not in mask.text(ioc.context)
        assert password not in mask.indicator(ioc)


def test_the_shown_form_names_the_host_but_not_the_password():
    ioc = secrets("conn user:NoSchemePw77@db.example.net")[0]
    value = "user:NoSchemePw77@db.example.net"
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    assert secret_shown(ioc) == (
        f"host_credentials  db[.]example[.]net  {len(value)} chars  sha256:{digest}"
    )


def test_the_password_is_blocked_on_its_own():
    pieces = SecretPieces(secrets("conn user:NoSchemePw77@db.example.net"))
    assert pieces.carried_by("it was NoSchemePw77 again")


@pytest.mark.parametrize(
    "text",
    [
        "git@github.com:org/repo.git",
        "git clone git@example.com:org/repo.git",
        "ssh git@db.example.com",
        "meet at 12:30@panel.example.com",
        "Time 10:20:30@panel.example.com",
        "ratio 1:2@3",
        "ratio 1:2@198.51.100.3",
        "mailto:a@b.example.com",
        "<a href=mailto:ops@example.org>",
        "Name: jane@example.com",
        "Name:jane@example.org",
        "email:ops@example.org",
        "email: ops@example.com",
        "contact:ops@example.org",
        "Copyright: dev@example.com",
        "Copyright:dev@example.org",
        "TODO: ask ops@example.com",
        "# TODO:ops@example.org",
        "https://panel.example.com/path?next=key:value@example.org",
        "http://198.51.100.8/users/a:b@c.example.com",
        "//note:x@panel.example.org",
        r"C:\x@y",
        r"C:\Users\x:y@panel.example.com",
        "a:b@c",
        "a:b@intranet",
        "fe80:1@panel.example.com",
        "2001:db8::1@panel.example.com",
        "user@db.example.com:22",
        "ssh user@198.51.100.4:22",
        "user: pass@db.example.com",
        "path/to/a:b@db.example.com",
    ],
)
def test_ordinary_text_with_a_colon_and_an_at_is_not_a_secret(text):
    assert [ioc for ioc in secrets(text) if ioc.label == "host_credentials"] == []


# A field or header name before an email is a label, not a login: the email
# must survive as an indicator on every exit.

LABELLED_EMAILS = [
    ("send_to:drop@evil-update.top", "drop@evil-update.top"),
    ("result_email:drop@evil-update.top", "drop@evil-update.top"),
    ("recipient:drop@evil-update.top", "drop@evil-update.top"),
    ("receiver:drop@evil-update.top", "drop@evil-update.top"),
    ("admin:drop@evil-update.top", "drop@evil-update.top"),
    ("dropbox:drop@evil-update.top", "drop@evil-update.top"),
    ("Delivered-To:jane@example.org", "jane@example.org"),
    ("X-Original-To:jane@example.org", "jane@example.org"),
    ("Envelope-To:jane@example.org", "jane@example.org"),
    ("Resent-From:jane@example.org", "jane@example.org"),
    ("Errors-To:jane@example.org", "jane@example.org"),
    ("X-Sender:jane@example.org", "jane@example.org"),
    ("Message-ID:abc123@mail.example.org", "abc123@mail.example.org"),
    ("user:jane@example.org logged in", "jane@example.org"),
    ("uid:jane@example.org", "jane@example.org"),
    ("login:jane@example.org", "jane@example.org"),
    ("account:jane@example.org", "jane@example.org"),
    ("rcpt:jane@example.org", "jane@example.org"),
    ("sent:jane@example.org", "jane@example.org"),
    ("assignee:jane@example.org", "jane@example.org"),
    ("reporter:jane@example.org", "jane@example.org"),
    ("customer:jane@example.org", "jane@example.org"),
    ("id:jane@example.org", "jane@example.org"),
    ("42,jane:jane@example.org,active", "jane@example.org"),
    ("17\tuser:jane@example.org\tok", "jane@example.org"),
    ("contact_email:ops@example.org", "ops@example.org"),
    ("admin_email:ops@example.org", "ops@example.org"),
    ("support_email:ops@example.org", "ops@example.org"),
    ("email_address:ops@example.org", "ops@example.org"),
    ("owner_email:ops@example.org", "ops@example.org"),
    ("username:noreply@example.org", "noreply@example.org"),
    ("spring.mail.username:noreply@example.org", "noreply@example.org"),
    ("smtp.user:noreply@example.org", "noreply@example.org"),
    ("key:value@example.org", "value@example.org"),
    ("D:jane@example.org", "jane@example.org"),
    ("results:jane.doe@example.org", "jane.doe@example.org"),
    ("**Email:**jane@example.org", "jane@example.org"),
    ("tel:+15550100@example.org", "15550100@example.org"),
    ("jdbc:mysql:jane@example.org", "jane@example.org"),
    ("Delivered-To:Jane.Doe@corp.example.com", "Jane.Doe@corp.example.com"),
    ("X-Sender:J.Smith@example.org", "J.Smith@example.org"),
    ("owner:Mary-Ann.Lee@example.org", "Mary-Ann.Lee@example.org"),
    ("user:Jane_Doe42@example.org", "Jane_Doe42@example.org"),
    # After a scheme or a field that names an address, any local part.
    ("mailto:Jane@example.org", "Jane@example.org"),
    ("sender:NoReply@example.org", "NoReply@example.org"),
    ("X-Sender:Support@example.org", "Support@example.org"),
    ("recipient:JaneDoe@example.org", "JaneDoe@example.org"),
    ("rcpt:JSmith@example.org", "JSmith@example.org"),
    ("send_to:Drop2024@evil-update.top", "Drop2024@evil-update.top"),
    ("Resent-From:Ops7Team@example.org", "Ops7Team@example.org"),
    # Up to six trailing digits on a lower case name.
    ("result:drop12345@evil-update.top", "drop12345@evil-update.top"),
    ("login:jdoe99999@example.org", "jdoe99999@example.org"),
]


@pytest.mark.parametrize(("line", "email"), LABELLED_EMAILS)
def test_a_label_before_an_email_keeps_the_email(line, email):
    iocs = found(line)
    assert not [ioc for ioc in iocs if ioc.label == "host_credentials"]
    assert email in {ioc.value for ioc in iocs if ioc.ioc_type == "email"}


def test_labelled_emails_reach_the_csv_and_the_indicator_list():
    root = "http://203.0.113.9/drop/"
    text = "\n".join(line for line, _ in LABELLED_EMAILS) + "\n"
    data = text.encode()
    entry = Entry(
        url=root + "fields.txt",
        name="fields.txt",
        parent_url=root,
        kind="data",
        size=len(data),
        fetched_bytes=len(data),
        head_hex=data[:64].hex(),
        text_preview=text,
        sha256="ab" * 32,
    )
    result = ScanResult(
        root_url=root,
        entries=[entry],
        iocs=dedupe_iocs(extract_iocs(text, entry.url)),
    )
    result = analyze(result)[0]
    run = Run(result=result, name="fields")
    options = Options(pick=(entry.url,), exclude_private=False)
    for target in ("csv", "indicators"):
        shown = render(TARGETS[target], run, options)
        for _, email in LABELLED_EMAILS:
            # Indicators dedupe without case, so ``Jane@`` may show as ``jane@``.
            listed = shown.lower()
            assert email.lower() in listed or defang(email).lower() in listed, (target, email)


# A password that is no mailbox name stays a secret, whatever its characters.


@pytest.mark.parametrize(
    ("text", "password"),
    [
        ("curl -u admin:Pa/ss99Word@db.example.com", "Pa/ss99Word"),
        ("admin:Pa:ss99Word@db.example.com", "Pa:ss99Word"),
        (r"admin:Pa\ss99Word@db.example.com", r"Pa\ss99Word"),
        (r"CORP\svc:Svc99Passw0rd@db.example.com", "Svc99Passw0rd"),
        ("j\u00fcrgen:Geheim99Pw@db.example.com", "Geheim99Pw"),
        ("cmd -admin:Dash99Passw@db.example.com", "Dash99Passw"),
        ("http://198.51.100.9/x?c=admin:Query99Pw@db.example.com", "Query99Pw"),
        ("send_to:Svc99Passw0rd@198.51.100.4", "Svc99Passw0rd"),
        # Hex letters, but longer than a group of an IPv6 address.
        ("cafe:Babe9999@db.example.com", "Babe9999"),
        # One capitalised word, or a name with a digit inside, is a password.
        ("admin:Summer@db.example.com", "Summer"),
        ("admin:Passw0rd@db.example.com", "Passw0rd"),
        ("admin:Jane.D0e@db.example.com", "Jane.D0e"),
        ("admin:Jane.Doe12345@db.example.com", "Jane.Doe12345"),
        # Not an address field, and no mailbox shape: still a secret.
        ("id:a1b2c3@db.example.com", "a1b2c3"),
        ("login:jdoe1234567@db.example.com", "jdoe1234567"),
        ("admin:JaneDoe@db.example.com", "JaneDoe"),
        # An address field before an IP address: no email to keep.
        ("rcpt:Svc99Passw0rd@198.51.100.4", "Svc99Passw0rd"),
    ],
)
def test_a_password_with_a_slash_a_colon_or_a_domain_user_is_a_secret(text, password):
    iocs = found(text)
    assert "host_credentials" in {ioc.label for ioc in iocs}, iocs
    tail = password[-8:]
    for ioc in iocs:
        if ioc.ioc_type != "secret":
            assert tail not in ioc.value, ioc


@pytest.mark.parametrize(
    "text",
    [
        r"C:\Users\x:y@panel.example.com",
        r"D:/backup/a:Pw99x@panel.example.com",
        "fe80::1@panel.example.com",
        "dead:beef@panel.example.com",
        "2001:db8@panel.example.com",
        "user/admin@EXAMPLE.ORG",
    ],
)
def test_a_drive_a_path_or_an_address_is_still_no_login(text):
    assert [ioc for ioc in secrets(text) if ioc.label == "host_credentials"] == []
