"""The SIEM, IDS, DNS and sharing targets added in the first SIEM wave.

Elastic (ES|QL and detection rules), Google SecOps YARA-L, IBM QRadar (AQL and
reference sets), CrowdStrike LogScale CQL, Suricata, DNS RPZ and MISP. Each is
held to its own syntax with hostile values, to the shared filter, and to the
same bytes for the same run. Offline validators are used where a pure Python
one exists: idstools parses the Suricata rules, dnspython the zone, and the
JSON schema PyMISP ships checks the MISP event.

Addresses are documentation values and names are made up.
"""

from __future__ import annotations

import json
import re

import pytest
from test_detections import GOLDEN_OPTIONS, ROOT, SECRET, STARTED, fixture_run, ioc

from dirsift.detections import TARGETS, Options, Run, preview, render
from dirsift.detections.collect import collect
from dirsift.models import ScanResult

NEW = [
    "elastic-esql",
    "elastic-rules",
    "secops-yaral",
    "qradar-aql",
    "qradar-set-ip",
    "qradar-set-domain",
    "qradar-set-url",
    "qradar-set-hash",
    "logscale-cql",
    "suricata",
    "rpz",
    "misp",
]

#: A URL with every character one of these languages gives a meaning to.
NASTY_URL = 'http://c2.evil-update.top/a";b|c\\d:e\'f*g%h_i`j'
#: A host name with a double quote, a back quote and a semicolon in it.
NASTY_HOST = 'x`y"z;w.evil-update.top'
#: A host name with a double quote only.
QUOTED_HOST = 'q"uote.evil-update.top'
NASTY_RUN = 'run";x\\y|z'


def nasty_run() -> Run:
    result = ScanResult(
        root_url=ROOT,
        started_at=STARTED,
        iocs=[
            ioc("url", NASTY_URL),
            ioc("domain", NASTY_HOST),
            ioc("domain", QUOTED_HOST),
            ioc("domain", "plain.evil-update.top"),
            ioc("ipv4", "203.0.113.77"),
        ],
    )
    return Run(result=result, name=NASTY_RUN)


LOOSE = Options(exclude_private=False)


def empty_run() -> Run:
    return Run(result=ScanResult(root_url=ROOT, started_at=STARTED), name="empty-run")


#: Nothing at all: no file, no root host (a single file was asked for that is not there).
NOTHING = Options(source=ROOT + "missing.txt")


def test_every_new_target_is_registered():
    for target_id in NEW:
        assert target_id in TARGETS, target_id
    assert TARGETS["suricata"].group == TARGETS["rpz"].group == "network"
    assert TARGETS["misp"].group == "share"
    assert TARGETS["qradar-set-ip"].group == "siem"
    for target_id in ("elastic-esql", "elastic-rules", "secops-yaral", "qradar-aql",
                      "logscale-cql"):
        assert TARGETS[target_id].group == "siem"


@pytest.mark.parametrize("target_id", NEW)
def test_same_run_same_bytes(target_id):
    target = TARGETS[target_id]
    assert render(target, nasty_run(), LOOSE) == render(target, nasty_run(), LOOSE)
    assert render(target, fixture_run(), GOLDEN_OPTIONS) == render(
        target, fixture_run(), GOLDEN_OPTIONS
    )


@pytest.mark.parametrize("target_id", NEW)
def test_the_filter_decides_what_goes_in(target_id):
    """With the default filter the documentation addresses, the resolver and
    the secret stay out, and a shared host never enters as a host."""
    text = render(TARGETS[target_id], fixture_run(), Options())
    for value in ("203.0.113.9", "198.51.100.23", "2001:db8::7", "8.8.8.8", "libssh.org", SECRET):
        assert value not in text, value
    assert "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" not in text
    assert "Global\\dirsift-test" not in text


@pytest.mark.parametrize("target_id", NEW)
def test_an_empty_run_still_gives_a_file_that_reads(target_id):
    text = render(TARGETS[target_id], empty_run(), NOTHING)
    assert "\r" not in text
    if target_id == "elastic-rules":
        assert text == ""
    elif target_id == "misp":
        assert json.loads(text)["Event"]["Attribute"] == []
    else:
        assert "no indicators left after filtering" in text


@pytest.mark.parametrize("target_id", NEW)
def test_the_preview_of_a_nasty_run_is_defanged(target_id):
    text = preview(TARGETS[target_id], nasty_run(), LOOSE)
    assert "203.0.113.77" not in text
    assert "plain.evil-update.top" not in text
    assert "http://" not in text


@pytest.mark.parametrize("target_id", NEW)
def test_file_names_are_ascii(target_id):
    from dirsift.detections import filename

    name = filename(nasty_run(), TARGETS[target_id])
    assert name.isascii()
    assert re.fullmatch(r"dirsift_[A-Za-z0-9._-]+_" + re.escape(target_id) + r"\.[a-z]+", name)


# Elastic


ESQL_LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')


def esql_unescape(body: str) -> str:
    table = {"\\": "\\", '"': '"', "r": "\r", "n": "\n", "t": "\t"}
    return re.sub(r"\\(.)", lambda m: table[m.group(1)], body)


def test_esql_blocks_each_run_alone():
    text = render(TARGETS["elastic-esql"], fixture_run(), GOLDEN_OPTIONS)
    blocks = text.strip().split("\n\n")[1:]
    assert len(blocks) == 8
    for block in blocks:
        lines = block.splitlines()
        assert lines[0].startswith("// ")
        assert lines[1] == "FROM logs-*"
        assert lines[2] == "| WHERE @timestamp > NOW() - 30 days"
        assert lines[3].startswith("| WHERE ")
        assert lines[-1] == "| LIMIT 1000"
    assert 'TO_IP("203.0.113.9")' in text
    assert 'ENDS_WITH(dns.question.name, ".panel-gate.xyz")' in text


def test_esql_string_literals_come_back_byte_for_byte():
    text = render(TARGETS["elastic-esql"], nasty_run(), LOOSE)
    query = "\n".join(line for line in text.splitlines() if line.startswith("|"))
    literals = {esql_unescape(body) for body in ESQL_LITERAL.findall(query)}
    assert NASTY_URL in literals
    assert NASTY_HOST in literals
    # Every quote in the query lines is either a delimiter or escaped.
    for line in text.splitlines():
        if line.startswith("|"):
            assert ESQL_LITERAL.sub("", line).count('"') == 0, line


def test_elastic_rules_are_one_importable_rule_per_line():
    text = render(TARGETS["elastic-rules"], fixture_run(), GOLDEN_OPTIONS)
    assert text.endswith("\n") and text.isascii()
    rules = [json.loads(line) for line in text.splitlines()]
    assert len(rules) == 4
    for rule in rules:
        for key in ("rule_id", "name", "description", "risk_score", "severity", "type",
                    "query", "language"):
            assert key in rule, key
        assert rule["type"] == "query" and rule["language"] == "kuery"
        assert rule["severity"] == "medium" and 22 <= rule["risk_score"] <= 47
        assert rule["enabled"] is False
        assert "TLP:AMBER" in rule["tags"]
        assert rule["author"] == ["cyb3rp03t"]
        assert len(rule["rule_id"]) == 36
    assert len({rule["rule_id"] for rule in rules}) == 4
    assert 'destination.ip: ("198.51.100.23" or "203.0.113.9" or "2001:db8::7")' == rules[0][
        "query"
    ]


def test_elastic_rule_queries_escape_quotes_and_backslashes():
    rules = [json.loads(line) for line in render(TARGETS["elastic-rules"], nasty_run(),
                                                 LOOSE).splitlines()]
    web = next(rule for rule in rules if "url.full" in rule["query"])
    found = [re.sub(r"\\(.)", r"\1", body) for body in ESQL_LITERAL.findall(web["query"])]
    assert NASTY_URL in found
    assert NASTY_HOST in found
    assert NASTY_RUN in web["name"]


# Google SecOps YARA-L


def yaral_rules(text: str) -> list[str]:
    return re.findall(r"^rule [^\n]*\{\n.*?^\}$", text, re.M | re.S)


def test_yaral_rules_have_the_documented_shape():
    text = render(TARGETS["secops-yaral"], fixture_run(), GOLDEN_OPTIONS)
    rules = yaral_rules(text)
    assert len(rules) == 4
    for rule in rules:
        name = rule.split()[1]
        assert re.fullmatch(r"[a-z][a-z0-9_]*", name), name
        lines = rule.splitlines()
        assert lines[1] == "  meta:"
        assert "  events:" in lines and "  condition:" in lines
        assert lines[-2] == "    $e"
        assert '    tlp = "TLP:AMBER"' in lines
        assert rule.count("(") == rule.count(")")
    assert '$e.target.ip = "203.0.113.9"' in text
    assert "$e.network.dns.questions.name = /(^|\\.)panel-gate\\.xyz$/ nocase" in text


def test_yaral_quotes_what_it_can_and_counts_what_it_cannot():
    text = render(TARGETS["secops-yaral"], nasty_run(), LOOSE)
    # Both kinds of quote in one host: no documented quoting holds it.
    assert "x`y" not in text
    assert "// 2 value(s) left out" in text
    # A double quote alone goes into back quotes, read literally.
    assert "= `" + QUOTED_HOST + "` nocase" in text
    # The URL holds both kinds of quote as well, so it is left out of the web rule.
    assert "a\";b" not in text
    # The run name cannot break a meta string.
    for line in text.splitlines():
        if line.strip().startswith(("description =", "author =", "tlp =")):
            value = line.split("=", 1)[1].strip()
            assert value.startswith('"') and value.endswith('"')
            assert '"' not in value[1:-1] and "\\" not in value[1:-1]


def test_yaral_doubles_a_backslash_in_a_double_quoted_string():
    from dirsift.detections.secops import yaral_string

    assert yaral_string("a\\b") == '"a\\\\b"'
    assert yaral_string('a"b') == '`a"b`'
    assert yaral_string('a"b`c') is None


# QRadar


def aql_searches(text: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def test_aql_is_one_search_per_line():
    text = render(TARGETS["qradar-aql"], fixture_run(), GOLDEN_OPTIONS)
    searches = aql_searches(text)
    assert len(searches) == 5
    for search in searches:
        assert search.startswith("SELECT * FROM ")
        assert search.endswith(" LAST 7 DAYS")
    assert "destinationip IN ('198.51.100.23', '203.0.113.9', '2001:db8::7')" in searches[0]
    assert searches[1].startswith("SELECT * FROM flows ")
    assert "UTF8(payload) ILIKE '%panel-gate.xyz%'" in text


def test_aql_leaves_out_a_value_with_a_single_quote():
    text = render(TARGETS["qradar-aql"], nasty_run(), LOOSE)
    assert "# 1 value(s) left out: they hold a single quote, a line break or a tab" in text
    for search in aql_searches(text):
        # Quotes come in pairs: every literal opens and closes on the line.
        assert search.count("'") % 2 == 0, search
    assert "UTF8(payload) ILIKE '%plain.evil-update.top%'" in text


def test_reference_sets_have_the_data_header_and_one_value_per_line():
    text = render(TARGETS["qradar-set-ip"], fixture_run(), GOLDEN_OPTIONS)
    rows = [line for line in text.splitlines() if not line.startswith("#")]
    assert rows == ["data", "198.51.100.23", "203.0.113.9", "2001:db8::7"]
    hashes = render(TARGETS["qradar-set-hash"], fixture_run(), GOLDEN_OPTIONS)
    assert [line for line in hashes.splitlines() if not line.startswith("#")][0] == "data"
    assert "element type ALNIC" in hashes


def test_reference_sets_leave_out_what_csv_would_split():
    run = nasty_run()
    urls = render(TARGETS["qradar-set-url"], run, LOOSE)
    assert NASTY_URL not in urls
    assert "# 1 value(s) left out" in urls
    domains = render(TARGETS["qradar-set-domain"], run, LOOSE)
    rows = [line for line in domains.splitlines() if not line.startswith("#")]
    assert rows == ["data", "c2.evil-update.top", "panel-gate.xyz", "plain.evil-update.top"]
    assert "# 2 value(s) left out" in domains


# LogScale


def test_cql_blocks_and_fields():
    text = render(TARGETS["logscale-cql"], fixture_run(), GOLDEN_OPTIONS)
    blocks = text.strip().split("\n\n")[1:]
    assert len(blocks) == 8
    assert "#event_simpleName=NetworkConnectIP4\n| in(field=RemoteAddressIP4, values=[" in text
    assert '"*.panel-gate.xyz"' in text
    assert "in(field=SHA256HashData, values=[" in text
    assert "// 1 URL(s) hold a * that CQL reads as a wildcard" in text


def test_cql_strings_come_back_byte_for_byte():
    text = render(TARGETS["logscale-cql"], nasty_run(), LOOSE)
    literals = {re.sub(r"\\(.)", r"\1", body) for body in ESQL_LITERAL.findall(text)}
    assert "*" + NASTY_URL.split("://", 1)[1] + "*" in literals
    assert NASTY_HOST in literals
    for line in text.splitlines():
        if not line.startswith("//"):
            assert ESQL_LITERAL.sub("", line).count('"') == 0, line


# Suricata


def suricata_rules(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("alert ")]


def test_suricata_rules_parse_and_carry_unique_local_sids():
    import idstools.rule

    text = render(TARGETS["suricata"], fixture_run(), GOLDEN_OPTIONS)
    lines = suricata_rules(text)
    assert len(lines) == 3 + 3 * 3 + 3
    sids = []
    for line in lines:
        rule = idstools.rule.parse(line)
        assert rule is not None, line
        assert 1000000 <= rule.sid <= 1999999
        assert rule.rev == 1
        assert rule.classtype == "trojan-activity"
        assert rule.msg.startswith("dirsift golden-run ")
        sids.append(rule.sid)
    assert len(set(sids)) == len(sids)
    assert "alert ip $HOME_NET any -> 203.0.113.9 any (" in text
    assert 'dns.query; dotprefix; content:".panel-gate.xyz"; nocase; endswith;' in text
    assert 'http.host; dotprefix; content:".panel-gate.xyz"; endswith;' in text
    assert 'tls.sni; dotprefix; content:".panel-gate.xyz"; nocase; endswith;' in text


def test_suricata_sids_follow_the_indicator_not_the_run():
    one = suricata_rules(render(TARGETS["suricata"], fixture_run(), GOLDEN_OPTIONS))
    other = Run(result=fixture_run().result, name="another-run")
    two = suricata_rules(render(TARGETS["suricata"], other, GOLDEN_OPTIONS))
    assert [re.search(r"sid:(\d+)", line).group(1) for line in one] == [
        re.search(r"sid:(\d+)", line).group(1) for line in two
    ]


def test_suricata_sids_never_collide():
    from dirsift.detections.suricata import _Sids

    sids = _Sids()
    taken = [sids.take("same") for _ in range(5)]
    assert len(set(taken)) == 5
    assert all(1000000 <= sid <= 1999999 for sid in taken)


def test_suricata_content_writes_reserved_characters_in_hex():
    import idstools.rule

    from dirsift.detections.suricata import content

    assert content('a";:|\\b') == '"a|22||3B||3A||7C||5C|b"'
    assert content("café") == '"caf|C3 A9|"'
    text = render(TARGETS["suricata"], nasty_run(), LOOSE)
    for line in suricata_rules(text):
        rule = idstools.rule.parse(line)
        assert rule is not None, line
        for option in rule.options:
            if option["name"] == "content":
                inner = option["value"][1:-1]
                assert not re.search(r'[";\\]', inner), inner
                # Pipes only open and close hex runs.
                assert all(re.fullmatch(r"[0-9A-F ]+", run) for run in inner.split("|")[1::2])
    assert "|22|" in text and "|3B|" in text and "|5C|" in text and "|60|" not in text


def test_suricata_msg_escapes_the_run_name():
    import idstools.rule

    text = render(TARGETS["suricata"], nasty_run(), LOOSE)
    rule = idstools.rule.parse(suricata_rules(text)[0])
    assert rule.msg.startswith('dirsift run\\"\\;x\\\\y|z ')


def test_suricata_url_rules_match_host_and_path():
    text = render(TARGETS["suricata"], fixture_run(), GOLDEN_OPTIONS)
    url = next(line for line in suricata_rules(text) if "/gate.php" in line)
    assert 'http.host; content:"c2.evil-update.top"; bsize:18;' in url
    assert 'http.uri.raw; content:"/gate.php?id=1&k=*"; startswith;' in url


# RPZ


def test_rpz_is_a_zone_dnspython_reads():
    import dns.rdatatype
    import dns.zone

    text = render(TARGETS["rpz"], fixture_run(), GOLDEN_OPTIONS)
    zone = dns.zone.from_text(text, origin="rpz.dirsift.invalid.", relativize=True,
                              check_origin=True)
    soa = zone.get_rdataset("@", dns.rdatatype.SOA)[0]
    assert soa.serial == 2026100109
    assert [str(ns.target) for ns in zone.get_rdataset("@", dns.rdatatype.NS)] == ["localhost."]
    for name in ("panel-gate.xyz", "*.panel-gate.xyz", "c2.evil-update.top"):
        rdata = zone.get_rdataset(name, dns.rdatatype.CNAME)
        assert rdata is not None, name
        assert str(rdata[0].target) == "."


def test_rpz_leaves_out_names_a_zone_file_would_read_as_syntax():
    import dns.zone

    text = render(TARGETS["rpz"], nasty_run(), LOOSE)
    assert "; 2 name(s) left out" in text
    zone = dns.zone.from_text(text, origin="rpz.dirsift.invalid.", relativize=True)
    names = sorted(str(name) for name in zone.nodes)
    assert names == ["*.c2.evil-update.top", "*.panel-gate.xyz", "*.plain.evil-update.top", "@",
                     "c2.evil-update.top", "panel-gate.xyz", "plain.evil-update.top"]


# MISP


def misp_schema() -> dict:
    from pathlib import Path

    import pymisp

    path = Path(pymisp.__file__).parent / "data" / "schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_misp_event_matches_the_schema_pymisp_ships():
    import jsonschema

    for run, options in ((fixture_run(), GOLDEN_OPTIONS), (nasty_run(), LOOSE),
                         (empty_run(), NOTHING)):
        event = json.loads(render(TARGETS["misp"], run, options))
        jsonschema.validate(event, misp_schema())


def test_misp_event_loads_and_uses_valid_category_type_pairs():
    from pathlib import Path

    import pymisp

    types = json.loads(
        (Path(pymisp.__file__).parent / "data" / "describeTypes.json").read_text(encoding="utf-8")
    )["result"]
    text = render(TARGETS["misp"], fixture_run(), GOLDEN_OPTIONS)
    event = pymisp.MISPEvent()
    event.load(text)
    assert event.distribution == 0
    assert event.published is False
    assert [tag.name for tag in event.tags] == ["tlp:amber"]
    assert len(event.attributes) == 12
    for attribute in event.attributes:
        assert attribute.type in types["category_type_mappings"][attribute.category]
    by_type = {attribute.type: attribute for attribute in event.attributes}
    assert by_type["email-src"].to_ids is False
    assert by_type["ip-dst"].to_ids is True
    assert by_type["sha256"].to_ids is True


@pytest.mark.parametrize(("level", "colour"), [("CLEAR", "#ffffff"), ("GREEN", "#33FF00"),
                                               ("AMBER", "#FFC000"), ("RED", "#FF2B2B")])
def test_misp_tlp_tag(level, colour):
    event = json.loads(render(TARGETS["misp"], fixture_run(), Options(tlp=level)))
    assert event["Event"]["Tag"] == [
        {"name": "tlp:" + level.lower(), "colour": colour, "exportable": True}
    ]


def test_misp_uuids_are_stable_and_distinct():
    one = json.loads(render(TARGETS["misp"], fixture_run(), GOLDEN_OPTIONS))["Event"]
    uuids = [one["uuid"], *[attribute["uuid"] for attribute in one["Attribute"]]]
    assert len(set(uuids)) == len(uuids)
    other = json.loads(render(TARGETS["misp"], Run(result=fixture_run().result, name="b"),
                              GOLDEN_OPTIONS))["Event"]
    assert other["uuid"] != one["uuid"]


def test_misp_carries_the_hostile_url_whole():
    event = json.loads(render(TARGETS["misp"], nasty_run(), LOOSE))["Event"]
    assert NASTY_URL in {attribute["value"] for attribute in event["Attribute"]}
    assert len(event["Attribute"]) == len(collect(nasty_run().result, LOOSE).indicators)


# The report groups the targets


def test_every_live_target_is_in_exactly_one_report_family():
    from dirsift.detections import FAMILIES

    placed = [target_id for _, ids in FAMILIES for target_id in ids]
    assert len(placed) == len(set(placed))
    live = {target.id for target in TARGETS.values() if target.live}
    assert live <= set(placed)
    assert set(placed) <= set(TARGETS)
    blocks = dict(FAMILIES)["Block lists"]
    assert all(target_id.startswith("blocklist-") for target_id in blocks)


def test_the_report_has_one_row_per_family_and_each_type_once():
    from test_report import detections_report

    from dirsift.report import render_markdown

    text = render_markdown(detections_report(), logo="none")
    table = text[text.index("| Family | Formats | Carries |"):text.index("### 10.2")]
    rows = [line for line in table.splitlines() if line.startswith("| ")][2:]
    assert [row.split(" | ")[0].strip("| ") for row in rows] == [
        "SIEM queries", "Rules and sharing", "Block lists", "Network"
    ]
    for row in rows:
        carries = row.rstrip(" |").rsplit(" | ", 1)[1]
        kinds = [part.rsplit(" ", 1)[0] for part in carries.split(", ")]
        assert len(kinds) == len(set(kinds)), row
    assert "QRadar reference sets (domains, URLs)" in rows[0]
    assert "YARA not generated" in rows[1]


# Values at the edges: very long, control characters, zone ids


def long_url_run(path_length: int) -> Run:
    url = "http://c2.evil-update.top/gate.php?d=" + "QUJD" * (path_length // 4)
    result = ScanResult(root_url=ROOT, started_at=STARTED, iocs=[ioc("url", url)])
    return Run(result=result, name="long-run")


def test_a_long_url_is_cut_in_the_msg_and_kept_whole_in_the_match():
    import idstools.rule

    from dirsift.detections.suricata import MAX_RULE_BYTES, MSG_CUT, MSG_VALUE_LIMIT

    text = render(TARGETS["suricata"], long_url_run(3000), LOOSE)
    rule = next(line for line in suricata_rules(text) if "gate.php" in line)
    assert len(rule.encode()) <= MAX_RULE_BYTES
    parsed = idstools.rule.parse(rule)
    assert parsed.msg.endswith(MSG_CUT)
    assert len(parsed.msg) < MSG_VALUE_LIMIT + 120
    assert "QUJD" * 700 in rule  # the content still carries the whole path
    assert "left out" not in text


@pytest.mark.parametrize("length", [4100, 8000])
def test_a_rule_past_what_suricata_loads_is_left_out_and_counted(length):
    """4100: the content passes Suricata's limit; 8000: the line does too."""
    from dirsift.detections.suricata import MAX_RULE_BYTES

    text = render(TARGETS["suricata"], long_url_run(length), LOOSE)
    assert not [line for line in suricata_rules(text) if "gate.php" in line]
    assert f"# 1 rule(s) left out: longer than {MAX_RULE_BYTES} bytes" in text
    assert all(len(line.encode()) <= MAX_RULE_BYTES for line in text.splitlines())
    # The host level rules for the same domain are still written.
    assert 'content:".c2.evil-update.top"' in text


def test_an_ipv6_zone_id_is_dropped_from_the_rule_header():
    import idstools.rule

    from dirsift.detections.suricata import address

    assert address("2001:db8::81%eth0") == "2001:db8::81"
    assert address("not an address") is None
    result = ScanResult(root_url=ROOT, started_at=STARTED,
                        iocs=[ioc("ipv6", "2001:db8::81%eth0")])
    text = render(TARGETS["suricata"], Run(result=result, name="zone"), LOOSE)
    line = next(line for line in suricata_rules(text) if "2001:db8::81" in line)
    assert "%eth0" not in line
    assert idstools.rule.parse(line).header.endswith("-> 2001:db8::81 any")


@pytest.mark.parametrize("char", ["\n", "\r"])
def test_yaral_leaves_out_a_line_break(char):
    from dirsift.detections.secops import yaral_string

    assert yaral_string("a" + char + "b.example.com") is None
    assert yaral_string('a"' + char + "b") is None


def test_yaral_writes_a_tab_as_its_documented_escape():
    from dirsift.detections.secops import meta_text, yaral_string

    assert yaral_string("a\tb") == '"a\\tb"'
    assert yaral_string('a"\tb') is None  # back quotes would carry the tab raw
    assert "\n" not in meta_text("x\ny\tz")


def control_run() -> Run:
    result = ScanResult(
        root_url=ROOT,
        started_at=STARTED,
        iocs=[ioc("url", "http://c2.evil-update.top/a\rb"),
              ioc("url", "http://c2.evil-update.top/c\td"),
              ioc("url", "http://c2.evil-update.top/e\nf")],
    )
    return Run(result=result, name="control")


def test_cql_escapes_a_line_feed_and_counts_what_it_cannot_write():
    from dirsift.detections.logscale import cql_ok, cql_string

    assert cql_string("a\nb") == '"a\\nb"'
    assert not cql_ok("a\rb") and not cql_ok("a\tb")
    text = render(TARGETS["logscale-cql"], control_run(), LOOSE)
    assert "// 2 value(s) left out: a carriage return or a tab" in text
    assert "\r" not in text and "\t" not in text
    assert "/e\\nf" in text


def test_aql_and_reference_sets_leave_out_a_tab():
    from dirsift.detections.qradar import aql_string, set_value_ok

    assert aql_string("a\tb") is None
    assert not set_value_ok("a\tb")
    text = render(TARGETS["qradar-aql"], control_run(), LOOSE)
    assert "# 3 value(s) left out" in text
    assert "\t" not in text and "\r" not in text


@pytest.mark.parametrize("target_id", ["secops-yaral", "logscale-cql", "qradar-aql",
                                       "suricata", "qradar-set-url"])
def test_no_raw_control_character_reaches_these_files(target_id):
    text = render(TARGETS[target_id], control_run(), LOOSE)
    assert not re.search(r"[\x00-\x09\x0b-\x1f]", text), target_id
    # A raw line feed inside a value would split it over two lines.
    assert "/e\nf" not in text, target_id
