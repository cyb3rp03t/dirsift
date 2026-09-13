"""Parser tests against the real output of each server's index."""

from __future__ import annotations

from dirsift.fetcher import Response
from dirsift.listing import detect_flavor, parse_listing, parse_size

BASE = "http://example.test/files/"


def make(body: str, *, server: str = "", content_type: str = "text/html") -> Response:
    return Response(
        url=BASE,
        status=200,
        headers={"server": server, "content-type": content_type},
        body=body.encode(),
        truncated=False,
        elapsed=0.01,
    )


APACHE_PRE = """<html><head><title>Index of /files</title></head><body>
<h1>Index of /files</h1><pre><img src="/icons/blank.gif" alt="Icon "> <a href="?C=N;O=D">Name</a>
<hr><img src="/icons/back.gif" alt="[PARENTDIR]"> <a href="/">Parent Directory</a>   -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="bin/">bin/</a>  2026-02-12 09:41    -
<img src="/icons/unknown.gif" alt="[   ]"> <a href="run.bat">run.bat</a>  2026-02-12 09:41  4.2K
<img src="/icons/unknown.gif" alt="[   ]"> <a href="loader.exe">loader.exe</a>  2026-02-11 22:03  1.4M
<hr></pre></body></html>"""

NGINX = """<html><head><title>Index of /files/</title></head><body>
<h1>Index of /files/</h1><hr><pre><a href="../">../</a>
<a href="cfg/">cfg/</a>                         12-Feb-2026 09:41       -
<a href="stage1.ps1">stage1.ps1</a>             12-Feb-2026 09:41    3211
<a href="dump.tar.gz">dump.tar.gz</a>           11-Feb-2026 22:03  4194304
</pre><hr></body></html>"""

IIS = """<html><head><title>example.test - /files/</title></head><body>
<H1>example.test - /files/</H1><hr><pre><A HREF="/">[To Parent Directory]</A><br><br>
 2/12/2026  9:41 AM        &lt;dir&gt; <A HREF="/files/tools/">tools</A><br>
 2/12/2026  9:41 AM         4096 <A HREF="/files/notes.txt">notes.txt</A><br>
</pre><hr></body></html>"""

PYTHON = """<!DOCTYPE HTML><html><head><title>Directory listing for /files/</title></head>
<body><h1>Directory listing for /files/</h1><hr><ul>
<li><a href="a.bin">a.bin</a></li>
<li><a href="sub/">sub/</a></li>
</ul><hr></body></html>"""

CADDY_TABLE = """<html><head><title>files</title></head><body>
<table class="listing"><tbody>
<tr><td><a href="payload.zip">payload.zip</a></td><td>842 KiB</td><td>2026-02-12 09:41</td></tr>
<tr><td><a href="logs/">logs/</a></td><td>&mdash;</td><td>2026-02-10 11:00</td></tr>
</tbody></table></body></html>"""

JSON_LISTING = """[
 {"name":"beacon.exe","type":"file","mtime":"Thu, 12 Feb 2026 09:41:00 GMT","size":91234},
 {"name":"conf","type":"directory","mtime":"Thu, 12 Feb 2026 09:41:00 GMT"}
]"""


def names(listing) -> list[str]:
    return [e.name for e in listing.entries]


def test_apache_pre_layout():
    listing = parse_listing(make(APACHE_PRE, server="Apache/2.4.62"), BASE)
    assert listing.flavor == "apache"
    assert names(listing) == ["bin", "run.bat", "loader.exe"]
    by_name = {e.name: e for e in listing.entries}
    assert by_name["bin"].is_dir
    assert by_name["run.bat"].size == 4300  # 4.2K
    assert by_name["loader.exe"].modified == "2026-02-11 22:03"


def test_nginx_autoindex():
    listing = parse_listing(make(NGINX, server="nginx/1.27.3"), BASE)
    assert listing.flavor == "nginx"
    assert names(listing) == ["cfg", "stage1.ps1", "dump.tar.gz"]
    by_name = {e.name: e for e in listing.entries}
    assert by_name["stage1.ps1"].size == 3211
    assert by_name["dump.tar.gz"].modified == "11-Feb-2026 22:03"


def test_iis():
    listing = parse_listing(make(IIS, server="Microsoft-IIS/10.0"), BASE)
    assert listing.flavor == "iis"
    assert names(listing) == ["tools", "notes.txt"]


def test_python_http_server():
    listing = parse_listing(make(PYTHON, server="SimpleHTTP/0.6 Python/3.11"), BASE)
    assert listing.flavor == "python"
    assert names(listing) == ["a.bin", "sub"]
    assert {e.name: e.is_dir for e in listing.entries}["sub"] is True


def test_caddy_table_layout():
    listing = parse_listing(make(CADDY_TABLE, server="Caddy"), BASE)
    assert listing.flavor == "caddy"
    by_name = {e.name: e for e in listing.entries}
    assert by_name["payload.zip"].size == 862208  # 842 KiB


def test_json_listing():
    listing = parse_listing(make(JSON_LISTING, content_type="application/json"), BASE)
    assert listing.flavor == "json"
    by_name = {e.name: e for e in listing.entries}
    assert by_name["beacon.exe"].size == 91234
    assert by_name["conf"].is_dir


def test_parent_and_sort_links_are_dropped():
    """The walk must never climb out of the directory it was pointed at."""
    listing = parse_listing(make(APACHE_PRE, server="Apache"), BASE)
    urls = [e.url for e in listing.entries]
    assert all(u.startswith(BASE) for u in urls)
    assert not any("C=N" in u for u in urls)
    assert "Parent Directory" not in names(listing)


def test_offsite_and_non_http_links_are_dropped():
    body = """<h1>Index of /files</h1><pre>
    <a href="http://evil.test/x.exe">x.exe</a>
    <a href="mailto:a@b.test">mail</a>
    <a href="javascript:void(0)">js</a>
    <a href="real.exe">real.exe</a></pre>"""
    listing = parse_listing(make(body, server="Apache"), BASE)
    assert names(listing) == ["real.exe"]


def test_size_parsing():
    assert parse_size("4.2K") == 4300
    assert parse_size("1.4M") == 1468006
    assert parse_size("3211") == 3211
    assert parse_size("-") is None
    assert parse_size(None) is None


def test_flavor_from_body_when_server_header_is_absent():
    assert detect_flavor(make(NGINX), None) == "nginx"
