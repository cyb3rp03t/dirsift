"""What a scan note means, in a sentence a person can act on.

A row that says "HTTP 503" tells you the server refused and nothing else: not
whether it was you, the target, or something between the two. These are the
sentences that go next to it. They say what is known and stop there, because a
guess dressed as a diagnosis is worse than a bare status code.
"""

from __future__ import annotations

from dirsift.diagnose import explain


def test_a_status_with_no_special_case_still_gets_its_meaning():
    note = explain("HTTP 404")
    assert note
    assert "not there" in note.lower() or "gone" in note.lower()


def test_an_antivirus_interception_is_named_as_one():
    """Kaspersky answers locally with 499 and this exact phrase."""
    note = explain("HTTP 499 Request has been forbidden by antivirus")
    assert "antivirus" in note.lower()
    assert "nothing ever reached the target" in note.lower()


def test_a_bare_499_is_not_blamed_on_an_antivirus():
    """nginx uses 499 for a client that went away, which is a different thing."""
    note = explain("HTTP 499")
    assert "antivirus" in note.lower()  # still worth mentioning as one cause
    assert "nginx" in note.lower()


def test_service_unavailable_says_the_tool_already_waited():
    note = explain("HTTP 503")
    assert "retried" in note.lower() or "waited" in note.lower()


def test_an_auth_wall_says_the_branch_was_dropped_on_purpose():
    note = explain("401 at http://203.0.113.24/private/")
    assert "credential" in note.lower()


def test_too_many_requests_says_to_slow_down():
    note = explain("HTTP 429")
    assert "--delay" in note


def test_a_timeout_points_at_the_timeout_flag():
    note = explain("ConnectTimeout: timed out")
    assert "--timeout" in note or "--delay" in note


def test_a_refused_connection_is_not_confused_with_a_slow_one():
    note = explain("ConnectError: [Errno 111] Connection refused")
    assert "nothing is listening" in note.lower() or "refused" in note.lower()


def test_a_name_that_does_not_resolve_says_so():
    note = explain("ConnectError: [Errno -2] Name or service not known")
    assert "name" in note.lower()


def test_a_note_nobody_wrote_a_sentence_for_comes_back_empty():
    """Silence beats invention: an unknown detail gets no explanation at all."""
    assert explain("something nobody has seen before") == ""
    assert explain("") == ""


def test_the_gone_and_forbidden_cases_are_told_apart():
    assert explain("HTTP 403") != explain("HTTP 404")
    assert "forbidden" in explain("HTTP 403").lower()


def test_a_server_error_is_the_target_breaking_not_the_scan():
    note = explain("HTTP 500")
    assert "target" in note.lower() or "server" in note.lower()


# -- the note the walk writes ----------------------------------------------


def test_the_walk_keeps_the_reason_line_a_server_sent(tmp_path):
    """Without the reason, an antivirus page and an nginx 499 look identical."""
    import http.server
    import socketserver
    import threading

    class Refuse(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(503, "No site configured")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    from dirsift.fetcher import MIN_DELAY
    from dirsift.walker import ScanOptions, scan

    httpd = socketserver.TCPServer(("127.0.0.1", 0), Refuse)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/"
        result = scan(url, ScanOptions(depth=1, delay=MIN_DELAY, allow_private=True))
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert result.errors
    assert "No site configured" in result.errors[0].detail


def test_the_report_explains_its_notes_too():
    from dirsift.models import ScanError, ScanResult
    from dirsift.report import render_markdown

    result = ScanResult(
        root_url="http://203.0.113.24/files/",
        errors=[
            ScanError(
                url="http://203.0.113.24/files/",
                stage="walk",
                detail="HTTP 503 Service Temporarily Unavailable",
            ),
            ScanError(
                url="http://203.0.113.24/files/x.bin",
                stage="peek",
                detail="a detail nobody has written a sentence for",
            ),
        ],
    )
    markdown = render_markdown(result, [])
    assert "already waited and retried" in markdown
    assert markdown.count("  _") >= 1  # the sentence sits under its note
    assert "a detail nobody has written a sentence for" in markdown


def test_the_operating_system_speaking_another_language_still_gets_a_sentence():
    """A Windows console in Turkish writes the refusal in Turkish, with a number."""
    note = explain(
        "ConnectError: [WinError 10061] Hedef makine etkin olarak "
        "reddettiginden baglanti kurulamadi"
    )
    assert "nothing is listening" in note.lower()


def test_a_connect_failure_nobody_has_a_number_for_still_says_something():
    note = explain("ConnectError: something the platform worded its own way")
    assert "connection could not be made" in note.lower()
