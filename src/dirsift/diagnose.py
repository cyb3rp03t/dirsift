"""Turn a scan note into a sentence someone can act on.

A run's notes are the honest part of the page: they say where the walk stopped
and what the answer was. The answer is usually a number, and a number is not a
diagnosis. `HTTP 503` says the server refused; it does not say whether the
directory is gone, the host is overloaded, or something between you and it
decided the conversation was over.

These are the sentences that go beside those notes. Two rules hold them
together. They say what the status means and what is worth doing about it, and
they stop where knowledge stops: a note nobody has written a sentence for gets
no sentence, because inventing a cause is worse than printing the code alone.
"""

from __future__ import annotations

import re

#: A status like "HTTP 503" or "HTTP 499 Request has been forbidden by antivirus".
STATUS = re.compile(r"HTTP (\d{3})(?:\s+(.*))?$")

#: What each status means here, written for the person reading the run.
BY_STATUS = {
    400: "The server rejected the request as malformed. Usually a URL with "
    "characters the listing escaped one way and the server reads another.",
    401: "The server asked for credentials. DirSift carries none and never "
    "will, so this branch was dropped on purpose.",
    403: "Forbidden. The file is listed but the server will not serve it, "
    "which happens with directories that list more than they allow.",
    404: "Not there. The listing named a file the server will not give, so "
    "either it is gone or the index is stale.",
    405: "The method was refused. DirSift only sends GET and HEAD, so this is "
    "a server that dislikes one of them on this path.",
    408: "The server gave up waiting for the request. Raise --timeout and try "
    "the run again.",
    429: "Too many requests. DirSift retried twice, honouring Retry-After. "
    "Raise --delay well above one second before going back.",
    451: "Refused for legal reasons. Someone between you and the host is "
    "blocking it, or the host is complying with an order.",
    500: "The target broke while answering. That is the server's fault, not "
    "the scan's, and it often means a script rather than a static index.",
    502: "A gateway in front of the target got nothing usable from it. The "
    "thing that serves the files may be down while the front end is up.",
    503: "The service refused to serve. DirSift already waited and retried "
    "twice. Common causes: the site is gone from the host, the index is only "
    "served under a hostname rather than the bare address, or the box is "
    "overloaded.",
    504: "A gateway timed out waiting for the target. Slow or dying host; a "
    "larger --timeout rarely helps when the front end has already given up.",
}

#: Codes that mean different things depending on who produced them.
AMBIGUOUS = {
    499: "499 is not a standard status. nginx uses it for a client that "
    "disconnected before the answer was ready. Local antivirus software also "
    "answers with it when it blocks a site, in which case the request never "
    "reached the target at all.",
}

#: Phrases a middlebox puts in the reason line when it answers instead of the target.
INTERCEPTIONS = (
    ("forbidden by antivirus", "Your antivirus answered this request itself: "
     "it blocked the host and returned its own page, so nothing ever reached "
     "the target. Scan from a machine or network without that filter, or "
     "through a proxy, rather than turning the filter off."),
    ("blocked by", "Something between you and the target answered instead of "
     "the target. The request did not reach the host."),
)

#: Transport failures, matched on the exception name the walker recorded.
#
# The operating system's own wording is matched by number wherever there is
# one. A Windows console in Turkish says "Hedef makine etkin olarak reddetti",
# and a sentence that only recognises "Connection refused" would have nothing
# to say to the person most likely to need it.
NAME_NOT_FOUND = ("The hostname does not resolve. Check the spelling, or scan "
                  "the address directly if you have it.")
REFUSED = ("Nothing is listening on that port. The service is down, or the "
           "directory is served on another port.")
UNREACHABLE = ("The connection could not be made. The host is down, "
               "unreachable from here, or something is filtering the route.")

BY_TRANSPORT = (
    ("Name or service not known", NAME_NOT_FOUND),
    ("nodename nor servname", NAME_NOT_FOUND),
    ("Errno -2", NAME_NOT_FOUND),
    ("Errno -3", NAME_NOT_FOUND),
    ("Errno -5", NAME_NOT_FOUND),
    ("11001", NAME_NOT_FOUND),  # WSAHOST_NOT_FOUND
    ("Connection refused", REFUSED),
    ("Errno 111", REFUSED),
    ("10061", REFUSED),  # WSAECONNREFUSED
    ("10060", "Nothing answered inside the timeout. The host may be gone, or "
     "dropping packets from you rather than refusing them."),
    ("Errno 110", "Nothing answered inside the timeout. The host may be gone, "
     "or dropping packets from you rather than refusing them."),
    ("10065", UNREACHABLE),  # WSAEHOSTUNREACH
    ("Errno 113", UNREACHABLE),
    ("ConnectTimeout", "The connection never opened: no answer at all within "
     "--timeout. The host may be gone, or filtering you."),
    ("ReadTimeout", "The connection opened but the body never finished "
     "arriving. Raise --timeout, and --delay if the host is struggling."),
    ("WriteTimeout", "The request could not be sent inside --timeout."),
    ("PoolTimeout", "DirSift could not get a connection from its own pool in "
     "time. Retry the run."),
    ("SSLError", "TLS failed. Open directories often run expired or "
     "self signed certificates; --no-verify-tls is already the default, so "
     "this is something stranger."),
    ("ProxyError", "The proxy refused or failed. Check that it is running and "
     "that the address in --proxy is right."),
    ("redirect loop", "The server kept redirecting in a circle. Nothing to "
     "follow, so the walk stopped there."),
    ("too many redirects", "The chain of redirects was longer than DirSift "
     "will follow, which usually means a redirect loop."),
    ("out of scope", "The link pointed outside the root you gave. DirSift "
     "stays under the root, so it was not followed."),
    ("unsupported scheme", "The link was not http or https."),
    ("private or loopback", "The target is a private or loopback address. "
     "Pass --allow-private if that is deliberate."),
    ("AuthWall", "The server asked for credentials. DirSift carries none, so "
     "the branch ends here."),
    # Last, so a recognised reason above wins: any other failure to connect.
    ("ConnectError", UNREACHABLE),
)


def explain(detail: str) -> str:
    """One sentence about a scan note, or nothing when there is nothing to say."""
    if not detail:
        return ""
    text = detail.strip()

    match = STATUS.search(text)
    if match:
        status = int(match.group(1))
        reason = (match.group(2) or "").lower()
        for phrase, sentence in INTERCEPTIONS:
            if phrase in reason:
                return sentence
        if status in AMBIGUOUS:
            return AMBIGUOUS[status]
        if status in BY_STATUS:
            return BY_STATUS[status]
        if 500 <= status < 600:
            return "The target failed while answering. That is the server's "\
                "fault rather than the scan's."
        if 400 <= status < 500:
            return "The server refused this request and gave no reason "\
                "DirSift knows how to read."
        return ""

    lowered = text.lower()
    for phrase, sentence in BY_TRANSPORT:
        if phrase.lower() in lowered:
            return sentence

    if lowered.startswith("401 ") or " 401 " in lowered:
        return BY_STATUS[401]
    return ""
