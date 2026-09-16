"""The one place DirSift talks to anything other than the target.

Everything else in this tool reads the directory in front of it and nothing
else. A verdict lookup breaks that silence on purpose, so the rules are narrow
and written down here rather than implied:

* **A hash goes out, never a file.** VirusTotal is asked about a digest DirSift
  already computed. The sample is not uploaded, and there is no code path here
  that could upload one.
* **Only when asked.** Nothing in this module runs during a scan. It is called
  from the console when someone presses the button for one file.
* **No key, no request.** Without ``DIRSIFT_VT_API_KEY`` the lookup raises
  before a socket is opened, so a missing key cannot turn into a silent call.
* **One file at a time.** The free tier allows a handful of lookups a minute;
  batching them behind the user's back would burn the quota and the quiet.

A "not found" answer is a finding in itself: a sample nobody has ever submitted
is either very new or very targeted.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import httpx

from .models import Verdict

#: The file report endpoint. A digest is appended to it.
VT_URL = "https://www.virustotal.com/api/v3/files/"

#: Engine buckets that count towards the denominator of a score like 6/64.
COUNTED = ("malicious", "suspicious", "undetected", "harmless")

ENV_KEY = "DIRSIFT_VT_API_KEY"


class MissingKey(RuntimeError):
    """No API key was configured, so nothing was sent."""


def api_key_from_env() -> str | None:
    """The key, if the environment carries one. Never read from the run file."""
    key = os.environ.get(ENV_KEY, "").strip()
    return key or None


def lookup_hash(
    sha256: str,
    *,
    api_key: str | None,
    timeout: float = 15.0,
    transport: httpx.BaseTransport | None = None,
) -> Verdict:
    """Ask VirusTotal what it knows about one digest."""
    if not api_key:
        raise MissingKey(
            f"no VirusTotal key. Set {ENV_KEY} in the environment that runs the "
            "console, then restart it."
        )

    with httpx.Client(timeout=timeout, transport=transport) as client:
        response = client.get(
            VT_URL + sha256,
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )

    now = datetime.now(UTC)
    if response.status_code == 404:
        return Verdict(found=False, checked_at=now)
    response.raise_for_status()

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    analysed = attributes.get("last_analysis_date")
    return Verdict(
        found=True,
        malicious=int(stats.get("malicious", 0)),
        total=sum(int(stats.get(bucket, 0)) for bucket in COUNTED),
        analysed=(
            datetime.fromtimestamp(analysed, UTC).strftime("%Y-%m-%d") if analysed else None
        ),
        checked_at=now,
    )
