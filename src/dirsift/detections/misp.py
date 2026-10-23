"""A MISP event in the MISP core format, for the MISP event import.

From the MISP core format (https://www.misp-standard.org/rfc/misp-standard-core.html):

- the document is ``{"Event": {...}}`` with ``uuid``, ``info``, ``date``,
  ``timestamp``, ``publish_timestamp``, ``published``, ``threat_level_id``,
  ``analysis``, ``distribution`` and ``sharing_group_id``; numbers are written
  as JSON strings.
- ``distribution`` ``0`` is "Your Organisation Only"; an attribute's ``5`` is
  "Inherit Event". The event is not published: whoever imports it decides.
- attributes are category, type and value triplets from the format's list:
  ``ip-dst``, ``domain`` and ``url`` under "Network activity", ``sha256``,
  ``md5`` and ``email-src`` under "Payload delivery".
- ``to_ids`` marks an attribute as meant for detection. Addresses, names,
  URLs and hashes are; a mail address is not, because one found in a kit is
  usually where stolen data goes, not a sender to match on.
- the TLP marking is a tag from the MISP tlp taxonomy (``tlp:clear``,
  ``tlp:green``, ``tlp:amber``, ``tlp:red``), with the taxonomy's colour.

``org_id``, ``orgc_id`` and ``event_id`` are numbers an instance gives its own
records, so they are left for the importing instance to set. Every uuid is
derived from the run, so a second import of the same run updates the event
instead of adding a copy. The timestamps are the scan's start.
"""

from __future__ import annotations

import json

from .collect import collect
from .meta import NOT_A_VERDICT, Run, stable_uuid, started
from .options import Options

KINDS = ("ipv4", "ipv6", "domain", "url", "email", "sha256", "md5")

ASSUMES = [
    "MISP event import (MISP core format JSON), distribution: your organisation only",
]

#: indicator type: (MISP type, MISP category, to_ids)
TYPES = {
    "ipv4": ("ip-dst", "Network activity", True),
    "ipv6": ("ip-dst", "Network activity", True),
    "domain": ("domain", "Network activity", True),
    "url": ("url", "Network activity", True),
    "email": ("email-src", "Payload delivery", False),
    "sha256": ("sha256", "Payload delivery", True),
    "md5": ("md5", "Payload delivery", True),
}

#: The MISP tlp taxonomy's colours.
TLP_COLOURS = {"CLEAR": "#ffffff", "GREEN": "#33FF00", "AMBER": "#FFC000", "RED": "#FF2B2B"}


def _comment(item, run: Run) -> str:
    parts = []
    if item.label == "target":
        parts.append("the directory's own host")
    if item.sources:
        parts.append("found in " + ", ".join(item.sources))
    if item.partial:
        parts.append("partial read")
    parts.append(f"dirsift run {run.name}")
    return "; ".join(parts)


def build_event(run: Run, options: Options) -> dict:
    collected = collect(run.result, options)
    when = started(run)
    stamp = str(int(when.timestamp()))
    attributes = []
    for item in collected.indicators:
        kind, category, to_ids = TYPES[item.kind]
        attributes.append(
            {
                "uuid": stable_uuid(run, options, "misp-attribute", item.kind, item.value),
                "type": kind,
                "category": category,
                "value": options.show(item.value),
                "to_ids": to_ids,
                "comment": _comment(item, run),
                "distribution": "5",
                "sharing_group_id": "0",
                "timestamp": stamp,
                "deleted": False,
                "disable_correlation": False,
            }
        )
    return {
        "Event": {
            "uuid": stable_uuid(run, options, "misp-event"),
            "info": f"dirsift run {run.name}: indicators from an open directory. {NOT_A_VERDICT}",
            "date": when.strftime("%Y-%m-%d"),
            "timestamp": stamp,
            "publish_timestamp": "0",
            "published": False,
            "threat_level_id": "4",
            "analysis": "0",
            "distribution": "0",
            "sharing_group_id": "0",
            "Tag": [
                {
                    "name": "tlp:" + options.tlp.lower(),
                    "colour": TLP_COLOURS[options.tlp],
                    "exportable": True,
                }
            ],
            "Attribute": attributes,
        }
    }


def render(run: Run, options: Options) -> str:
    return json.dumps(build_event(run, options), indent=2, ensure_ascii=True) + "\n"
