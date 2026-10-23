"""What a person asked for when exporting: the label, the types, the file, the filters."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace

from ..extract import defang


def defang_value(value: str) -> str:
    """The project's defang, plus IPv6, which has no dot to bracket.

    An IPv6 address is written with its colons bracketed, 2001[:]db8[:][:]7, so
    a reader sees it and no parser takes it for an address.
    """
    try:
        if ipaddress.ip_address(value).version == 6:
            return value.replace(":", "[:]")
    except ValueError:
        pass
    return defang(value)

#: Traffic Light Protocol levels offered for an export. AMBER is the default:
#: a run describes someone else's live infrastructure, and the person who
#: exports it decides whether it may travel further.
TLP_LEVELS = ("CLEAR", "GREEN", "AMBER", "RED")
DEFAULT_TLP = "AMBER"

#: How a block list writes its comments. Products disagree on where a comment
#: may sit, so the person picks the one their product reads.
PROFILES = ("generic", "paloalto", "bare")


class BadOption(ValueError):
    """An option value that is not one of the allowed ones."""


@dataclass(frozen=True)
class Options:
    tlp: str = DEFAULT_TLP
    types: frozenset[str] | None = None  # None means every type
    source: str | None = None  # one file's URL, or None for the whole run
    exclude_private: bool = True
    exclude_protocol: bool = True
    profile: str = "generic"
    pick: tuple[str, ...] = ()  # files for the YARA target
    live: bool = True  # False renders the defanged preview

    def show(self, value: str) -> str:
        """The value as this rendering carries it: live in a file, defanged on screen."""
        return value if self.live else defang_value(value)

    @property
    def tlp_label(self) -> str:
        return "TLP:" + self.tlp

    def preview(self) -> Options:
        return replace(self, live=False)


def parse_tlp(value: str | None) -> str:
    if value is None or value == "":
        return DEFAULT_TLP
    upper = value.strip().upper().removeprefix("TLP:")
    if upper not in TLP_LEVELS:
        raise BadOption("tlp must be one of " + ", ".join(TLP_LEVELS))
    return upper


def parse_types(values: list[str] | None, allowed: tuple[str, ...]) -> frozenset[str] | None:
    if not values:
        return None
    picked = {part.strip().lower() for value in values for part in value.split(",") if part.strip()}
    if not picked:
        return None
    if picked - set(allowed):
        raise BadOption("types must be drawn from " + ", ".join(allowed))
    return frozenset(picked)


def parse_profile(value: str | None) -> str:
    if value is None or value == "":
        return "generic"
    value = value.strip().lower()
    if value not in PROFILES:
        raise BadOption("profile must be one of " + ", ".join(PROFILES))
    return value
