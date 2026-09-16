"""Which network an address belongs to, answered from a table on disk.

An address found inside someone's staging directory is worth placing: the
hosting provider behind it is the part that repeats across campaigns, far more
often than the address does. Doing that with a lookup service would mean
telling a third party what you are looking at, one address at a time, which is
exactly the leak this tool is built to avoid.

So it is done from a file. The expected shape is the one iptoasn.com publishes,
a tab separated table of ranges:

    1.0.0.0<TAB>1.0.0.255<TAB>13335<TAB>US<TAB>CLOUDFLARENET

Ranges are loaded once, sorted, and searched by bisection. Gzip is read in
place. A missing file is not an error: most runs will not have the dataset, and
a scan that cannot say the ASN is still a scan.

The table carries where it came from and when. ASN ownership changes, so an
answer without a date is a guess dressed as a fact.
"""

from __future__ import annotations

import gzip
import ipaddress
import os
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

#: Where the table is looked for when nobody says. First hit wins.
ENV_PATH = "DIRSIFT_ASN_DB"
CANDIDATE_NAMES = (
    "ip2asn-combined.tsv.gz",
    "ip2asn-combined.tsv",
    "ip2asn-v4.tsv.gz",
    "ip2asn-v4.tsv",
)


@dataclass(frozen=True)
class AsnRecord:
    """One announcement: the network, who announces it, and from where."""

    asn: int
    name: str
    country: str


@dataclass
class AsnTable:
    """Ranges from one dataset file, searchable by address."""

    source: str = ""
    stamp: str = ""
    _starts: list[int] = field(default_factory=list)
    _ends: list[int] = field(default_factory=list)
    _records: list[AsnRecord] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self._records

    @classmethod
    def load(cls, path: Path | str | None = None) -> AsnTable:
        """Read a table, or come back empty when there is nothing to read."""
        found = Path(path) if path else cls.discover()
        if found is None or not found.exists():
            return cls()

        starts: list[int] = []
        ends: list[int] = []
        records: list[AsnRecord] = []
        opener = gzip.open if found.suffix == ".gz" else open
        with opener(found, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                row = line.rstrip("\n").split("\t")
                if len(row) < 5:
                    continue
                try:
                    asn = int(row[2])
                    first = int(ipaddress.ip_address(row[0]))
                    last = int(ipaddress.ip_address(row[1]))
                except ValueError:
                    continue
                if asn == 0:  # iptoasn writes unrouted space this way
                    continue
                starts.append(first)
                ends.append(last)
                records.append(AsnRecord(asn=asn, name=row[4].strip(), country=row[3].strip()))

        order = sorted(range(len(starts)), key=starts.__getitem__)
        modified = datetime.fromtimestamp(found.stat().st_mtime, UTC)
        return cls(
            source=found.name,
            stamp=modified.strftime("%Y-%m-%d"),
            _starts=[starts[i] for i in order],
            _ends=[ends[i] for i in order],
            _records=[records[i] for i in order],
        )

    @staticmethod
    def discover() -> Path | None:
        """The dataset the machine already has, if it has one."""
        from_env = os.environ.get(ENV_PATH, "").strip()
        if from_env:
            return Path(from_env)
        for directory in (Path.cwd(), Path.home() / ".dirsift"):
            for name in CANDIDATE_NAMES:
                candidate = directory / name
                if candidate.exists():
                    return candidate
        return None

    def lookup(self, address: str) -> AsnRecord | None:
        """The announcement covering this address, or nothing."""
        if self.empty:
            return None
        try:
            number = int(ipaddress.ip_address(address.strip()))
        except ValueError:
            return None
        index = bisect_right(self._starts, number) - 1
        if index < 0 or number > self._ends[index]:
            return None
        return self._records[index]


@lru_cache(maxsize=4)
def _cached(path: str, mtime: float) -> AsnTable:
    return AsnTable.load(Path(path))


def default_table() -> AsnTable:
    """The table this machine has, loaded once and reused.

    A run page re-analyses on every view, and the dataset is hundreds of
    thousands of ranges. The cache is keyed on the file's modification time, so
    replacing the dataset is picked up without a restart.
    """
    found = AsnTable.discover()
    if found is None or not found.exists():
        return AsnTable()
    return _cached(str(found), found.stat().st_mtime)
