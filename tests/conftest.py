"""Keep every test away from the machine it runs on.

The address table is discovered from the environment, the working directory and
the home folder. A developer who downloaded it gets different answers from CI,
so every test starts with a path that does not exist, and the tests that want a
table hand one over themselves.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def no_address_table_from_this_machine(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("DIRSIFT_ASN_DB", str(tmp_path / "no-table-here.tsv.gz"))
