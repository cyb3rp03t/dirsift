"""Compare two saved runs of the same open directory.

Attacker staging hosts are not static. A box revisited a week later has new
builds, has lost the ones that got detected, and sometimes has moved to another
provider altogether. Reading the second run on its own answers "what is here";
the question worth asking is "what changed", and that is this module.

It works from two saved runs and nothing else. No function here reaches the
network: the target is not asked again, no lookup is made, and both runs are
already analysed by the time they arrive.

The trap it is built around is coverage. A file missing from the newer run has
not necessarily been removed: the newer walk may have stopped earlier, gone less
deep, or been refused a folder. A file only counts as removed when the folder it
sat in was actually listed the second time. Otherwise it is reported as not
seen, which is a different claim, and the same rule runs the other way for
files that look added. Hashes get the same caution: a file cut at the peek
ceiling has no digest, so whether its bytes changed is not something this
module will say.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import unquote

from pydantic import BaseModel, Field

from .extract import SecretMask, defang
from .models import Entry, Ioc, Kind, ScanResult
from .report import human_size, network_note

#: Scan options that decide how much of a directory a run could have seen.
COVERAGE_OPTIONS = ("depth", "peek", "peek_bytes", "max_requests", "max_entries")

#: Walk errors that mean the run stopped early rather than that a folder failed.
BUDGET_NOTES = ("request budget exhausted", "entry budget exhausted")

#: A walk note that is a warning about the root, not a failure to list it.
NOT_AN_INDEX = "does not look like a directory index"

# Verdicts for a file both runs saw. Only the first is a claim about bytes.
BYTES_DIFFER = "bytes differ"
LISTING_CHANGED = "listing says changed, bytes not compared"
CANNOT_TELL = "cannot tell"


class FileRef(BaseModel):
    """A file or folder on one side of the comparison."""

    path: str
    kind: str = "dir"
    size: int | None = None
    sha256: str | None = None


class FieldChange(BaseModel):
    """One property of the server that read differently the second time."""

    field: str
    old: str | None = None
    new: str | None = None


class FileChange(BaseModel):
    """A file both runs saw, and what can honestly be said about its contents."""

    path: str
    verdict: str  # BYTES_DIFFER, LISTING_CHANGED or CANNOT_TELL
    old_sha256: str | None = None
    new_sha256: str | None = None
    old_size: int | None = None
    new_size: int | None = None
    old_modified: str | None = None
    new_modified: str | None = None


class KindChange(BaseModel):
    """The same path, read as a different kind of file."""

    path: str
    old_kind: str
    new_kind: str
    old_confidence: str
    new_confidence: str


class FamilyChange(BaseModel):
    """A version family whose members are not the same in both runs."""

    label: str
    status: str  # appeared, vanished, changed
    added: list[str] = Field(default_factory=list)
    pulled: list[str] = Field(default_factory=list)  # gone from a folder that was listed
    not_seen: list[str] = Field(default_factory=list)  # gone, but its folder was not walked
    ungrouped: list[str] = Field(default_factory=list)  # still there, no longer in a family


class IndicatorRow(BaseModel):
    """An indicator as it may be printed: defanged, never live."""

    ioc_type: str
    defanged: str
    label: str | None = None
    asn: int | None = None
    as_name: str | None = None
    country: str | None = None


class EntryPointChange(BaseModel):
    """The file ranked most likely to drive the rest, when that changed."""

    old_path: str | None = None
    old_score: float = 0.0
    new_path: str | None = None
    new_score: float = 0.0


class Unchanged(BaseModel):
    """What stayed the same, as numbers rather than lists."""

    files_same_bytes: int = 0
    files_same_listing: int = 0  # no digest on one side, listing identical
    dirs: int = 0
    families: int = 0
    indicators: int = 0


class RunDiff(BaseModel):
    """Everything that differs between two runs of one directory.

    Roots and addresses are stored defanged and indicators only in their
    defanged form, so this model can be written out and pasted anywhere.
    """

    old_root: str
    new_root: str
    old_started: datetime
    new_started: datetime
    swapped: bool = False
    roots_differ: bool = False
    # Whether each run listed its root at all. A run that did not has nothing
    # to compare, and "nothing changed" would be a claim it cannot make.
    old_listed: bool = True
    new_listed: bool = True

    server: list[FieldChange] = Field(default_factory=list)
    asn_moved: bool = False

    kind_changes: list[KindChange] = Field(default_factory=list)
    changed: list[FileChange] = Field(default_factory=list)
    families: list[FamilyChange] = Field(default_factory=list)

    indicators_added: list[IndicatorRow] = Field(default_factory=list)
    indicators_removed: list[IndicatorRow] = Field(default_factory=list)
    # Only one run read the file it came from, so its absence proves nothing.
    indicators_not_compared: list[IndicatorRow] = Field(default_factory=list)

    entry_point: EntryPointChange | None = None

    added: list[FileRef] = Field(default_factory=list)
    removed: list[FileRef] = Field(default_factory=list)
    not_seen_in_new: list[FileRef] = Field(default_factory=list)
    not_seen_in_old: list[FileRef] = Field(default_factory=list)

    unchanged: Unchanged = Field(default_factory=Unchanged)
    notes: list[str] = Field(default_factory=list)

    @property
    def changed_anything(self) -> bool:
        return any(
            (
                self.server,
                self.kind_changes,
                self.changed,
                self.families,
                self.indicators_added,
                self.indicators_removed,
                self.indicators_not_compared,
                self.entry_point,
                self.added,
                self.removed,
                self.not_seen_in_new,
                self.not_seen_in_old,
            )
        )


# Where things are


def _rel(url: str, root: str) -> str:
    """A URL as a path under the run's root, readable rather than escaped.

    Listings link names percent-encoded, so a Cyrillic filename arrives as a run
    of %D0 escapes. Both runs are decoded the same way, so the keys still match.
    """
    return unquote(url.removeprefix(root))


def _key(entry: Entry, root: str) -> str:
    """The path that identifies an entry across runs, as hashes_cmd prints it."""
    path = _rel(entry.url, root) or entry.name
    return path.rstrip("/") + "/" if entry.is_dir else path


def _parent(path: str) -> str:
    """The folder a path sits in. The root is the empty string."""
    head, _, _ = path.rstrip("/").rpartition("/")
    return head + "/" if head else ""


def _parent_key(entry: Entry, root: str) -> str:
    if entry.parent_url:
        parent = _rel(entry.parent_url, root)
        return parent.rstrip("/") + "/" if parent.strip("/") else ""
    return _parent(_key(entry, root))


class _Side:
    """One run, indexed the way the comparison needs to ask it things."""

    def __init__(self, result: ScanResult) -> None:
        root = result.root_url
        self.result = result
        self.files = {_key(e, root): e for e in result.entries if not e.is_dir}
        self.dirs = {_key(e, root): e for e in result.entries if e.is_dir}
        # A folder was listed when something in it came back. A folder that only
        # appears as a row was named, not walked: depth and budget stop there.
        self.walked = {_parent_key(e, root) for e in result.entries}
        if result.listing_flavor is not None:
            self.walked.add("")
        self.by_url = {e.url: _key(e, root) for e in result.entries}

    def absence_is_real(self, folder: str) -> bool:
        """Whether a path missing under ``folder`` was really missing.

        True when the folder was listed and did not name it, or when the folder
        itself is gone from a parent that was listed. False when the walk never
        read that far.
        """
        while True:
            if folder in self.walked:
                return True
            if folder in self.dirs or folder == "":
                return False
            folder = _parent(folder)

    def read(self, path: str) -> bool:
        """Whether this run read the file's contents, so its indicators count."""
        entry = self.files.get(path)
        return entry is not None and bool(entry.text_preview)

    def compared(self, path: str) -> bool:
        """Whether this run gave the file a fair chance to carry an indicator."""
        if path in self.files:
            return self.read(path)
        return self.absence_is_real(_parent(path))


def _ref(path: str, entry: Entry) -> FileRef:
    if entry.is_dir:
        return FileRef(path=path)
    return FileRef(
        path=path,
        kind=str(entry.kind),
        size=entry.size if entry.size is not None else entry.fetched_bytes,
        sha256=entry.sha256,
    )


# The passes


def _server(old: ScanResult, new: ScanResult) -> list[FieldChange]:
    """The fields that describe the host, compared one by one."""
    fields = (
        ("target_ip", lambda r: defang(r.target_ip) if r.target_ip else None),
        ("target_asn", lambda r: f"AS{r.target_asn}" if r.target_asn else None),
        ("target_as_name", lambda r: r.target_as_name),
        ("target_country", lambda r: r.target_country),
        ("server", lambda r: r.server),
        ("listing_flavor", lambda r: r.listing_flavor),
        ("title", lambda r: r.title),
    )
    changes = []
    for name, read in fields:
        before, after = read(old), read(new)
        if before != after:
            changes.append(FieldChange(field=name, old=before, new=after))
    return changes


def _compare_contents(path: str, old: Entry, new: Entry) -> FileChange | None:
    """What can be said about a file both runs saw. None when it did not change.

    A digest is only taken from a file read whole, so a file cut at the ceiling
    has none. Without a digest on both sides the bytes were not compared, and
    the listing's own size and date are the only evidence left: reported as the
    listing's claim, never as the file's.
    """
    if old.sha256 and new.sha256:
        if old.sha256 == new.sha256:
            return None
        verdict = BYTES_DIFFER
    else:
        pairs = [(old.size, new.size), (old.modified, new.modified)]
        known = [(a, b) for a, b in pairs if a is not None and b is not None]
        if not known:
            verdict = CANNOT_TELL
        elif any(a != b for a, b in known):
            verdict = LISTING_CHANGED
        else:
            return None
    return FileChange(
        path=path,
        verdict=verdict,
        old_sha256=old.sha256,
        new_sha256=new.sha256,
        old_size=old.size,
        new_size=new.size,
        old_modified=old.modified,
        new_modified=new.modified,
    )


def _kind_change(path: str, old: Entry, new: Entry) -> KindChange | None:
    """The same path read as another kind of file. Unknown on either side is no claim."""
    if old.kind == new.kind or Kind.UNKNOWN in (old.kind, new.kind):
        return None
    return KindChange(
        path=path,
        old_kind=str(old.kind),
        new_kind=str(new.kind),
        old_confidence=str(old.confidence),
        new_confidence=str(new.confidence),
    )


def _members(result: ScanResult) -> dict[str, set[str]]:
    return {cluster.label: set(cluster.members) for cluster in result.clusters}


def _families(old: _Side, new: _Side) -> tuple[list[FamilyChange], int]:
    """Builds that joined or left each version family.

    A member that left a family is only called pulled when its folder was
    listed the second time and it was not there. One whose folder was not
    walked is not seen, and one that is still there but no longer grouped (the
    family shrank to one file) is said to be exactly that.
    """
    before, after = _members(old.result), _members(new.result)
    names_now = {entry.name for entry in new.files.values()}
    folders = {}
    for path, entry in old.files.items():
        folders.setdefault(entry.name, []).append(_parent(path))

    changes: list[FamilyChange] = []
    same = 0
    for label in sorted(set(before) | set(after)):
        was, now = before.get(label, set()), after.get(label, set())
        if was == now:
            same += 1
            continue
        change = FamilyChange(
            label=label,
            status="appeared" if not was else "vanished" if not now else "changed",
            added=sorted(now - was),
        )
        for name in sorted(was - now):
            if name in names_now:
                change.ungrouped.append(name)
            elif all(new.absence_is_real(folder) for folder in folders.get(name, [""])):
                change.pulled.append(name)
            else:
                change.not_seen.append(name)
        changes.append(change)
    return changes, same


def _row(ioc: Ioc, mask: SecretMask) -> IndicatorRow:
    return IndicatorRow(
        ioc_type=ioc.ioc_type,
        # A secret is named by its kind, length and digest, never quoted.
        defanged=mask.indicator(ioc),
        label=ioc.label,
        asn=ioc.asn,
        as_name=ioc.as_name,
        country=ioc.country,
    )


def _indicators(old: _Side, new: _Side, diff: RunDiff) -> None:
    """Indicators on one side only, split by whether the other side could have seen them.

    An indicator lives in a file. When the other run read that file, or truly
    lacks it, the indicator's absence there is a finding. When the other run
    never read the file, it is only a gap in coverage.
    """
    before = {ioc.key(): ioc for ioc in old.result.iocs}
    after = {ioc.key(): ioc for ioc in new.result.iocs}
    diff.unchanged.indicators = len(before.keys() & after.keys())
    old_mask, new_mask = SecretMask(old.result.iocs), SecretMask(new.result.iocs)

    def sources(ioc: Ioc, side: _Side) -> list[str]:
        urls = ioc.sources or [ioc.source_url]
        return [side.by_url[url] for url in urls if url in side.by_url]

    for key in sorted(after.keys() - before.keys()):
        ioc = after[key]
        fair = any(old.compared(path) for path in sources(ioc, new))
        (diff.indicators_added if fair else diff.indicators_not_compared).append(
            _row(ioc, new_mask)
        )
    for key in sorted(before.keys() - after.keys()):
        ioc = before[key]
        fair = any(new.compared(path) for path in sources(ioc, old))
        (diff.indicators_removed if fair else diff.indicators_not_compared).append(
            _row(ioc, old_mask)
        )


def _top(side: _Side) -> tuple[str | None, float]:
    """The entry point candidate the run ranked first, in the order glue sorts."""
    scored = [(entry, path) for path, entry in side.files.items() if entry.glue_score > 0]
    if not scored:
        return None, 0.0
    entry, path = min(scored, key=lambda pair: (-pair[0].glue_score, pair[0].name))
    return path, entry.glue_score


def _walk_failures(result: ScanResult) -> int:
    """Listings that failed, as opposed to a run that stopped on its budget."""
    return sum(
        1
        for error in result.errors
        if error.stage == "walk"
        and not any(note in error.detail for note in BUDGET_NOTES)
        and NOT_AN_INDEX not in error.detail
    )


def _notes(old: ScanResult, new: ScanResult, diff: RunDiff) -> list[str]:
    """Why some rows are not seen rather than added or removed."""
    notes: list[str] = []
    if diff.swapped:
        notes.append(
            "The runs were given newest first. They were compared in the order "
            "they were taken."
        )
    for option in COVERAGE_OPTIONS:
        before, after = old.options.get(option), new.options.get(option)
        if before is not None and after is not None and before != after:
            notes.append(
                f"{option} was {before} in the older run and {after} in the newer one."
            )
    for label, result in (("older", old), ("newer", new)):
        for budget in BUDGET_NOTES:
            if any(budget in error.detail for error in result.errors):
                notes.append(f"The {label} run stopped early: {budget}.")
        failures = _walk_failures(result)
        if failures:
            notes.append(
                f"The {label} run could not list {failures} folder"
                f"{'s' if failures != 1 else ''}."
            )
    if diff.not_seen_in_new or diff.not_seen_in_old:
        notes.append(
            "A file is only called removed or added when the folder it sits in was "
            "listed by both runs. The rest are not seen, which says nothing about "
            "whether they are still there."
        )
    return notes


def diff_runs(old: ScanResult, new: ScanResult) -> RunDiff:
    """Compare two analysed runs of one directory. Reads both, changes neither.

    The runs are put in the order they were taken, whatever order they were
    given in, so "added" always means added since the earlier visit.
    """
    swapped = new.started_at < old.started_at
    if swapped:
        old, new = new, old
    before, after = _Side(old), _Side(new)

    diff = RunDiff(
        old_root=defang(old.root_url),
        new_root=defang(new.root_url),
        old_started=old.started_at,
        new_started=new.started_at,
        swapped=swapped,
        roots_differ=old.root_url != new.root_url,
        old_listed="" in before.walked,
        new_listed="" in after.walked,
        server=_server(old, new),
        asn_moved=bool(old.target_asn and new.target_asn and old.target_asn != new.target_asn),
    )

    for path in sorted(before.files.keys() | after.files.keys()):
        was, now = before.files.get(path), after.files.get(path)
        if was is not None and now is not None:
            kind = _kind_change(path, was, now)
            if kind:
                diff.kind_changes.append(kind)
            change = _compare_contents(path, was, now)
            if change:
                diff.changed.append(change)
            elif was.sha256 and now.sha256:
                diff.unchanged.files_same_bytes += 1
            else:
                diff.unchanged.files_same_listing += 1
        elif was is not None:
            real = after.absence_is_real(_parent(path))
            (diff.removed if real else diff.not_seen_in_new).append(_ref(path, was))
        elif now is not None:
            real = before.absence_is_real(_parent(path))
            (diff.added if real else diff.not_seen_in_old).append(_ref(path, now))

    for path in sorted(before.dirs.keys() | after.dirs.keys()):
        was, now = before.dirs.get(path), after.dirs.get(path)
        if was is not None and now is not None:
            diff.unchanged.dirs += 1
        elif was is not None:
            real = after.absence_is_real(_parent(path))
            (diff.removed if real else diff.not_seen_in_new).append(_ref(path, was))
        elif now is not None:
            real = before.absence_is_real(_parent(path))
            (diff.added if real else diff.not_seen_in_old).append(_ref(path, now))

    diff.families, diff.unchanged.families = _families(before, after)
    _indicators(before, after, diff)

    old_top, new_top = _top(before), _top(after)
    if old_top[0] != new_top[0]:
        diff.entry_point = EntryPointChange(
            old_path=old_top[0], old_score=old_top[1], new_path=new_top[0], new_score=new_top[1]
        )

    diff.notes = _notes(old, new, diff)
    return diff



# The page

_FIELD_LABEL = {
    "target_ip": "Address",
    "target_asn": "AS number",
    "target_as_name": "Network",
    "target_country": "Country",
    "server": "Server header",
    "listing_flavor": "Index flavour",
    "title": "Page title",
}


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}{'' if number == 1 else 's'}"


def _read_as(kind: str, confidence: str) -> str:
    """A kind, with how it was decided when it was decided at all."""
    return kind if confidence == "none" else f"{kind} ({confidence})"


def _when(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _network(diff: RunDiff, side: str) -> str:
    fields = {change.field: getattr(change, side) for change in diff.server}
    asn = (fields.get("target_asn") or "").removeprefix("AS")
    return network_note(
        int(asn) if asn.isdigit() else None,
        fields.get("target_as_name") or "",
        fields.get("target_country") or "",
    )


def _indicator_line(row: IndicatorRow) -> str:
    label = f"  [{row.label}]" if row.label else ""
    network = network_note(row.asn, row.as_name or "", row.country or "")
    return f"{row.ioc_type:<8} {row.defanged}{label}{f'  {network}' if network else ''}"


def _file_line(ref: FileRef) -> str:
    if ref.kind == "dir":
        return f"- `{ref.path}` (folder)"
    return f"- `{ref.path}` ({ref.kind}, {human_size(ref.size)})"


def _digest(sha256: str | None) -> str:
    return f"`{sha256[:16]}`" if sha256 else "no hash"


def _listing(size: int | None, modified: str | None) -> str:
    return f"{human_size(size)}, {modified or 'no date'}"


def render_diff_markdown(diff: RunDiff) -> str:
    """The comparison as a page, in the order an analyst wants it.

    What the host is first, because a provider move changes how every other row
    reads. Then the rows that are findings (a file that changed kind, bytes that
    changed, builds pulled from a family, new indicators), then the inventory
    deltas, then the rows that are only gaps in coverage, and the notes that
    explain those gaps last. Empty sections are left out rather than printed
    with "none" under them.
    """
    lines: list[str] = []
    add = lines.append

    add(f"# Run comparison: {diff.new_root}")
    add("")
    warnings: list[str] = []
    if diff.roots_differ:
        warnings.append(
            f"**Different roots.** The older run walked `{diff.old_root}` and the newer "
            f"one `{diff.new_root}`. Paths are compared relative to each root, so a "
            "row below may be the same file seen from another folder."
        )
    if not diff.changed_anything:
        for warning in warnings:
            add(f"> {warning}")
            add("")
        kept = diff.unchanged
        unlisted = [
            side
            for side, listed in (("older", diff.old_listed), ("newer", diff.new_listed))
            if not listed
        ]
        if unlisted:
            which = (
                "neither run could" if len(unlisted) == 2 else f"the {unlisted[0]} run could not"
            )
            add(
                f"Nothing to compare: {which} list the root, so no row here says anything "
                "about what is on the host. The notes say why."
            )
            for note in diff.notes:
                add("")
                add(f"_{note}_")
            return "\n".join(lines).rstrip() + "\n"
        add(
            f"Nothing changed between the run of {_when(diff.old_started)} and the run "
            f"of {_when(diff.new_started)}: "
            f"{_count(kept.files_same_bytes + kept.files_same_listing, 'file')}, "
            f"{_count(kept.dirs, 'folder')} and {_count(kept.indicators, 'indicator')} "
            "read the same."
        )
        for note in diff.notes:
            add("")
            add(f"_{note}_")
        return "\n".join(lines).rstrip() + "\n"

    add(f"- **Older run**: {_when(diff.old_started)}")
    add(f"- **Newer run**: {_when(diff.new_started)}")
    add("")
    for warning in warnings:
        add(f"> {warning}")
        add("")

    # Server
    if diff.server:
        add("## Server")
        add("")
        if diff.asn_moved:
            add(
                f"**The host moved network**: {_network(diff, 'old')} on the first visit, "
                f"{_network(diff, 'new')} now. Whoever runs it changed provider, and "
                "the provider is the part that usually repeats between campaigns."
            )
            add("")
        add("| Field | Older | Newer |")
        add("|---|---|---|")
        for change in diff.server:
            label = _FIELD_LABEL.get(change.field, change.field)
            add(f"| {label} | {change.old or '-'} | {change.new or '-'} |")
        add("")

    # Kind changes
    if diff.kind_changes:
        add("## Changed type")
        add("")
        add("The same path, read as another kind of file. Usually the row worth reading first.")
        add("")
        for kind in diff.kind_changes:
            add(
                f"- **`{kind.path}`**: {_read_as(kind.old_kind, kind.old_confidence)} on the "
                f"first visit, {_read_as(kind.new_kind, kind.new_confidence)} now"
            )
        add("")

    # Changed files
    if diff.changed:
        add("## Changed files")
        add("")
        add(
            f"Only _{BYTES_DIFFER}_ compares contents. A file cut at the peek ceiling has "
            "no hash, so for those rows the listing's own size and date are all there is."
        )
        add("")
        add("| Path | What changed | Older | Newer |")
        add("|---|---|---|---|")
        for change in diff.changed:
            if change.verdict == BYTES_DIFFER:
                before, after = _digest(change.old_sha256), _digest(change.new_sha256)
            else:
                before = _listing(change.old_size, change.old_modified)
                after = _listing(change.new_size, change.new_modified)
            add(f"| `{change.path}` | {change.verdict} | {before} | {after} |")
        add("")

    # Families
    if diff.families:
        add("## Version families")
        add("")
        for family in diff.families:
            add(f"- `{family.label}` ({family.status})")
            if family.added:
                add(f"  - new builds: {', '.join(f'`{m}`' for m in family.added)}")
            if family.pulled:
                add(
                    f"  - pulled: {', '.join(f'`{m}`' for m in family.pulled)}. Gone from a "
                    "folder that was listed again, so the build was taken down."
                )
            if family.not_seen:
                add(
                    f"  - not seen: {', '.join(f'`{m}`' for m in family.not_seen)}. Its folder "
                    "was not walked the second time."
                )
            if family.ungrouped:
                add(
                    f"  - still there, no longer in this family: "
                    f"{', '.join(f'`{m}`' for m in family.ungrouped)}"
                )
        add("")

    # Indicators
    if diff.indicators_added or diff.indicators_removed or diff.indicators_not_compared:
        add("## Indicators")
        add("")
        add("Defanged. Read from file contents only, in both runs; nothing was looked up.")
        add("")
        for title, rows, hint in (
            ("New", diff.indicators_added, ""),
            ("Gone", diff.indicators_removed, ""),
            (
                "Not compared",
                diff.indicators_not_compared,
                "Only one run read the file these came from, so they are neither new nor gone.",
            ),
        ):
            if not rows:
                continue
            add(f"**{title}** ({len(rows)})")
            add("")
            if hint:
                add(hint)
                add("")
            add("```")
            for row in rows:
                add(_indicator_line(row))
            add("```")
            add("")

    # Entry point
    if diff.entry_point:
        point = diff.entry_point
        before = f"`{point.old_path}` ({point.old_score}/100)" if point.old_path else "nothing"
        after = f"`{point.new_path}` ({point.new_score}/100)" if point.new_path else "nothing"
        add("## Entry point")
        add("")
        add(f"The file ranked first as the driver changed: {before} then, {after} now.")
        add("")

    # Inventory
    for title, refs in (
        ("Added", diff.added),
        ("Removed", diff.removed),
        ("Not seen in the newer run (its folder was not walked)", diff.not_seen_in_new),
        ("Not seen in the older run (its folder was not walked)", diff.not_seen_in_old),
    ):
        if not refs:
            continue
        add(f"## {title}")
        add("")
        for ref in refs:
            add(_file_line(ref))
        add("")

    # What stayed
    kept = diff.unchanged
    add("## Unchanged")
    add("")
    add(
        f"{_count(kept.files_same_bytes, 'file')} with the same bytes, "
        f"{kept.files_same_listing} more whose listing reads the same but whose bytes were "
        f"not compared, {_count(kept.dirs, 'folder')}, "
        f"{kept.families} version {'family' if kept.families == 1 else 'families'} and "
        f"{_count(kept.indicators, 'indicator')}."
    )
    add("")

    # Notes
    if diff.notes:
        add("## Notes")
        add("")
        for note in diff.notes:
            add(f"- {note}")
        add("")

    return "\n".join(lines).rstrip() + "\n"
