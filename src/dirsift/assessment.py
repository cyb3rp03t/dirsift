"""The analyst's assessment of a run, kept beside it in a sidecar file.

The run file is evidence and the assessment is opinion, so they never share a
file. A run at ``runs/<name>.json`` has its assessment at
``runs/assessments/<name>.json``; the run list globs one folder deep only, so
the sidecar never shows up as a run.

Saving is careful in three ways. Values come only from the defined lists and
within the stated lengths. A form carries the revision it was opened at, and a
save against an older revision is refused instead of overwriting someone
else's change. The file is written whole to a temporary name and moved into
place, so a crash never leaves half a file. Saving the same values again does
not bump the version.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from . import report_text as T
from .report_model import normalise_tlp, tlp_rank, version_of

SCHEMA = 1
ASSESSMENTS = tuple(T.ASSESSMENT_DEFINITIONS)
CONFIDENCES = tuple(T.CONFIDENCE_DEFINITIONS)
PRIORITIES = tuple(T.PRIORITY_DEFINITIONS)
STATUSES = tuple(T.STATUS_DEFINITIONS)
ALT_STATUSES = (T.NOT_RULED_OUT, T.RULED_OUT)

#: Text fields and their limits, in characters.
LIMITS = {
    "author": 120,
    "bottom_line": 1000,
    "rationale": 4000,
    "attribution": 500,
    "found_via": 300,
    "reason": 500,
}
LABELS = {
    "author": "Author",
    "tlp": "TLP",
    "assessment": "Assessment",
    "confidence": "Confidence",
    "priority": "Priority for follow-up",
    "status": "Status",
    "bottom_line": "Bottom line",
    "rationale": "Rationale",
    "attribution": "Attribution",
    "found_via": "Found via",
    "reason": "Reason",
}
#: The fields the form edits, in form order.
FORM_FIELDS = ("author", "tlp", "assessment", "confidence", "priority", "status",
               "bottom_line", "rationale", "attribution", "found_via")
TEXT_FIELDS = ("author", "bottom_line", "rationale", "attribution", "found_via")
CHOICES = {
    "assessment": ("",) + ASSESSMENTS,
    "confidence": ("",) + CONFIDENCES,
    "priority": ("",) + PRIORITIES,
    "status": STATUSES,
    "tlp": T.TLP_ORDER,
}

CONFLICT = "This assessment changed since you opened it; reload to see the saved version."
FINAL_NEEDS = "Final needs {n} more field(s): {fields}."
RULED_OUT_NEEDS = "Ruled out needs a reason: {explanation}."
TOO_LONG = "{label} is longer than {n} characters."
CONTROL_CHAR = "{label} contains a control character."
NOT_A_CHOICE = "{label} must be one of: {values}."
UNREADABLE = "The saved assessment could not be read ({detail}). Saving will replace it."
CONSISTENCY = (
    'Benign or research is selected while "Red team or penetration test infrastructure" is '
    "still Not ruled out."
)
CROSS_ORIGIN = "Cross-origin request refused."

#: C0 controls but tab and line breaks, DEL, the C1 block, and the bidi
#: embeddings, overrides and isolates (U+202A to U+202E, U+2066 to U+2069):
#: the last can reverse how a shared report reads. Plain right-to-left text and
#: the directional marks are left alone.
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f‪-‮⁦-⁩]")


class AssessmentError(ValueError):
    """A sidecar that is not a valid assessment. The message names the field."""


def sidecar_path(run_file: Path) -> Path:
    return run_file.parent / "assessments" / run_file.name


def _text_problem(key: str, value: str, limit_key: str | None = None) -> str | None:
    label = LABELS[limit_key or key]
    limit = LIMITS[limit_key or key]
    if len(value) > limit:
        return TOO_LONG.format(label=label, n=limit)
    if _CONTROL.search(value):
        return CONTROL_CHAR.format(label=label)
    return None


def validate(data: object) -> dict:
    """A sidecar as read from disk, checked field by field.

    Raises AssessmentError naming the first field that is wrong. Unknown keys
    are kept as they are.
    """
    if not isinstance(data, dict):
        raise AssessmentError("the file is not a JSON object")
    out = dict(data)
    schema = out.get("schema", SCHEMA)
    if schema != SCHEMA:
        raise AssessmentError(f"schema: expected {SCHEMA}, found {schema!r}")
    revision = out.get("revision", 0)
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise AssessmentError("revision: must be a whole number, 0 or more")
    if "tlp" in out and out["tlp"] not in (None, ""):
        label = normalise_tlp(str(out["tlp"]))
        if label is None:
            raise AssessmentError("tlp: " + T.TLP_UNKNOWN)
        out["tlp"] = label
    for key in ("assessment", "confidence", "priority", "status"):
        value = out.get(key)
        if value in (None, ""):
            continue
        if not isinstance(value, str) or value not in CHOICES[key]:
            raise AssessmentError(f"{key}: " + NOT_A_CHOICE.format(
                label=LABELS[key], values=", ".join(v for v in CHOICES[key] if v)))
    for key in TEXT_FIELDS:
        value = out.get(key)
        if value in (None, ""):
            continue
        if not isinstance(value, str):
            raise AssessmentError(f"{key}: must be text")
        problem = _text_problem(key, value)
        if problem:
            raise AssessmentError(f"{key}: {problem}")
    alts = out.get("alternatives", [])
    if not isinstance(alts, list):
        raise AssessmentError("alternatives: must be a list")
    for n, alt in enumerate(alts):
        where = f"alternatives[{n}]"
        if not isinstance(alt, dict):
            raise AssessmentError(f"{where}: must be an object")
        if alt.get("explanation") not in T.ALTERNATIVES:
            raise AssessmentError(f"{where}.explanation: not one of the five alternatives")
        if alt.get("status", T.NOT_RULED_OUT) not in ALT_STATUSES:
            raise AssessmentError(f"{where}.status: " + NOT_A_CHOICE.format(
                label="Status", values=", ".join(ALT_STATUSES)))
        reason = alt.get("reason") or ""
        if not isinstance(reason, str):
            raise AssessmentError(f"{where}.reason: must be text")
        problem = _text_problem("reason", reason)
        if problem:
            raise AssessmentError(f"{where}.reason: {problem}")
        if alt.get("status") == T.RULED_OUT and not reason.strip():
            raise AssessmentError(f"{where}.reason: " + RULED_OUT_NEEDS.format(
                explanation=alt["explanation"]))
    attack = out.get("attack", [])
    if not isinstance(attack, list):
        raise AssessmentError("attack: must be a list")
    for n, item in enumerate(attack):
        if not isinstance(item, dict) or not all(
                isinstance(item.get(k, ""), str) for k in ("tactic", "technique", "id",
                                                           "evidence")):
            raise AssessmentError(f"attack[{n}]: needs tactic, technique, id and evidence as text")
    for key in ("limits_added", "references"):
        items = out.get(key, [])
        if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
            raise AssessmentError(f"{key}: must be a list of text")
    if "attack_version" in out and not isinstance(out["attack_version"], str | None):
        raise AssessmentError("attack_version: must be text")
    history = out.get("history", [])
    if not isinstance(history, list) or not all(isinstance(h, dict) for h in history):
        raise AssessmentError("history: must be a list of objects")
    if out.get("status") == "Final":
        missing = final_missing(out)
        if missing:
            raise AssessmentError("status: " + FINAL_NEEDS.format(
                n=len(missing), fields=", ".join(LABELS[m] for m in missing)))
    return out


def final_missing(data: dict) -> list[str]:
    """Form names of the fields a Final assessment still needs, in form order."""
    missing = []
    if not (data.get("author") or "").strip():
        missing.append("author")
    if not data.get("assessment"):
        missing.append("assessment")
    if not (data.get("bottom_line") or "").strip():
        missing.append("bottom_line")
    if data.get("assessment") != "Undetermined" and not data.get("confidence"):
        missing.append("confidence")
    return missing


def load(path: Path) -> dict:
    """The sidecar at ``path``, validated; an empty dict when there is none.

    Raises AssessmentError when the file is there but is not a valid assessment.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise AssessmentError(f"cannot read the file: {exc.strerror}") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AssessmentError(f"not JSON: line {exc.lineno}") from None
    return validate(data)


def save(path: Path, data: dict) -> None:
    """Write the sidecar whole, then move it into place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _alternatives_from(data: dict) -> list[dict]:
    saved = {a.get("explanation"): a for a in data.get("alternatives") or []
             if isinstance(a, dict)}
    out = []
    for index, explanation in enumerate(T.ALTERNATIVES):
        hit = saved.get(explanation) or {}
        out.append({
            "index": index,
            "field": f"alt-{index}",
            "explanation": explanation,
            "status": hit.get("status") or T.NOT_RULED_OUT,
            "reason": hit.get("reason") or "",
        })
    return out


def values_from(data: dict) -> dict[str, str]:
    values = {key: str(data.get(key) or "") for key in FORM_FIELDS}
    if not values["status"]:
        values["status"] = "Preliminary"
    return values


class SaveResult:
    """What a form save produced: the data to keep, and why it was refused if it was."""

    def __init__(self) -> None:
        self.data: dict = {}
        self.changed = False
        self.errors: list[str] = []
        self.missing: list[str] = []
        self.invalid: list[str] = []
        self.conflict: str | None = None
        self.values: dict[str, str] = {}
        self.alternatives: list[dict] = []

    @property
    def ok(self) -> bool:
        return not self.errors and self.conflict is None


def apply_form(current: dict, form: dict[str, str], run_sha256: str,
               now: datetime | None = None) -> SaveResult:
    """Turn a submitted form into the next sidecar, or say why not.

    ``current`` is what is on disk (an empty dict for none). The submitted
    ``revision`` must match it; on a mismatch nothing changes and ``conflict``
    carries the sentence the form shows.
    """
    res = SaveResult()
    try:
        revision = int(form.get("revision", "0") or 0)
    except ValueError:
        revision = -1
    saved_revision = int(current.get("revision", 0) or 0)
    if revision != saved_revision:
        res.conflict = CONFLICT
        res.values = values_from(current)
        res.alternatives = _alternatives_from(current)
        res.data = current
        return res

    values = {key: (form.get(key) or "") for key in FORM_FIELDS}
    for key in TEXT_FIELDS:
        values[key] = values[key].replace("\r\n", "\n").strip()
    values["tlp"] = normalise_tlp(values["tlp"]) or values["tlp"]
    values["status"] = values["status"] or "Preliminary"
    for key, choices in CHOICES.items():
        if values[key] not in choices:
            res.errors.append(NOT_A_CHOICE.format(
                label=LABELS[key], values=", ".join(v for v in choices if v)))
            res.invalid.append(key)
    for key in TEXT_FIELDS:
        problem = _text_problem(key, values[key])
        if problem:
            res.errors.append(problem)
            res.invalid.append(key)

    alternatives = []
    shown = []
    for index, explanation in enumerate(T.ALTERNATIVES):
        status = form.get(f"alt-{index}-status") or T.NOT_RULED_OUT
        reason = (form.get(f"alt-{index}-reason") or "").replace("\r\n", "\n").strip()
        shown.append({"index": index, "field": f"alt-{index}", "explanation": explanation,
                      "status": status, "reason": reason})
        if status not in ALT_STATUSES:
            res.errors.append(NOT_A_CHOICE.format(label="Status", values=", ".join(ALT_STATUSES)))
            res.invalid.append(f"alt-{index}-status")
            continue
        problem = _text_problem("reason", reason)
        if problem:
            res.errors.append(problem)
            res.invalid.append(f"alt-{index}-reason")
        if status == T.RULED_OUT:
            if not reason:
                res.errors.append(RULED_OUT_NEEDS.format(explanation=explanation))
                res.invalid.append(f"alt-{index}-reason")
            alternatives.append({"explanation": explanation, "status": status, "reason": reason})
    res.values = values
    res.alternatives = shown

    if values["status"] == "Final":
        missing = final_missing(values)
        if missing:
            res.missing = missing
            res.errors.append(FINAL_NEEDS.format(
                n=len(missing), fields=", ".join(LABELS[m] for m in missing)))
    if res.errors:
        res.data = current
        return res

    nxt = dict(current)
    nxt["schema"] = SCHEMA
    for key in FORM_FIELDS:
        nxt[key] = values[key]
    nxt["alternatives"] = alternatives
    changed = [key for key in FORM_FIELDS if (current.get(key) or "") != (values[key] or "")]
    if key_default(current, "status") == values["status"] and "status" in changed:
        changed.remove("status")
    if (current.get("alternatives") or []) != alternatives:
        changed.append("alternatives")
    if not changed:
        res.data = current
        return res
    stamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    nxt["revision"] = saved_revision + 1
    nxt["run_sha256"] = run_sha256
    history = list(current.get("history") or [])
    history.append({"version": f"1.{nxt['revision']}", "at": stamp,
                    "by": values["author"] or "Not set", "fields": changed})
    nxt["history"] = history
    ordered = {k: nxt[k] for k in SIDECAR_ORDER if k in nxt}
    ordered.update({k: v for k, v in nxt.items() if k not in ordered})
    res.data = ordered
    res.changed = True
    return res


def key_default(data: dict, key: str) -> str:
    value = data.get(key) or ""
    if key == "status" and not value:
        return "Preliminary"
    return value


SIDECAR_ORDER = (
    "schema", "revision", "run_sha256", "tlp", "author", "status", "assessment", "confidence",
    "priority", "bottom_line", "rationale", "attribution", "found_via", "alternatives",
    "attack", "attack_version", "limits_added", "references", "history",
)


def tlp_levels() -> list[dict]:
    return [{"value": label, "label": "TLP:" + label, "rank": rank,
             "definition": T.TLP_DEFINITIONS[label]}
            for rank, label in enumerate(T.TLP_ORDER)]


def downgrade_warning(choice: str, saved: str | None) -> str | None:
    """The warning for an explicit TLP looser than the saved one, or None."""
    if saved and tlp_rank(choice) < tlp_rank(saved):
        return T.TLP_DOWNGRADE.format(choice=choice, saved=saved)
    return None


def consistency_warning(values: dict, alternatives: list[dict]) -> str | None:
    red_team = next((a for a in alternatives if a["explanation"] == T.ALTERNATIVES[0]), None)
    if values.get("assessment") == "Benign or research" and (
            red_team is None or red_team["status"] != T.RULED_OUT):
        return CONSISTENCY
    return None


def form_context(name: str, data: dict, *, result: SaveResult | None = None,
                 sidecar_error: str | None = None) -> dict:
    """Everything the assessment form template reads (contract section 4.2)."""
    if result is not None:
        values, alternatives = result.values, result.alternatives
        shown_data = result.data
    else:
        values, alternatives, shown_data = values_from(data), _alternatives_from(data), data
    revision = int(shown_data.get("revision", 0) or 0)

    def described(options, definitions, empty_label=None):
        out = []
        for value in options:
            if value == "":
                out.append({"value": "", "label": empty_label or T.NOT_ASSESSED,
                            "definition": T.NOT_ASSESSED_DEFINITION})
            else:
                out.append({"value": value, "label": value, "definition": definitions[value]})
        return out

    return {
        "name": name,
        "action": f"/runs/{name}/assessment",
        "values": values,
        "alternatives": alternatives,
        "revision": revision,
        "version": version_of(shown_data),
        "saved": bool(result is not None and result.ok),
        "changed": bool(result is not None and result.changed),
        "errors": list(result.errors) if result else [],
        "missing": list(result.missing) if result else [],
        "invalid": list(result.invalid) if result else [],
        "conflict": result.conflict if result else None,
        "sidecar_error": sidecar_error,
        "consistency_warning": consistency_warning(values, alternatives),
        "choices": {
            "assessment": described(CHOICES["assessment"], T.ASSESSMENT_DEFINITIONS),
            "confidence": described(CHOICES["confidence"], T.CONFIDENCE_DEFINITIONS,
                                    "Not set"),
            "priority": described(CHOICES["priority"], T.PRIORITY_DEFINITIONS, "Not set"),
            "status": described(STATUSES, T.STATUS_DEFINITIONS),
            "tlp": tlp_levels(),
            "alt_status": list(ALT_STATUSES),
        },
        "limits": dict(LIMITS),
        "icd203": [{"term": term, "range": rng} for term, rng in T.ICD203_SCALE],
        "icd203_note": T.ICD203_NOTE,
    }
