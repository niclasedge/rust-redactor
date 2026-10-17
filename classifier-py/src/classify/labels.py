"""Default label loader for the classifier sidecar.

The ``labels.txt`` file ships with the package (``defaults/labels.txt``)
and is also copied into ``~/.config/redactor/classifier/labels.txt`` at
install time so users can edit it. This module is intentionally tiny —
its only job is to parse the text format into a clean list and merge a
user-supplied set with the defaults.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "DEFAULT_LABELS_PATH",
    "load_default_labels",
    "merge_labels",
    "parse_labels_text",
]


# defaults/labels.txt lives next to ``src/`` and ``tests/``.
# classify/labels.py → src/classify/labels.py → repo root is two up.
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LABELS_PATH: Path = _REPO_ROOT / "defaults" / "labels.txt"


def parse_labels_text(text: str) -> list[str]:
    """Parse the label-file text into an ordered, deduplicated list.

    Rules:
    * Lines beginning with ``#`` (after stripping whitespace) are comments.
    * Blank / whitespace-only lines are ignored.
    * Surrounding whitespace on label lines is stripped.
    * First occurrence wins for duplicates; order is preserved.

    Raises ``ValueError`` if the parsed list is empty — an empty label set
    is never valid (GLiNER would have nothing to look for).
    """
    seen: set[str] = set()
    labels: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        labels.append(line)
    if not labels:
        raise ValueError("no labels: input contained only comments or blanks")
    return labels


def load_default_labels(path: Path | None = None) -> list[str]:
    """Load the shipped default label set."""
    target = path or DEFAULT_LABELS_PATH
    return parse_labels_text(target.read_text(encoding="utf-8"))


def merge_labels(user: list[str], defaults: list[str]) -> list[str]:
    """Merge user-supplied labels with defaults.

    User labels come first (they're the explicit override) and any
    defaults not already covered get appended. Both lists empty → raise.
    """
    seen: set[str] = set()
    merged: list[str] = []
    for lbl in (*user, *defaults):
        if lbl in seen:
            continue
        seen.add(lbl)
        merged.append(lbl)
    if not merged:
        raise ValueError("no labels: both user and defaults are empty")
    return merged
