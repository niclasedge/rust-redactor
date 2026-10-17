"""Tests for ``classify.labels`` — default label loader.

The label file (``defaults/labels.txt``) is the source of truth for
GLiNER's zero-shot entity set. These tests pin the loader contract:
comments and blank lines are stripped, empty input raises clearly,
and unknown tokens pass through untouched (GLiNER is zero-shot).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from classify.labels import (
    DEFAULT_LABELS_PATH,
    load_default_labels,
    merge_labels,
    parse_labels_text,
)


def test_default_labels_path_points_to_defaults_dir() -> None:
    assert DEFAULT_LABELS_PATH.is_file()
    assert DEFAULT_LABELS_PATH.name == "labels.txt"


def test_load_default_labels_returns_nonempty_list() -> None:
    labels = load_default_labels()
    assert isinstance(labels, list)
    assert labels  # at least one label
    assert all(isinstance(lbl, str) for lbl in labels)
    assert "TAX_DOC" in labels
    assert "CREDENTIAL" in labels
    assert "PRIVATE_KEY" in labels


def test_parse_labels_text_strips_comments_and_blanks() -> None:
    text = "\n".join(
        [
            "# top comment",
            "",
            "TAX_DOC",
            "  ",
            "# inline comment line",
            "BANK_STATEMENT",
            "  PADDED_LABEL  ",  # whitespace trimmed
        ]
    )
    result = parse_labels_text(text)
    assert result == ["TAX_DOC", "BANK_STATEMENT", "PADDED_LABEL"]


def test_parse_labels_text_preserves_order() -> None:
    text = "ZULU\nALPHA\nMIKE\n"
    assert parse_labels_text(text) == ["ZULU", "ALPHA", "MIKE"]


def test_parse_labels_text_deduplicates_keeping_first() -> None:
    text = "A\nB\nA\nC\nB\n"
    assert parse_labels_text(text) == ["A", "B", "C"]


def test_parse_labels_text_empty_raises_value_error() -> None:
    with pytest.raises(ValueError, match="no labels"):
        parse_labels_text("# only a comment\n\n   \n")


def test_merge_labels_user_overrides_then_defaults() -> None:
    defaults = ["TAX_DOC", "CREDENTIAL"]
    user = ["CONTRACT", "TAX_DOC", "NDA"]
    merged = merge_labels(user, defaults)
    # User-supplied first, then defaults not yet present.
    assert merged == ["CONTRACT", "TAX_DOC", "NDA", "CREDENTIAL"]


def test_merge_labels_empty_user_returns_defaults() -> None:
    defaults = ["TAX_DOC", "CREDENTIAL"]
    assert merge_labels([], defaults) == defaults


def test_merge_labels_empty_defaults_returns_user() -> None:
    user = ["CONTRACT", "NDA"]
    assert merge_labels(user, []) == user


def test_merge_labels_both_empty_raises() -> None:
    with pytest.raises(ValueError, match="no labels"):
        merge_labels([], [])


def test_unknown_tokens_pass_through(tmp_path: Path) -> None:
    """GLiNER is zero-shot; we do NOT validate against a closed vocabulary."""
    custom = tmp_path / "labels.txt"
    custom.write_text("SOMETHING_VERY_DOMAIN_SPECIFIC\nMORE_WEIRD_LABELS_42\n")
    labels = parse_labels_text(custom.read_text())
    assert "SOMETHING_VERY_DOMAIN_SPECIFIC" in labels
    assert "MORE_WEIRD_LABELS_42" in labels
