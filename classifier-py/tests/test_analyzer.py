"""Tests for ``classify.analyzer`` — confidence + evidence aggregation.

Mocking strategy: the analyzer module wraps Presidio behind a thin
``Analyzer`` protocol so unit tests can swap in a hand-rolled stub
that returns canned ``Entity`` records. We never import GLiNER or
spaCy in the default test suite — the real model wiring is gated
behind ``test_smoke_real.py`` (``RUN_CLASSIFY_SMOKE=1``).
"""

from __future__ import annotations

from typing import List

import pytest

from classify.analyzer import (
    Entity,
    aggregate_confidence,
    build_evidence,
    classify_file,
    filename_boost,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class FakeAnalyzer:
    """Stand-in for ``classify.analyzer.Analyzer`` that returns canned hits."""

    def __init__(self, entities_by_text: dict[str, List[Entity]]):
        self._entities_by_text = entities_by_text
        self.calls: list[tuple[str, list[str]]] = []

    def analyze(self, text: str, labels: list[str]) -> List[Entity]:
        self.calls.append((text, list(labels)))
        return list(self._entities_by_text.get(text, []))


def _file_entry(
    path: str = "/tmp/example.txt",
    filename: str | None = None,
    size_bytes: int = 1024,
    content_preview: str = "",
) -> dict[str, object]:
    return {
        "path": path,
        "filename": filename if filename is not None else path.rsplit("/", 1)[-1],
        "size_bytes": size_bytes,
        "content_preview": content_preview,
    }


# ---------------------------------------------------------------------------
# filename_boost — pattern-keyed bonuses, capped at 0.3
# ---------------------------------------------------------------------------


def test_filename_boost_zero_for_neutral_name() -> None:
    assert filename_boost("notes.txt") == 0.0


@pytest.mark.parametrize(
    "filename",
    [
        "steuererklaerung.pdf",
        "Steuer_2024.pdf",  # case-insensitive
        "my_tax_return.pdf",
        "passwort_liste.txt",
        "personalakte_2023.docx",
        "gehaltsabrechnung.pdf",
    ],
)
def test_filename_boost_recognises_single_keyword(filename: str) -> None:
    boost = filename_boost(filename)
    assert boost == pytest.approx(0.1)


def test_filename_boost_stacks_multiple_keywords() -> None:
    # Two keywords → 0.2
    assert filename_boost("steuer_passwort.pdf") == pytest.approx(0.2)


def test_filename_boost_capped_at_threshold() -> None:
    # Four keywords would naively give 0.4 — must clamp to 0.3.
    name = "tax_passwort_personalakte_gehalt.pdf"
    assert filename_boost(name) == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# aggregate_confidence — normalize entity scores + filename boost
# ---------------------------------------------------------------------------


def test_aggregate_confidence_no_entities_no_boost_is_zero() -> None:
    assert aggregate_confidence(entities=[], filename="random.txt") == 0.0


def test_aggregate_confidence_filename_only_signal() -> None:
    """No entities but a strong filename → low but non-zero confidence."""
    score = aggregate_confidence(entities=[], filename="steuererklaerung.pdf")
    assert score == pytest.approx(0.1)


def test_aggregate_confidence_single_entity_normalized() -> None:
    ents = [Entity(text="Einkommensteuer", label="TAX_DOC", score=0.8)]
    # Normalization: sum of scores capped to 0.7 entity component.
    score = aggregate_confidence(entities=ents, filename="random.txt")
    # 0.8 normalised via min(score_sum, 0.7) → 0.7
    assert score == pytest.approx(0.7)


def test_aggregate_confidence_multiple_entities_saturate() -> None:
    ents = [
        Entity(text="a", label="X", score=0.9),
        Entity(text="b", label="Y", score=0.9),
        Entity(text="c", label="Z", score=0.9),
    ]
    # Sum > 0.7 → clamped to 0.7 entity component.
    score = aggregate_confidence(entities=ents, filename="random.txt")
    assert score == pytest.approx(0.7)


def test_aggregate_confidence_clamped_at_one() -> None:
    ents = [Entity(text="x", label="TAX_DOC", score=1.0)]
    score = aggregate_confidence(
        entities=ents,
        filename="steuer_passwort_personalakte_gehalt.pdf",
    )
    # 0.7 entity + 0.3 filename = 1.0 exactly.
    assert score == pytest.approx(1.0)


def test_aggregate_confidence_entity_plus_filename() -> None:
    ents = [Entity(text="Einkommensteuer", label="TAX_DOC", score=0.5)]
    score = aggregate_confidence(entities=ents, filename="tax_return.pdf")
    # 0.5 entity component (sum<0.7, no cap) + 0.1 filename = 0.6
    assert score == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# build_evidence — top-3 entities, formatted, truncated to 280 chars
# ---------------------------------------------------------------------------


def test_build_evidence_empty_when_no_entities() -> None:
    assert build_evidence([]) == ""


def test_build_evidence_top_three_by_score() -> None:
    ents = [
        Entity(text="alpha", label="A", score=0.40),
        Entity(text="bravo", label="B", score=0.90),
        Entity(text="charlie", label="C", score=0.10),
        Entity(text="delta", label="D", score=0.75),
        Entity(text="echo", label="E", score=0.60),
    ]
    evidence = build_evidence(ents)
    # Top-3 sorted descending: bravo (0.90), delta (0.75), echo (0.60)
    assert "bravo" in evidence
    assert "delta" in evidence
    assert "echo" in evidence
    assert "alpha" not in evidence
    assert "charlie" not in evidence


def test_build_evidence_format_includes_label_and_score() -> None:
    ents = [Entity(text="Einkommensteuer", label="TAX_DOC", score=0.94)]
    evidence = build_evidence(ents)
    assert "Einkommensteuer" in evidence
    assert "TAX_DOC" in evidence
    assert "0.94" in evidence
    assert "Detected" in evidence


def test_build_evidence_truncated_to_280() -> None:
    # Force a very long evidence string.
    ents = [Entity(text="X" * 500, label="LONG_LABEL", score=0.9)]
    evidence = build_evidence(ents)
    assert len(evidence) <= 280


# ---------------------------------------------------------------------------
# classify_file — orchestrator, returns Result | None
# ---------------------------------------------------------------------------


def test_classify_file_empty_content_no_filename_signal_returns_none() -> None:
    analyzer = FakeAnalyzer({})
    file = _file_entry(content_preview="")
    result = classify_file(analyzer, file, labels=["TAX_DOC"])
    assert result is None


def test_classify_file_with_entities_returns_result() -> None:
    text = "Einkommensteuer 2024 — Finanzamt München"
    analyzer = FakeAnalyzer(
        {
            text: [
                Entity(text="Einkommensteuer", label="TAX_DOC", score=0.94),
                Entity(text="Finanzamt", label="TAX_DOC", score=0.91),
            ]
        }
    )
    file = _file_entry(
        path="/Users/x/Steuer/2024.pdf",
        content_preview=text,
    )
    result = classify_file(analyzer, file, labels=["TAX_DOC"])
    assert result is not None
    assert result["path"] == "/Users/x/Steuer/2024.pdf"
    assert "TAX_DOC" in result["labels"]
    assert result["confidence"] > 0.5
    assert "Einkommensteuer" in result["evidence"]


def test_classify_file_filename_only_signal_returns_low_confidence() -> None:
    """No content entities but a tax-keyed filename still yields a Result."""
    analyzer = FakeAnalyzer({})
    file = _file_entry(
        path="/Users/x/Steuer/erklaerung.pdf",
        filename="steuererklaerung.pdf",
        content_preview="some unrelated text",
    )
    result = classify_file(analyzer, file, labels=["TAX_DOC"])
    assert result is not None
    assert 0 < result["confidence"] < 0.5
    # Filename-only signal carries no entity evidence.
    assert result["evidence"] == "" or "filename" in result["evidence"].lower()


def test_classify_file_labels_deduplicated() -> None:
    text = "x"
    analyzer = FakeAnalyzer(
        {
            text: [
                Entity(text="a", label="TAX_DOC", score=0.5),
                Entity(text="b", label="TAX_DOC", score=0.4),
                Entity(text="c", label="FINANCIAL_RECORD", score=0.3),
            ]
        }
    )
    file = _file_entry(content_preview=text)
    result = classify_file(analyzer, file, labels=["TAX_DOC", "FINANCIAL_RECORD"])
    assert result is not None
    # Labels deduped, order = descending by aggregate score.
    assert result["labels"] == ["TAX_DOC", "FINANCIAL_RECORD"]


def test_classify_file_passes_labels_to_analyzer() -> None:
    analyzer = FakeAnalyzer({})
    file = _file_entry(content_preview="dummy text content")
    labels = ["TAX_DOC", "CONTRACT", "NDA"]
    classify_file(analyzer, file, labels=labels)
    assert analyzer.calls == [("dummy text content", labels)]
