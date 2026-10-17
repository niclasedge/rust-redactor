"""End-to-end smoke test using the real GLiNER model.

Skipped by default. Run with ``RUN_CLASSIFY_SMOKE=1`` to exercise the
actual ``urchade/gliner_multi_pii-v1`` weights against a fixture of
German tax keywords. The model has to be available in the local
HuggingFace cache — this test does *not* download anything.

Marker: ``slow`` (also see ``pyproject.toml`` if you add custom marker
filters). The skip happens before any heavy import.
"""

from __future__ import annotations

import os

import pytest

_SMOKE_FLAG = "RUN_CLASSIFY_SMOKE"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        os.environ.get(_SMOKE_FLAG) != "1",
        reason=f"set {_SMOKE_FLAG}=1 to run the real-model smoke test",
    ),
]


def test_real_gliner_detects_german_tax_keywords() -> None:
    """Real GLiNER finds tax-related entities in a German fixture."""
    from classify.analyzer import build_analyzer, classify_file

    labels = ["TAX_DOC", "FINANCIAL_RECORD", "PERSONAL_RECORD"]
    analyzer, warnings = build_analyzer(labels)
    assert warnings == [] or all(isinstance(w, str) for w in warnings)

    fixture_text = (
        "Einkommensteuererklärung 2024 für Herrn Max Mustermann. "
        "Finanzamt München-Süd. Steuernummer 123/456/78901. "
        "Vorauszahlung Einkommensteuer Q4."
    )
    file_entry = {
        "path": "/tmp/steuer.pdf",
        "filename": "steuererklaerung_2024.pdf",
        "size_bytes": len(fixture_text),
        "content_preview": fixture_text,
    }
    result = classify_file(analyzer, file_entry, labels)
    assert result is not None
    assert result["confidence"] >= 0.6, result
    # We expect TAX_DOC to dominate the labels list.
    assert "TAX_DOC" in result["labels"]
