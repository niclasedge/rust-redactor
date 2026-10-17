"""Presidio + GLiNER analyzer wiring for the redactor classifier sidecar.

This module has two layers:

1.  **Pure aggregation** (``Entity``, ``filename_boost``,
    ``aggregate_confidence``, ``build_evidence``, ``classify_file``).
    No model imports, fully unit-testable with a fake analyzer.

2.  **Real-model factory** (``build_analyzer``) — wires Microsoft
    Presidio's ``AnalyzerEngine`` with a GLiNER-backed
    ``EntityRecognizer``. The heavy imports happen *inside*
    ``build_analyzer`` so the unit tests in ``test_analyzer.py`` never
    touch GLiNER, Presidio, or spaCy.

The protocol the rest of the system relies on is ``Analyzer`` —
anything with an ``analyze(text, labels) -> list[Entity]`` method works.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

__all__ = [
    "Analyzer",
    "Entity",
    "Result",
    "aggregate_confidence",
    "build_analyzer",
    "build_evidence",
    "classify_file",
    "entity_type_for_label",
    "filename_boost",
    "DOCUMENT_TYPE_LABELS",
    "ENTITY_TYPE_LABELS",
]


# ---------------------------------------------------------------------------
# Phase 6b — label-class mapping
# ---------------------------------------------------------------------------

# Default document-type labels (file-confidence aggregation).
DOCUMENT_TYPE_LABELS: frozenset[str] = frozenset(
    {
        "TAX_DOC",
        "BANK_STATEMENT",
        "PERSONAL_RECORD",
        "CREDENTIAL",
        "PRIVATE_KEY",
        "MEDICAL_RECORD",
        "LEGAL_DOC",
        "PASSWORD_VAULT",
        "CUSTOMER_DATA",
        "EMPLOYEE_RECORD",
    }
)

# Entity-type labels → produce keyword-suggestions, not file-confidence.
ENTITY_TYPE_LABELS: frozenset[str] = frozenset(
    {
        "PERSON",
        "ORGANIZATION",
        "LOCATION",
        "URL",
        "EMAIL",
        "HOSTNAME",
        "PASSWORD",
        "SECRET",
        "API_KEY",
    }
)


def entity_type_for_label(label: str) -> str:
    """Classify a GLiNER label into a Phase-6b entity-type bucket.

    Returns one of:
        ``"DOCUMENT_TYPE"`` — feeds into file-confidence
        ``"PERSON"`` / ``"ORGANIZATION"`` / ``"LOCATION"`` / ``"URL"`` /
        ``"EMAIL"`` / ``"HOSTNAME"`` / ``"PASSWORD"`` / ``"SECRET"`` /
        ``"API_KEY"`` — feeds into the keyword-suggestion stream
        ``"OTHER"`` — dropped at aggregation
    """
    upper = label.strip().upper()
    if upper in DOCUMENT_TYPE_LABELS:
        return "DOCUMENT_TYPE"
    if upper in ENTITY_TYPE_LABELS:
        return upper
    return "OTHER"


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Entity:
    """A single PII / classification hit.

    ``score`` is whatever the source recognizer reports (0..1). For
    GLiNER+Presidio the score is the GLiNER confidence for that span.
    """

    text: str
    label: str
    score: float


class Analyzer(Protocol):
    """Anything that can score a chunk of text against a label set."""

    def analyze(self, text: str, labels: list[str]) -> list[Entity]: ...


# Wire-format result entry (one per "above-signal" file).
Result = dict[str, Any]


# ---------------------------------------------------------------------------
# Filename heuristic
# ---------------------------------------------------------------------------

# Keyword → boost contribution. Each match adds 0.1, capped at 0.3.
# Substring match (case-insensitive). The keywords are deliberately
# loose German + English markers that appear in actual file names —
# the goal is to nudge low-content files past the threshold, not to
# replace content analysis.
_FILENAME_KEYWORDS: tuple[str, ...] = (
    "steuer",
    "tax",
    "passwort",
    "password",
    "personalakt",
    "gehalt",
    "salary",
    "payroll",
)

_FILENAME_BOOST_PER_HIT = 0.1
_FILENAME_BOOST_CAP = 0.3
_ENTITY_SCORE_CAP = 0.7  # leaves headroom for the filename component


def filename_boost(filename: str) -> float:
    """Return the filename heuristic contribution to confidence.

    Returns 0.0 for neutral names. Each unique keyword hit adds
    ``_FILENAME_BOOST_PER_HIT`` (0.1), clamped at ``_FILENAME_BOOST_CAP``
    (0.3) so a filename alone can never dominate the score.
    """
    lower = filename.lower()
    hits = sum(1 for kw in _FILENAME_KEYWORDS if kw in lower)
    return min(hits * _FILENAME_BOOST_PER_HIT, _FILENAME_BOOST_CAP)


# ---------------------------------------------------------------------------
# Confidence aggregation
# ---------------------------------------------------------------------------


def aggregate_confidence(entities: list[Entity], filename: str) -> float:
    """Combine entity scores and filename boost into a single 0..1 score.

    Phase 6b: only *document-type* entity hits contribute to the file-level
    confidence. Pure entity-type hits (PERSON, ORGANIZATION, …) feed the
    keyword stream instead, so we exclude them from the path-suggestion math.
    Backward-compat: when no label classifies as DOCUMENT_TYPE (typical for
    a custom label list without the Phase-6b sections), fall back to summing
    every hit — so existing setups don't regress to 0.0 confidence.

    Math:
    * Entity component = ``min(sum(eligible_entity.score), 0.7)``.
    * Filename component = ``filename_boost(filename)``, capped at 0.3.
    * Final = ``min(1.0, entity_component + filename_component)``.
    """
    document_entities = [
        e for e in entities if entity_type_for_label(e.label) == "DOCUMENT_TYPE"
    ]
    # Backwards-compat: if NO label in the active set is a doc-type, treat
    # everything as document-type (legacy behaviour).
    eligible = document_entities if document_entities else entities
    entity_component = min(sum(e.score for e in eligible), _ENTITY_SCORE_CAP)
    return min(1.0, entity_component + filename_boost(filename))


# ---------------------------------------------------------------------------
# Evidence string (top-3 entities, truncated)
# ---------------------------------------------------------------------------

_EVIDENCE_TOP_N = 3
_EVIDENCE_MAX_CHARS = 280


def build_evidence(entities: list[Entity]) -> str:
    """Format the top-N entities into a short human-readable evidence string.

    Schema (matches §4.3 of the design spec):
        ``Detected '<text>' (<LABEL>, score=0.94), '<text2>' (<L>, ...), ...``

    Truncated to 280 chars to keep the .suggested file readable and the
    JSON response small. Returns "" for an empty list.
    """
    if not entities:
        return ""
    top = sorted(entities, key=lambda e: e.score, reverse=True)[:_EVIDENCE_TOP_N]
    parts = [f"'{e.text}' ({e.label}, score={e.score:.2f})" for e in top]
    evidence = "Detected " + ", ".join(parts)
    if len(evidence) > _EVIDENCE_MAX_CHARS:
        # Truncate and add ellipsis — caller treats this string as opaque.
        evidence = evidence[: _EVIDENCE_MAX_CHARS - 1].rstrip() + "…"
    return evidence


# ---------------------------------------------------------------------------
# classify_file orchestrator
# ---------------------------------------------------------------------------


def _labels_sorted_by_score(entities: list[Entity]) -> list[str]:
    """Distinct labels in descending order of summed score."""
    totals: dict[str, float] = {}
    for ent in entities:
        totals[ent.label] = totals.get(ent.label, 0.0) + ent.score
    return sorted(totals, key=lambda lbl: totals[lbl], reverse=True)


def classify_file(
    analyzer: Analyzer,
    file_entry: dict[str, Any],
    labels: list[str],
) -> Result | None:
    """Score a single file. Returns a Result or None if there's no signal.

    ``file_entry`` matches the request schema (§5.5):
        {path, filename, size_bytes, content_preview}

    Returns ``None`` for files where neither the analyzer nor the
    filename heuristic produce any signal — the Rust side filters
    those out anyway, but skipping the entry up-front keeps the
    response compact.
    """
    content = str(file_entry.get("content_preview", "") or "")
    filename = str(file_entry.get("filename", "") or "")
    path = str(file_entry["path"])

    entities = analyzer.analyze(content, labels) if content else []
    confidence = aggregate_confidence(entities, filename)
    if confidence <= 0.0:
        return None

    detected_labels = _labels_sorted_by_score(entities)
    evidence = build_evidence(entities)
    if not entities and filename_boost(filename) > 0:
        # Filename-only signal — leave detected_labels empty (the GLiNER
        # ran but found nothing) and put a human-readable note in evidence
        # so reviewers know why this file showed up.
        evidence = f"Filename heuristic matched (boost={filename_boost(filename):.2f})"

    # Phase 6b: serialize per-entity hits with their bucket category so the
    # Rust side can aggregate into the keyword stream.
    entity_hits = [
        {
            "text": e.text,
            "label": e.label,
            "score": round(e.score, 4),
            "entity_type": entity_type_for_label(e.label),
        }
        for e in entities
    ]

    return {
        "path": path,
        "confidence": round(confidence, 4),
        "labels": detected_labels,
        "evidence": evidence,
        "entities": entity_hits,
    }


# ---------------------------------------------------------------------------
# Real-model factory
# ---------------------------------------------------------------------------


def build_analyzer(labels: list[str]) -> tuple[Analyzer, list[str]]:
    """Construct a real Presidio + GLiNER analyzer.

    Returns ``(analyzer, warnings)``. Warnings are non-fatal strings
    (e.g. "spaCy model de_core_news_sm not found, skipped"). On hard
    failure (Presidio cannot init, GLiNER weights missing), raises
    ``RuntimeError`` — the caller in ``__main__`` converts that to a
    response-level warning.

    Model source: ``REDACTOR_GLINER_PATH`` env var if set (points at the
    local_dir written by ``redactor classifier-install``), otherwise the
    HuggingFace repo id and the default HF cache. The env-var path matters
    on Windows, where the installer writes flat files via ``local_dir`` to
    avoid the symlink restriction that ``cache_dir`` mode hits without
    Developer Mode.
    """
    # Local imports keep the unit-test suite free of ML deps.
    import os

    warnings: list[str] = []

    try:
        from gliner import GLiNER  # type: ignore[import-untyped]
    except Exception as exc:  # noqa: BLE001 — surface any import error verbatim
        raise RuntimeError(f"GLiNER import failed: {exc}") from exc

    model_source = (
        os.environ.get("REDACTOR_GLINER_PATH") or "urchade/gliner_multi_pii-v1"
    )
    try:
        gliner_model = GLiNER.from_pretrained(model_source)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"GLiNER weights load failed (source={model_source!r}): {exc}"
        ) from exc

    analyzer = _GlinerAnalyzer(gliner_model, default_labels=labels)
    return analyzer, warnings


class _GlinerAnalyzer:
    """Thin wrapper that adapts GLiNER to the ``Analyzer`` protocol.

    We deliberately do NOT route through Presidio's ``AnalyzerEngine``
    here. Presidio shines when you have many heterogeneous recognizers
    (SSN regex + spaCy NER + custom regexes) and want score
    deduplication. For our pure-GLiNER zero-shot setup the engine adds
    overhead without value. We keep the option open: the public
    ``Analyzer`` protocol means we can wrap Presidio later without
    touching ``classify_file``.
    """

    def __init__(self, gliner_model: Any, default_labels: list[str]) -> None:
        self._model = gliner_model
        self._default_labels = default_labels

    def analyze(self, text: str, labels: list[str]) -> list[Entity]:
        if not text:
            return []
        active_labels = labels or self._default_labels
        try:
            raw = self._model.predict_entities(text, active_labels)
        except Exception:
            # Per-file failure must not kill the whole run.
            return []
        out: list[Entity] = []
        for hit in raw:
            try:
                out.append(
                    Entity(
                        text=str(hit["text"]),
                        label=str(hit["label"]),
                        score=float(hit.get("score", 0.0)),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return out
