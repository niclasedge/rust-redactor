"""pytest conftest — register custom markers without touching pyproject.toml."""

from __future__ import annotations


def pytest_configure(config) -> None:  # type: ignore[no-untyped-def]
    config.addinivalue_line(
        "markers",
        "slow: marks tests that load real ML models (set RUN_CLASSIFY_SMOKE=1 to run)",
    )
