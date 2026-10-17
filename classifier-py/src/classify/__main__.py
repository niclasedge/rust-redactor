"""Entry point for ``python -m classify`` (Phase 4 — real classifier).

Reads a JSON request from stdin (§5.5), runs each file through the
Presidio + GLiNER analyzer, and writes the response JSON to stdout.

Exit codes (locked contract — Rust depends on these):

* ``0`` — success. Response JSON on stdout, possibly with warnings.
* ``1`` — hard analyzer error after schema validation succeeded.
  Response JSON still on stdout, plus an ``error`` field.
* ``2`` — schema validation failed; stderr explains.

The heavy ML imports are gated behind ``_load_analyzer`` so a malformed
request or a missing sidecar install never triggers them.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import traceback
from typing import Any, Callable

from classify.analyzer import Analyzer, Result, classify_file

SUPPORTED_VERSION = 1

# Env override used by the test suite to inject a fake analyzer factory
# without ever importing GLiNER. Value is a dotted module path that
# exposes ``build_analyzer(labels) -> (Analyzer, list[str])``.
_FACTORY_ENV = "REDACTOR_CLASSIFY_ANALYZER_FACTORY"
_DEFAULT_FACTORY = "classify.analyzer"


class RequestError(Exception):
    """Raised when the JSON request fails schema validation.

    The string form is written verbatim to stderr before exit 2, so keep
    it short and actionable (the Rust side surfaces this to the user).
    """


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RequestError(message)


def validate_request(payload: Any) -> dict[str, Any]:
    """Validate a parsed JSON payload against the §5.5 request schema."""
    _require(isinstance(payload, dict), "request must be a JSON object")

    version = payload.get("version")
    _require(
        version == SUPPORTED_VERSION,
        f"unsupported or missing 'version' (expected {SUPPORTED_VERSION}, got {version!r})",
    )

    labels = payload.get("labels", [])
    _require(isinstance(labels, list), "'labels' must be a list of strings")
    for i, label in enumerate(labels):
        _require(
            isinstance(label, str),
            f"'labels[{i}]' must be a string (got {type(label).__name__})",
        )

    files = payload.get("files", [])
    _require(isinstance(files, list), "'files' must be a list of objects")
    for i, entry in enumerate(files):
        _require(
            isinstance(entry, dict),
            f"'files[{i}]' must be an object (got {type(entry).__name__})",
        )
        _require(
            bool("path" in entry and isinstance(entry["path"], str) and entry["path"]),
            f"'files[{i}].path' is required and must be a non-empty string",
        )

    # mypy: cast away the Any from JSON parsing — we just validated shape.
    return dict(payload)


def _load_analyzer(
    labels: list[str],
) -> tuple[Analyzer | None, list[str]]:
    """Resolve and call the analyzer factory.

    Returns ``(analyzer, warnings)``. On any failure ``analyzer`` is None
    and the failure reason is appended to ``warnings`` so the caller can
    still return a well-formed response (degraded, but valid).
    """
    factory_path = os.environ.get(_FACTORY_ENV, _DEFAULT_FACTORY)
    try:
        module = importlib.import_module(factory_path)
    except Exception as exc:  # noqa: BLE001
        return None, [f"analyzer module {factory_path!r} not loadable: {exc}"]

    build = getattr(module, "build_analyzer", None)
    if not callable(build):
        return None, [
            f"analyzer module {factory_path!r} has no 'build_analyzer(labels)' function"
        ]

    builder: Callable[[list[str]], tuple[Analyzer, list[str]]] = build
    try:
        analyzer, warnings = builder(labels)
    except Exception as exc:  # noqa: BLE001 — surface anything as a warning
        return None, [f"analyzer init failed: {exc}"]
    return analyzer, list(warnings)


def _process_files(
    analyzer: Analyzer,
    files: list[dict[str, Any]],
    labels: list[str],
) -> tuple[list[Result], list[str]]:
    """Run each file through the analyzer and collect results + warnings."""
    results: list[Result] = []
    warnings: list[str] = []
    for entry in files:
        try:
            result = classify_file(analyzer, entry, labels)
        except Exception as exc:  # noqa: BLE001 — never let one file kill the run
            warnings.append(f"file {entry.get('path')!r}: {exc}")
            continue
        if result is not None:
            results.append(result)
    return results, warnings


def main(argv: list[str] | None = None) -> int:
    """CLI entry. Returns the process exit code.

    * 0 — JSON response on stdout
    * 1 — hard error during classification; stdout still has a valid JSON
      envelope with an ``error`` field
    * 2 — bad input; stderr explains
    """
    del argv  # reserved for future flags

    raw = sys.stdin.read()
    if not raw.strip():
        print("redactor-classify: empty stdin (expected JSON request)", file=sys.stderr)
        return 2

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"redactor-classify: malformed JSON request: {exc}", file=sys.stderr)
        return 2

    try:
        request = validate_request(payload)
    except RequestError as exc:
        print(f"redactor-classify: {exc}", file=sys.stderr)
        return 2

    labels = list(request.get("labels", []))
    files = list(request.get("files", []))

    response: dict[str, Any] = {
        "version": SUPPORTED_VERSION,
        "results": [],
        "warnings": [],
    }

    analyzer, load_warnings = _load_analyzer(labels)
    response["warnings"].extend(load_warnings)

    if analyzer is None:
        # Graceful degradation: empty results, warnings already populated,
        # still exit 0 so the Rust side surfaces the warning rather than
        # treating the whole run as a hard failure.
        json.dump(response, sys.stdout)
        sys.stdout.write("\n")
        return 0

    try:
        results, file_warnings = _process_files(analyzer, files, labels)
    except Exception as exc:  # noqa: BLE001 — analyzer-level catastrophe
        response["error"] = f"analyzer crashed: {exc}"
        response["warnings"].append("aborting run after analyzer-level failure")
        # Print full traceback to stderr for debuggability.
        traceback.print_exc(file=sys.stderr)
        json.dump(response, sys.stdout)
        sys.stdout.write("\n")
        return 1

    response["results"] = results
    response["warnings"].extend(file_warnings)
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
