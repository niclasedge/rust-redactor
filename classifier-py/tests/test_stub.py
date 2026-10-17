"""Phase-3 contract tests for the classifier sidecar.

Originally these tested the Phase-3 stub. Phase 4 replaces the stub with
the real Presidio + GLiNER pipeline — the **schema-validation contract
remains locked** (exit 2 on bad input, exit 0 on a well-formed request).

To keep this suite hermetic we set ``REDACTOR_CLASSIFY_ANALYZER_FACTORY``
to a non-existent module so the default GLiNER loader is never invoked.
The full Phase-4 happy-path with an injected fake analyzer lives in
``test_main.py``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"


def _run_module(stdin_text: str) -> subprocess.CompletedProcess[str]:
    """Invoke ``python -m classify`` with PYTHONPATH=src and the given stdin.

    Returns the completed process so each test can inspect stdout/stderr/exit.
    """
    env = {
        **os.environ,
        "PYTHONPATH": str(SRC_DIR),
        # Hermetic: avoid loading the real GLiNER weights in the unit suite.
        "REDACTOR_CLASSIFY_ANALYZER_FACTORY": "definitely.not.installed",
    }
    return subprocess.run(
        [sys.executable, "-m", "classify"],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# Happy path — valid request, analyzer unavailable: graceful degradation.
# ---------------------------------------------------------------------------


def test_valid_request_returns_well_formed_envelope() -> None:
    """Even without an analyzer, the response envelope is valid."""
    request = {
        "version": 1,
        "labels": ["TAX_DOC", "PERSONAL_RECORD"],
        "files": [
            {
                "path": "/tmp/example.txt",
                "filename": "example.txt",
                "size_bytes": 12,
                "content_preview": "Hallo Welt!",
            }
        ],
    }
    proc = _run_module(json.dumps(request))
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    payload = json.loads(proc.stdout)
    assert payload["version"] == 1
    assert payload["results"] == []
    assert isinstance(payload["warnings"], list)
    # Analyzer unavailable → warning surfaces the reason.
    assert any("analyzer" in w.lower() for w in payload["warnings"])


def test_empty_files_list_is_valid() -> None:
    request = {"version": 1, "labels": ["TAX_DOC"], "files": []}
    proc = _run_module(json.dumps(request))
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    payload = json.loads(proc.stdout)
    assert payload["results"] == []


# ---------------------------------------------------------------------------
# Schema validation — exit 2 with a clear stderr message on bad input.
# ---------------------------------------------------------------------------


def test_malformed_json_exits_2() -> None:
    proc = _run_module("{this is not json")
    assert proc.returncode == 2
    assert proc.stderr  # non-empty error message


def test_missing_version_field_exits_2() -> None:
    proc = _run_module(json.dumps({"labels": [], "files": []}))
    assert proc.returncode == 2
    assert "version" in proc.stderr.lower()


def test_unsupported_version_exits_2() -> None:
    proc = _run_module(json.dumps({"version": 99, "labels": [], "files": []}))
    assert proc.returncode == 2
    assert "version" in proc.stderr.lower()


def test_labels_must_be_list_of_strings() -> None:
    proc = _run_module(
        json.dumps({"version": 1, "labels": "not-a-list", "files": []})
    )
    assert proc.returncode == 2
    assert "labels" in proc.stderr.lower()


def test_files_entry_must_have_path() -> None:
    request = {
        "version": 1,
        "labels": [],
        "files": [{"filename": "x.txt", "size_bytes": 1, "content_preview": ""}],
    }
    proc = _run_module(json.dumps(request))
    assert proc.returncode == 2
    assert "path" in proc.stderr.lower()


def test_empty_stdin_exits_2() -> None:
    proc = _run_module("")
    assert proc.returncode == 2
