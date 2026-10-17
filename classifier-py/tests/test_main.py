"""Integration tests for ``python -m classify`` (Phase 4 entry).

Phase-3 schema-validation behaviour MUST be preserved (exit 2 on bad
input). On top of that, the entry now:

* lazy-loads the analyzer
* runs each file through the analyzer
* writes the response in §5.5 shape

Tests use ``REDACTOR_CLASSIFY_ANALYZER_FACTORY`` (an env-var hook on
``__main__``) to inject a fake analyzer module — that keeps Presidio
+ GLiNER fully out of the unit-test path. The default suite must not
import them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"


def _run_module(
    stdin_text: str,
    *,
    extra_env: dict[str, str] | None = None,
    extra_pythonpath: list[Path] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    pythonpath_parts = [str(SRC_DIR)]
    if extra_pythonpath:
        pythonpath_parts = [str(p) for p in extra_pythonpath] + pythonpath_parts
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "classify"],
        input=stdin_text,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def _write_fake_analyzer_module(
    tmp_path: Path,
    *,
    crash_on_load: bool = False,
    behaviour: str = "empty",  # "empty" | "tax" | "all-files"
) -> Path:
    """Write a fake ``classify_fake_factory`` module that __main__ can import."""
    pkg = tmp_path / "fake_factory_pkg"
    pkg.mkdir(exist_ok=True)
    (pkg / "__init__.py").write_text("")
    module = pkg / "fake_factory.py"
    module.write_text(
        textwrap.dedent(
            f"""
            from classify.analyzer import Entity

            CRASH_ON_LOAD = {crash_on_load!r}
            BEHAVIOUR = {behaviour!r}


            class FakeAnalyzer:
                def __init__(self):
                    self.warnings = []

                def analyze(self, text, labels):
                    if BEHAVIOUR == "empty":
                        return []
                    if BEHAVIOUR == "tax":
                        return [
                            Entity(
                                text="Einkommensteuer",
                                label="TAX_DOC",
                                score=0.94,
                            ),
                            Entity(
                                text="Finanzamt",
                                label="TAX_DOC",
                                score=0.91,
                            ),
                        ]
                    if BEHAVIOUR == "all-files":
                        return [
                            Entity(text="hit", label="CREDENTIAL", score=0.85)
                        ]
                    return []


            def build_analyzer(labels):
                if CRASH_ON_LOAD:
                    raise RuntimeError("simulated model load failure")
                return FakeAnalyzer(), []  # (analyzer, warnings)
            """
        ).strip()
        + "\n"
    )
    return pkg


# ---------------------------------------------------------------------------
# Phase-3 contract preserved (locked exit codes)
# ---------------------------------------------------------------------------


def test_malformed_json_exits_2() -> None:
    proc = _run_module("{this is not json")
    assert proc.returncode == 2
    assert proc.stderr


def test_missing_version_field_exits_2() -> None:
    proc = _run_module(json.dumps({"labels": [], "files": []}))
    assert proc.returncode == 2
    assert "version" in proc.stderr.lower()


def test_empty_stdin_exits_2() -> None:
    proc = _run_module("")
    assert proc.returncode == 2


def test_files_entry_must_have_path() -> None:
    request = {
        "version": 1,
        "labels": [],
        "files": [{"filename": "x.txt", "size_bytes": 1, "content_preview": ""}],
    }
    proc = _run_module(json.dumps(request))
    assert proc.returncode == 2
    assert "path" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# Phase-4 happy path: injected fake analyzer
# ---------------------------------------------------------------------------


def test_valid_request_with_fake_analyzer_returns_results(tmp_path: Path) -> None:
    pkg = _write_fake_analyzer_module(tmp_path, behaviour="tax")
    request = {
        "version": 1,
        "labels": ["TAX_DOC"],
        "files": [
            {
                "path": "/tmp/steuer.pdf",
                "filename": "steuer.pdf",
                "size_bytes": 1234,
                "content_preview": "Einkommensteuer 2024",
            }
        ],
    }
    proc = _run_module(
        json.dumps(request),
        extra_env={
            "REDACTOR_CLASSIFY_ANALYZER_FACTORY": "fake_factory_pkg.fake_factory",
        },
        extra_pythonpath=[pkg.parent],
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    payload = json.loads(proc.stdout)
    assert payload["version"] == 1
    assert len(payload["results"]) == 1
    result = payload["results"][0]
    assert result["path"] == "/tmp/steuer.pdf"
    assert "TAX_DOC" in result["labels"]
    assert result["confidence"] > 0.5
    assert "Einkommensteuer" in result["evidence"]


def test_empty_signal_yields_no_result_entry(tmp_path: Path) -> None:
    pkg = _write_fake_analyzer_module(tmp_path, behaviour="empty")
    request = {
        "version": 1,
        "labels": ["TAX_DOC"],
        "files": [
            {
                "path": "/tmp/random.txt",
                "filename": "random.txt",
                "size_bytes": 10,
                "content_preview": "Lorem ipsum",
            }
        ],
    }
    proc = _run_module(
        json.dumps(request),
        extra_env={
            "REDACTOR_CLASSIFY_ANALYZER_FACTORY": "fake_factory_pkg.fake_factory",
        },
        extra_pythonpath=[pkg.parent],
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    payload = json.loads(proc.stdout)
    assert payload["results"] == []


# ---------------------------------------------------------------------------
# Phase-4 graceful degradation: no analyzer available
# ---------------------------------------------------------------------------


def test_missing_analyzer_models_returns_warning_not_crash() -> None:
    """Without Presidio/GLiNER installed, the run still succeeds with a warning."""
    request = {"version": 1, "labels": ["TAX_DOC"], "files": []}
    proc = _run_module(
        json.dumps(request),
        extra_env={
            # Point at a module that does not exist — analyzer load should
            # fail gracefully and produce a warning.
            "REDACTOR_CLASSIFY_ANALYZER_FACTORY": "definitely.not.installed",
        },
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    payload = json.loads(proc.stdout)
    assert payload["results"] == []
    assert any("analyzer" in w.lower() for w in payload["warnings"])


def test_factory_raises_returns_warning_with_files(tmp_path: Path) -> None:
    """If the analyzer factory blows up at runtime, we degrade with a warning."""
    pkg = _write_fake_analyzer_module(tmp_path, crash_on_load=True)
    request = {
        "version": 1,
        "labels": ["TAX_DOC"],
        "files": [
            {
                "path": "/tmp/random.txt",
                "filename": "random.txt",
                "size_bytes": 10,
                "content_preview": "Lorem ipsum",
            }
        ],
    }
    proc = _run_module(
        json.dumps(request),
        extra_env={
            "REDACTOR_CLASSIFY_ANALYZER_FACTORY": "fake_factory_pkg.fake_factory",
        },
        extra_pythonpath=[pkg.parent],
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}"
    payload = json.loads(proc.stdout)
    assert payload["results"] == []
    assert any("simulated model load failure" in w for w in payload["warnings"])


def test_response_version_is_one(tmp_path: Path) -> None:
    pkg = _write_fake_analyzer_module(tmp_path, behaviour="empty")
    proc = _run_module(
        json.dumps({"version": 1, "labels": ["TAX_DOC"], "files": []}),
        extra_env={
            "REDACTOR_CLASSIFY_ANALYZER_FACTORY": "fake_factory_pkg.fake_factory",
        },
        extra_pythonpath=[pkg.parent],
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["version"] == 1
