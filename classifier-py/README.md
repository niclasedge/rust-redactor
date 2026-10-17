# redactor-classify (Python sidecar)

Python-side companion to the `redactor` Rust CLI. The sidecar runs the
ML-based file classifier (Microsoft Presidio + GLiNER + spaCy) and is
spawned by Rust as a subprocess over stdin/stdout JSON.

> **Phase 3 status:** skeleton only. `__main__` validates the request
> schema and returns a stub response. The real Presidio + GLiNER wiring
> lands in Phase 4 (see `knowledge/plans/2026-05-12-redactorignore-and-classifier-design.html` §P).

## Layout

```
classifier-py/
├── pyproject.toml          # uv-managed, pinned deps
├── README.md               # this file
├── src/classify/
│   ├── __init__.py
│   └── __main__.py         # entry: `python -m classify`
└── tests/
    └── test_stub.py
```

## Wire-up from Rust

The Rust binary spawns the sidecar via the venv created by
`redactor classifier-install`:

```bash
~/.config/redactor/classifier/venv/bin/python -m classify
```

Request (Rust → stdin) and response (stdout) follow the schema in
spec §5.5:

```jsonc
// stdin
{
  "version": 1,
  "labels": ["TAX_DOC", "BANK_STATEMENT", ...],
  "files":  [{ "path": "...", "filename": "...",
               "size_bytes": 1234, "content_preview": "..." }]
}

// stdout
{ "version": 1, "results": [...], "warnings": [...] }
```

Exit codes:

| code | meaning |
|------|---------|
| 0    | success — JSON response on stdout |
| 2    | bad input — schema validation failed; stderr explains |

## Local dev

```bash
cd classifier-py
uv venv
uv pip install -e ".[dev]"
uv run pytest -v
```

The sidecar is not on PyPI. The only supported install path is
`redactor classifier-install`, which creates the venv at
`<config>/classifier/venv` and runs `uv pip install -e <repo>/classifier-py`.
