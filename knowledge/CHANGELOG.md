# Changelog

## 2026-05-12

- **v0.7.0-dev** — `~/.redactorignore` + ML File Classifier release. Spec at `knowledge/plans/2026-05-12-redactorignore-and-classifier-design.html`. Five-phase implementation:
  - **Phase 1**: `src/ignorefile.rs` parser (gitignore-style keyword/path heuristic, globset-backed matching, negation, BOM/CRLF tolerant). `~/.redactorignore` replaces legacy `<config>/keywords.txt` with deprecation warning + `migrate-keywords` helper. Path-guard extended (`hook.rs`): `match_self_protect` (`~/.redactorignore` is unblockable), `match_crypto_container` (`.kdbx`/`.gpg`/`.age`/`.p12`/`.pfx`/`.keychain-db` blocked at Read+Bash), `match_office_doc` (`.xlsx`/`.docx`/`.pdf`/`.pptx` blocked at Read only — `docx`/`xlsx`/`pdf` skills route via Bash), `match_redactorignore_path` (user paths with gitignore-order negation). 27 ignorefile + 17 hook + 5 config = 49 new Rust tests.
  - **Phase 2**: `[allow]` section in `.redactor.toml` for project-level overrides — `paths` (gitignore-style globs) and `filetypes` (extensions). Overrides `.redactorignore` paths + office-doc defaults; **cannot** override self-protect / crypto / `.env`-family (spec §3.3). New `redactor hook pre-edit` subcommand for `Edit|MultiEdit|Write` matcher — primary purpose: block Write from creating new files at protected paths. `examples/strict-redaction/claude/settings.json` v0.5.0 adds the matcher.
  - **Phase 3**: `classifier-py/` Python sidecar skeleton (uv-managed pinned `presidio-analyzer`, `gliner`, `spacy`, CPU-only `torch`; Python `>=3.10,<3.14` for spaCy wheel availability). `src/classify.rs` Rust IPC bridge (`run_classifier(files, labels)` → `NotInstalled` / `Crashed` / `Timeout` / `BadResponse`; `REDACTOR_CLASSIFIER_TIMEOUT_SECS` env var; test override `REDACTOR_CLASSIFIER_PYTHON`). `src/classifier_lifecycle.rs` for `classifier-install / update / status / uninstall` subcommands — install downloads `urchade/gliner_multi_pii-v1` + `de_core_news_sm` + `en_core_web_sm` (~550 MB). 8 Python pytest + 13 Rust tests.
  - **Phase 4**: real Presidio + GLiNER analyzer + `classify-files` subcommand (in progress, parallel subagents).
  - **Phase 5**: `classify-merge`, `migrate-keywords`, decisions.md, release notes (pending).
- New top-level dep: `globset` for gitignore-style path matching.
- `.gitignore` extended: Python venv, pycache, pytest cache, `.claude/worktrees/`.

## 2026-05-03

- **phone_de FP fix** — tightened regex from permissive `[\s\-()/0-9]{5,15}` to digit-counting `(?:[\s\-/()]*\d){5,14}`. Greenshot timestamps (`2026-05-03 17.20.50.png`), dash-form German dates (`28-04-2026`), and ISO datetime strings now pass clean. Real DE phones (`+49 30 12345678`, `030 12345678`) and order-IDs (`0012345678`) unaffected. Old "documented FP" test for dash-dates flipped to a regression assertion. `src/patterns.rs`, `tests/eu_pii_patterns.rs`, `tests/red_team.rs`.

## 2026-05-01

- **v0.6.0** — sectioned search output: `project knowledge / tasks / code / global wiki`. Per-section `--limit` (default 5). Modal flags `--knowledge-only`/`--tasks-only`/`--code-only`/`--wiki-only`. `--no-wiki` opt-out. `-a` deprecated as no-op. JSON schema breaking: top-level `hits[]` → `sections{}` map. Outside-project marker on project sections when cwd is not under `~/GITHUB/<project>/`. Latency: project warm ~30ms, with wiki ~90ms.
- **v0.5.2** — project tasks (title + body + status + phase + priority + notes) added to default search corpus via shell-out to `task list` + `task feed`. Notes filtered client-side by task_id prefix (upstream `--project` flag on `task feed` is broken). Default `--limit` raised 10 → 20. Task hits render as `task://<id>  [status · phase=X · prio=Y]`.
- **v0.5.1** — `r` short-alias for `redactor` binary. Hook accepts both names as bash-strict prefix. Symlink `~/.cargo/bin/r → redactor` via `just install-alias`.
- **v0.5.0** — `redactor search` subcommand. probly-search BM25 with title×3 / tags×2 / content×1 boost + temporal decay (`exp(-0.05 * days_old)`). Snippets sanitized through `redact_pattern` before output. Audit-logged under `source=search:project|global`. Project + global (`-a`) scopes. `--code` mode for source files.
- **Hook fix** — anchored `.key`/`.pem` regex to require path-context (`[/~]\S*` prefix). Prevented false-positives on Rust field access (`r.key;`).
