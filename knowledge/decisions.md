# Decisions

Non-obvious choices made during the v0.5.x → v0.7.0 evolution.

---

## v0.7.0 — `.redactorignore` + ML File Classifier (2026-05-12)

Spec: `knowledge/plans/2026-05-12-redactorignore-and-classifier-design.html`

### Python-Sidecar statt Rust-native ML

ML-Klassifikation wird via Python-Subprocess (Presidio + GLiNER + spaCy) gemacht, nicht via Rust-native Inferenz (z.B. `candle`, `burn`). Presidio liefert produktionsreife PII-Aggregation und Confidence-Scoring out-of-the-box; nachgebaut in Rust = mehrere Wochen ohne Mehrwert. GLiNER + spaCy haben keine stabilen Rust-Bindings. Sidecar ist strikt **optional** — Path-Guard und `.redactorignore` funktionieren ohne Python; nur `classify-files` braucht ihn. Trade-off: +1 Python-Dependency (uv vorausgesetzt), +550 MB Disk-Footprint. Akzeptiert.

### Neue `[allow]`-Section, kein Overloading von `[whitelist]`

Project-Level File-Read-Unlocks landen in einer **neuen** `[allow]`-Section in `.redactor.toml`, nicht in der existierenden `[whitelist]`. Begründung: `[whitelist]` bedeutet heute "skip pattern detection in this file" — semantisch eine andere Achse als "allow read/edit of this path". Overloading würde Verwirrung produzieren ("warum wird mein File nicht redacted, ich hab's doch in `[whitelist]` …"). Klare Trennung: `[whitelist]` = Content-Skip, `[allow]` = File-Access-Override. `[allow]` kann **NICHT** unblockable categories überschreiben (self-protect, crypto, .env-family) — per spec §3.3.

### `urchade/gliner_multi_pii-v1` als Default-Modell

Default GLiNER-Model ist `urchade/gliner_multi_pii-v1`. User kann via `config.toml` zu beliebigem GLiNER-Modell wechseln. Begründung: explizit auf PII fine-tuned, multilingual inkl. Deutsch, ~350 MB, MPS-fähig auf Apple-Silicon. Bessere Out-of-the-Box-Qualität als `gliner_multi-v2.1` für PII-Detection. Re-evaluate when: ein neueres Modell mit deutlich besseren PII-Metriken erscheint.

### `~/.redactorignore` ersetzt `keywords.txt` (Hard-Cutover mit Migration-Helper)

Statt zwei parallele Keyword-Quellen, ersetzt `~/.redactorignore` das alte `<config>/keywords.txt` vollständig. Bestehende User kriegen Deprecation-Warning + `redactor migrate-keywords`-Helper. Beide-Files-Existieren ist erlaubt aber `~/.redactorignore` wins (Warning auf stderr). Gitignore-style ist vertraut + erlaubt Mixing von Keywords UND Pfad-Patterns in einem File mit klarer Heuristik.

### `pre-edit`-Hook trotz Read-Block-Indirection

Edit + MultiEdit erfordern in Claude Code einen vorherigen Read der Datei → wenn Read durch path-guard geblockt ist → Edit/MultiEdit indirekt mitgeblockt. **Aber**: Write kann **neue** Files an protected paths erzeugen ohne vorheriges Read. `pre-edit` mit matcher `Edit|MultiEdit|Write` ist primär für Write da. Edit/MultiEdit sind defense-in-depth — falls Claude Code's Read-Before-Edit-Invariante irgendwann fällt.

### Office-Doc-Defaults nur am Read-Tool, nicht an Bash

`.xlsx`/`.docx`/`.pdf`/`.pptx` werden default-mäßig **nur am Read-Tool** geblockt, nicht an Bash. Begründung: Read kann sie nicht sinnvoll parsen (Binär/ZIP-XML — würde Müll dumpen), aber Skills wie `docx`/`xlsx`/`pdf` brauchen Bash-Zugriff für strukturierte Parser. CSV ist explizit ausgeschlossen — der `pre-bash struct-file guard` + `redactor --type csv` covered den Use-Case schon.

### Crypto-Container überall geblockt — ohne `[allow]`-Override

`.kdbx`/`.gpg`/`.age`/`.p12`/`.pfx`/`.keychain-db` werden bei Read UND Bash hard-blockiert und können **nicht** durch `[allow]` überridet werden. Begründung: encrypted containers haben keinen legitimen LLM-readable Use-Case. User muss out-of-session arbeiten (KeePass/gpg/age direkt). Kein Escape-Hatch — Vermeidung der Konsistenz-Schwächung.

### Suggestions-First UX: separates `.suggested`-File, nicht direkter Append

`classify-files` schreibt nach `~/.redactorignore.suggested` (default), nicht direkt nach `~/.redactorignore`. User reviewt explizit per `classify-merge`. Begründung: ML-Output ist non-deterministisch, Review-Phase muss aufmerksam erfolgen, und non-destructive Default minimiert Risiko. Power-User-Shortcut `--apply` für direkten Append vorhanden.

---

## v0.6.x — search-subcommand evolution

## Search engine: probly-search, not Tantivy

Corpus is ~3 MB total (PKM + project + tasks). Walking + indexing in-memory per query takes <30 ms in Rust. Tantivy's persistent on-disk index would buy ~5 ms read time at the cost of (a) lifecycle management, (b) FS-watcher daemon or stale-results, (c) significant code complexity. Re-evaluate when corpus crosses 50 MB or 10 000 docs.

## Tasks always in the default corpus, no `--tasks` opt-in

User explicitly chose "tasks always on" over latency budget. Pays ~30 ms per call (two `task` CLI shell-outs). Rationale: notes contain commit hashes and outcome context that's high-value for "where did we ship X" queries. If `task` CLI is missing → graceful degrade (stderr warn, file-only corpus continues).

## Sectioned output, not interleaved + score-normalized

Empirically tasks dominate the ranking 8-9:1 over markdown when interleaved (BM25 favors short docs with dense tags fields; tasks have all four phase/status/priority/user_tags as searchable, all topical). Tried briefly to fight BM25 via score normalization — too fragile. Sections give per-corpus visibility guaranteed by construction. Trade-off: 4 small ranked lists, no global score order across sections.

## `--limit` is per-section, not total

After sections, `--limit 5` means up to 4×5 = 20 visible hits. Simpler mental model than splitting a global limit proportionally. Default 5 chosen because typical "have we documented X?" queries surface 1-3 strong hits per section; more dilutes signal.

## `-a` flag deprecated as no-op (kept for compat)

Pre-v0.6.0 `-a` flipped scope to global PKM. With four sections, wiki is always shown unless `--no-wiki`. Removing `-a` would break muscle memory; keeping it as a no-op + stderr warn is cheap. Drop in a future major (v1.0).

## `r` alias as symlink, not binary rename

Renaming the `[[bin]]` target in Cargo.toml would break every existing strict-mode hook on disk that hardcodes `redactor` in `bash-strict`. Symlink `~/.cargo/bin/r → redactor` plus accepting both names as hook prefixes is backwards-compatible by construction. Binary stays `redactor`, package stays `redactor`. Justification commit: ca20164.

## `disable r` lives in `.zshenv`, not `.zshrc`

Non-interactive zsh shells (Claude Code Bash tool, scripts, `bash -c "zsh -c …"`) read only `.zshenv`. `.zshrc` is loaded for interactive shells only. The `r` alias must work in both contexts, so the unbinding belongs in `.zshenv`.

## Path-guard regex requires path-context anchor

`\.key($|[^A-Za-z0-9_])` matched any byte sequence with `.key` followed by a boundary, including Rust source `r.key;` and method calls. Anchored to `[/~]\S*\.key($|...)` so only path-like tokens (starting with `/` or `~`) trigger. Trade-off: `cat *.key` (literal glob, no leading slash) is no longer blocked — acceptable since most secret-path uses include `/` or `~`. Same fix applied to `.pem` for symmetry. Commit: 268e3a9.

## phone_de tightened, not deleted

Greenshot timestamps tripped the `\b0` branch of `phone_de` (the `0` of `05` from `2026-05-03 17.20.50` matched, then `5-03 17` ate enough chars to satisfy `{5,15}`). Two ways to fix: drop the `\b0` branch entirely (require `+49`/`0049` country code) or tighten the body to count real digits. Picked the latter — local-format DE phones without country code (`030 12345678`, `Tel: 0123 456789`) are common in source/comments and IDs need to keep matching. Rust regex has no lookahead, so used `(?:[\s\-/()]*\d){5,14}` to enforce 6-15 actual digits with arbitrary separators between them. Dot characters break the chain by construction → timestamps and dot-form dates pass clean. Trade-off: `(030) 12345678` style with both `)` and ` ` survives because `[\s\-/()]*` is greedy across all sep chars, but multi-char non-set sequences (`. `) still break.

## Notes filtered client-side by task_id prefix

`task feed --project <id>` flag is documented but broken upstream — returns cross-project events regardless of scope. Workaround: pull `task feed --limit 1000`, filter `kind=="note"` events whose `task_id` prefix is in the set derived from `task list` (which IS cwd-scoped correctly). Deletable workaround once upstream is fixed.

## Sanitization is mandatory, no `--no-redact` escape hatch

Every snippet — file or task — passes through `redact_pattern` with the resolved rule set before stdout. The point of redactor-search vs `q` is exactly this: agent never sees raw PKM/task content with secrets. If a user wants raw output, they can call `q` directly until that script is retired.
