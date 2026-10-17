# CLAUDE.md — agent guidance for `rust-redactor`

This file is read by AI coding agents (Claude Code, Codex CLI, OpenCode, etc.)
when they operate inside this repo OR inside a project that has `redactor`
wired into its hooks. It documents what the tool does, how to invoke it
correctly, and how to interpret its output.

## What is redactor

A single-binary CLI that scrubs secrets from text and structured files. It is
typically wired as a **pre-tool-use / post-tool-use hook** so that when an
agent reads a file or runs a shell command, sensitive values (API keys,
tokens, customer names, internal hostnames, PEM private keys) are replaced
with placeholders **before they enter the model's context window**.

## Output convention you will see

Redacted content uses placeholder strings the agent must NOT try to "recover"
or reverse:

| Placeholder | Meaning |
|-------------|---------|
| `<redacted>` | structural redaction (CSV cell, JSON leaf, env value) |
| `<redacted:openai_key>` | matched the OpenAI key pattern |
| `<redacted:anthropic_key>` | matched the Anthropic key pattern |
| `<redacted:aws_access_key>` | matched AWS access-key pattern (AKIA…) |
| `<redacted:github_token>` | matched a GitHub PAT (`ghp_`/`gho_`/…) |
| `<redacted:slack_token>` | matched Slack token (`xoxb-`/`xoxp-`/…) |
| `<redacted:stripe_live>` | matched a live Stripe key |
| `<redacted:jwt>` | matched a 3-segment JWT |
| `<redacted:private_key>` | matched a PEM `BEGIN ... PRIVATE KEY` block |
| `<redacted:keyword>` | matched a literal term from the user's keyword list |
| `<redacted:<custom>>` | matched a user-defined regex rule |

When you see these in tool output, treat them as opaque tokens. Do not:
- Try to reconstruct the value from context
- Ask the user to "share the unredacted version"
- Suggest disabling the redactor

If a redaction blocks legitimate work, surface that to the user with the
specific pattern name (`<redacted:keyword>` blocked progress on X) so they
can decide whether to add an exception.


## Knowledge & file discovery — `redactor search`

For ranked, snippet-style discovery across markdown corpora, prefer
`redactor search` over ad-hoc `grep -r` chains.

    redactor search "topic"                          # current project (default)
    redactor search "topic" -a                       # extended: PKM wiki + projects
    redactor search "topic" --code                   # source files in project
    redactor search "topic" --format json --limit 5  # for agent scripts

What it does:
- BM25 ranking with title×3 / tags×2 / content×1 boost
- Temporal decay: newer files rank higher (`exp(-0.05 * days_old)`)
- Snippets pass through redactor's pattern pipeline before output —
  any `<redacted:LABEL>` markers in results came from the snippet itself.
- Audit-logged under `source=search:project` or `source=search:global`.

### Decision matrix — when to use what

| Goal | Tool | Notes |
|---|---|---|
| "Where did we discuss X?" | `redactor search "X"` | **First call** for thematic queries. BM25 + decay + sanitization. ~8ms warm in project scope. |
| Topic across all PKM + projects | `redactor search "X" -a` | Extended scope. ~70ms warm. |
| Find a feature in source files | `redactor search "X" --code` | Walks .rs/.py/.ts/.go/.sh/.toml/.yaml. Filename match * 4 + content count. |
| Exact symbol or call sites of `foo()` | `Grep` / `rg` | rg is ~30x faster; BM25 ranking irrelevant when N=1. |
| Files matching `*.toml` etc | `Glob` / `fd` | Path-pattern, not content-driven. |
| Read entire known file | `Read` (or `redactor wrap -- cat` in strict mode) | search returns snippets only. |
| Quick TODO/FIXME sweep | `rg "TODO|FIXME"` | Deterministic; not thematic. |

**Rule of thumb:** if the question is "what do we know about TOPIC", start with `redactor search`. If you already know which symbol/file/path you want, use Grep/Glob/Read directly. Performance: project scope is 33x faster than the legacy python+node `q` tool; global scope is 3.8x faster (see `knowledge/2026-04-29-search-perf.md`).

## How to invoke redactor

> **Short alias:** `r` is a symlinked alias for `redactor` (created via `just install-alias`). Anywhere you see `redactor wrap --` below, `r wrap --` works identically and saves 8 chars per call. The hook accepts both. Note for zsh users: `r` is the history-recall builtin; either `disable r` in `~/.zshenv` or escape with `\r`.

Two styles. **Wrap is the recommended default for any agent-driven Bash call.**

```bash
# 1) Filter (stdin/file -> stdout)
cat data.csv | redactor                       # auto-detect csv
redactor data.csv                             # same
redactor -t pattern --keywords "alice,bob" -  # stdin, custom keywords
redactor --source-label "Read data.csv" -     # tell the log who called us

# 2) Wrap (run a subprocess, filter both streams, forward exit code)
redactor wrap -- ./run.sh
redactor wrap -- bash -c "./step1 && ./step2"
redactor wrap --keywords "PROJECT-X" -- kubectl logs deploy/api
```

Wrap is preferred because:
- works identically across bash/zsh/fish/cmd.exe/PowerShell
- preserves the wrapped process's exit code automatically
- streams line-by-line (good for `tail -F`, long jobs)
- logs the full argv as `command=...` for audit

## Strict-mode policy you may encounter

When a project enforces strict redaction (see `examples/strict-redaction/`),
its `.claude/settings.json` blocks every Bash call that does not start with
`redactor wrap --`. Pipe form (`cmd | redactor`) is intentionally rejected
in strict mode — wrap is the single canonical form because it works in any
shell, preserves the wrapped exit code automatically, and gives the audit log
a clean joined-argv `command=` field.

```bash
# acceptable — only this shape passes the strict bash hook
redactor wrap -- <your-command>
redactor wrap -- bash -c "./step1 && ./step2"
redactor wrap --keywords "EXTRA-SECRET" -- <cmd>

# REJECTED — bare command
./run.sh

# REJECTED — pipe form (works for the redactor binary, but the strict bash
# hook reads tool_input.command and rejects anything not starting with
# `redactor wrap`)
./run.sh | redactor
```

If your `Bash` call is rejected, reformulate as `redactor wrap -- <cmd>` and
retry. Do NOT try to bypass the hook by writing a wrapper script that hides
the inner command.

## Sensitive paths blocked at PreToolUse

Reads and Bash invocations that target paths matching these patterns will be
denied by the path-guard hook:

- `*.env`, `*.envrc`, `.env.*`
- `id_rsa*`, any file under `.ssh/` except `known_hosts`
- `.aws/credentials`, `.aws/config`
- `**/secrets/**`, `**/*.pem`, `**/*.key`

If you genuinely need such a file, ask the user to add an explicit exception
(via `--no-config` or by editing the path-guard) — do not work around it.

## Structured-file policy

All structured files (`.json` / `.jsonl` / `.ndjson` / `.csv` / `.tsv` /
`.env`) are forced through `redactor --type <mode> <file>` (direct mode)
by default — `pre-read` and the `pre-bash` struct-file guard reject
`Read foo.json` / `cat foo.json` and the equivalents for the other modes.
This is the secure-by-default position: pattern-mode redaction can miss
arbitrary leaf values that don't match a known regex.

**Per-project opt-out for JSON** — if a project legitimately needs raw
JSON reads (Power Automate exports, package manifests, hook-payload
fixtures, agent config inspection, …), drop a `.redactor.toml` at the
repo root:

```toml
[policy]
strict_json = false
```

JSON reads in that project then pass through both `pre-read` and the
`pre-bash` struct-file guards. Content still goes through pattern-mode
redaction on the way out (built-in regexes + your keyword list). The
direct mode (`redactor --type json <file>`) is unchanged and remains the
right tool when leaf-values matter (e.g. exported credential stores).

CSV / TSV / ENV are always strict — no opt-out. Their leaf semantics
(arbitrary cell contents, env-var values) make pattern-mode unsafe.

## The redaction log

Every redaction is appended to `<log-dir>/YYYY-MM-DD-redacted.log` with one
TSV line per rule hit:

```text
2026-04-28T01:39:50+02:00  source=stdin     command=Read test.csv  mode=pattern  rule=github_token  count=1  sample=ghp_abc...
2026-04-28T01:39:50+02:00  source=wrap:bash command=bash -c deploy.sh  mode=wrap   rule=openai_key   count=1  sample=sk-proj-FAK...
```

Fields: `source` (stdin / path / wrap:cmd), `command` (what triggered the
redaction), `mode`, `rule`, `count`, `sample` (first match, ≤ 60 chars).

If you need to verify *what* was redacted to debug a tool's output, the
user can show you the log — never ask for the original unredacted data.

## Installing redactor into a project — local vs. global

### Local install (per-project)

Deploys `.claude/settings.json` + `CLAUDE.md` into `<target>/.claude/`.
Only affects sessions started inside that project directory.

```bash
redactor install-plugin local .           # install in cwd (backup existing .claude/)
redactor install-plugin local --dry-run . # preview without writing
redactor install-plugin local --merge .   # merge hooks only (leaves other settings intact)
redactor install-plugin local --force .   # overwrite without backup

# backward-compatible alias — identical behavior:
redactor install-hooks .
```

### Global install (~/.claude/)

Merges hook entries into `~/.claude/settings.json` and appends/refreshes a
managed block in `~/.claude/CLAUDE.md`. Applies to every Claude Code session
(unless overridden by a project's local settings).

```bash
redactor install-plugin global --dry-run   # preview without writing
redactor install-plugin global             # install (creates timestamped backup)
redactor install-plugin global --force     # skip backup
```

Both commands are **idempotent** — running them twice changes nothing on the
second run.

### As a Claude Code plugin (marketplace)

Alternatively, install redactor as a **Claude Code plugin**. The strict hook
stack ships *inside* the plugin (`hooks/hooks.json`), so enabling the plugin
wires all hooks (no `settings.json` merge) and disabling it removes them
cleanly. The native binary is fetched per-OS by `/redactor:install`.

```text
/plugin marketplace add niclasedge/rust-redactor
/plugin install redactor@hook-redactor
/redactor:install        # fetch the prebuilt binary (Win/macOS/Linux) into the plugin's bin/
```

Commands: `/redactor:install`, `/redactor:status`, `/redactor:uninstall`. Full
details — layout, cross-platform binary delivery, rolling releases — are in
[`docs/claude-code-plugin.md`](docs/claude-code-plugin.md).

> Use **either** the plugin **or** `redactor install-plugin global`, not both:
> each wires the same hooks, so running both makes every hook fire twice.

### Check installation state

```bash
redactor plugin-status                            # local (cwd)
redactor plugin-status --target /path/to/project  # local (specific dir)
redactor plugin-status --global                   # global (~/.claude/)
```

### Uninstall from a local project

```bash
redactor uninstall-plugin .           # removes .claude/
redactor uninstall-plugin --dry-run . # preview only
```

## Repo-level workflow (when working ON redactor itself)

- All changes go through `cargo test`.
- Format: `cargo fmt`. Lint: `cargo clippy --all-targets -- -D warnings`.
- `just ci` runs fmt + lint + test.
- Hook templates ship under `examples/strict-redaction/` (baked into binary
  at compile time via `include_str!`).
- Versioning: bump `Cargo.toml` `version` and tag (`v0.x.y`) per release.

## Strict policy active

This project enforces redaction at the tool boundary for Codex. Read this
before issuing tool calls.

The project-local Codex config lives under `.codex/`:

- `.codex/config.toml` enables the `codex_hooks` feature flag.
- `.codex/hooks.json` wires the strict-redaction hooks.

Hook behavior in this repo:

1. `PreToolUse Bash` → `redactor hook pre-bash`
   - blocks sensitive paths (`.env*`, `.ssh/*` except `known_hosts`,
     `.aws/credentials`, `*.pem`, `*.key`, `/secrets/`)
   - blocks unwrapped shell commands; the canonical form is `redactor wrap -- <cmd>`
   - enforces the optional network allowlist from `.redactor-urls.json`
2. `PreToolUse apply_patch/Edit/Write` → `redactor hook pre-patch`
   - blocks edits that target the same sensitive paths
3. `PreToolUse mcp__*` → `redactor hook deny-mcp`
   - all MCP tools are disabled in this strict profile
4. `PostToolUse apply_patch/Edit/Write` → `redactor hook post-write`
   - validates changed `.json` and `.toml` files after the patch lands
5. `UserPromptSubmit` → `redactor hook prompt`
   - blocks prompts that contain secrets
6. `SessionStart` → `redactor hook session-start`
   - audit slot only, never blocks
