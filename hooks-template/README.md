# Self-bootstrapping redactor hooks

Drop-in `.claude/` directory for any project. The hook scripts under
`.claude/hooks/redactor/` are committed to the target repo; the redactor
binary itself is downloaded on first hook invocation (idempotently, with
SHA256 verification) and cached under `$RUNNER_TEMP/redactor` (CI) or
`$HOME/.cache/redactor` (local).

## What's in here

```
.claude/
├── settings.json                    ← Claude Code hook config (committed)
└── hooks/redactor/
    ├── _bootstrap.sh                ← idempotent: ensures `redactor` is on PATH
    ├── wrap.sh                      ← thin wrapper used by every hook command
    └── VERSION                      ← pinned redactor version (e.g. 0.6.0)
```

## How it works

Each hook in `settings.json` invokes
`${CLAUDE_PROJECT_DIR}/.claude/hooks/redactor/wrap.sh hook <event>`.

`wrap.sh` sources `_bootstrap.sh`, which:

1. Returns immediately if `redactor` is already on `$PATH` (~1 ms).
2. Returns immediately if a previously-bootstrapped binary lives in the
   cache directory (~5 ms — adds it to `$PATH`).
3. Otherwise downloads the prebuilt binary for the current platform from
   `https://github.com/niclasedge/rust-redactor/releases/download/v$VERSION/`,
   verifies it against `SHA256SUMS.txt` from the same release, extracts it
   to the cache directory, and adds it to `$PATH` (~2–3 s — only on the
   very first hook call of a clean CI runner).

After the first call within a session, every later hook call is back to
~5–10 ms (native binary, no shell overhead beyond the bash wrapper).

## Installing into a target repo

Copy the contents of `hooks-template/` into the target repo root:

```bash
cp -r hooks-template/.claude /path/to/target-repo/.claude
chmod +x /path/to/target-repo/.claude/hooks/redactor/*.sh
```

Or — equivalently, from inside the target repo — once
`redactor install-hooks` learns about this template
([`src/install.rs`](../src/install.rs)):

```bash
redactor install-hooks --strict --bootstrap .
```

(Currently `redactor install-hooks` deploys the legacy
`examples/strict-redaction/` template that assumes `redactor` is already
on `$PATH`. Use the manual copy until the bootstrap variant is wired in.)

Commit the resulting `.claude/` directory. Every developer who clones the
repo, plus every CI runner, will get the hooks active automatically.

## Pinning the redactor version

Edit `.claude/hooks/redactor/VERSION` to point to any released tag (without
the `v` prefix):

```
0.6.0
```

The bootstrap will fetch
`https://github.com/niclasedge/rust-redactor/releases/download/v0.6.0/...`
on first use.

## Cache location

| Environment | Cache path |
|-------------|-----------|
| GitHub Actions runner | `$RUNNER_TEMP/redactor/bin/redactor` |
| Local dev (Linux / macOS / Git-Bash) | `$HOME/.cache/redactor/bin/redactor` |
| Override | `$REDACTOR_CACHE_DIR/bin/redactor` |

The cache survives across hook invocations within a single workflow run /
shell session. CI runners are ephemeral, so each new run does the ~2–3 s
download once.

## What the hooks do

See `examples/strict-redaction/claude/CLAUDE.md` for the full agent-facing
explanation. Short version:

| Event | Hook | Purpose |
|-------|------|---------|
| `SessionStart` | `redactor hook session-start` | audit-log the session, never blocks |
| `UserPromptSubmit` | `redactor hook prompt` | reject prompts containing secrets |
| `PreToolUse` `Bash\|PowerShell` | `redactor hook pre-bash` | path-guard + strict-prefix + struct-file guard |
| `PreToolUse` `Read` | `redactor hook pre-read` | block structured / sensitive reads |
| `PreToolUse` `Grep` | `redactor hook deny-grep` | always block (use `r wrap -- rg` instead) |
| `PreToolUse` `NotebookEdit` | `redactor hook deny-notebook` | always block |
| `PreToolUse` `mcp__.*` | `redactor hook deny-mcp` | always block |
| `PostToolUse` `Write\|Edit` | `redactor hook post-write` | per-extension lint (.json / .toml) |
