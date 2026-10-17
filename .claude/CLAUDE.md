# CLAUDE.md — agent guidance for this strict-redaction project

This project enforces redaction at every tool boundary. Read this before
issuing any tool call.

## Strict policy active in this project

The `.claude/settings.json` in this project chains five hooks across three
events. Order within each `PreToolUse` matcher is significant — path-guard
runs first so its specific "sensitive path" reason wins.

1. **PreToolUse Bash** → `path-guard.sh`, then `bash-strict.sh`
   - `path-guard` rejects shell commands that touch sensitive paths
     (`.env*`, `id_rsa*`, `.aws/credentials`, `.ssh/*` except `known_hosts`,
     `*.pem`, `*.key`, `**/secrets/**`) — even when wrapped via
     `redactor wrap -- cat .env`.
   - `bash-strict` then rejects every Bash call that does not start with
     `redactor wrap --`. Bare commands and pipe form (`cmd | redactor`)
     are intentionally **rejected**.
2. **PreToolUse Read** → `path-guard.sh`, then `read-strict.sh`
   - `path-guard` blocks the same sensitive-path set as above with a
     specific reason.
   - `read-strict` then blocks **every other Read** as well — the Read tool
     is disabled in strict mode because PreToolUse hooks cannot sanitize
     file contents in-flight, and PostToolUse `additionalContext` is
     additive (the model sees the raw content first). The reject message
     tells the model to use `redactor wrap -- cat <file>` instead, which
     goes through bash-strict (allow) + post-tool-redact (sanitize).
3. **PostToolUse Read|Bash** → `post-tool-redact.sh` (fail-closed)
   Pipes the tool output through redactor. If **any** secret pattern hits,
   the hook returns `decision: "block"` with the sanitized text in the
   reason — so the model only sees the `<redacted:LABEL>`-form, never the
   raw output. Outputs with no matches pass through unchanged.
4. **UserPromptSubmit** → `prompt-scan.sh`
   If a user prompt contains a secret, the prompt is **rejected** with a
   redacted preview.

## How to issue a Bash call here

This project's `bash-strict` hook enforces a **single canonical form**: every
`Bash` tool call must start with either `redactor wrap --` or its short alias
`r wrap --` (8 chars saved per call — same hook, same behavior, same audit log;
see `just install-alias`). The pipe form (`cmd | redactor`) is intentionally
NOT accepted — wrap works in any shell, preserves the wrapped exit code
automatically, and gives the audit log a clean joined-argv `command=` field.

**zsh gotcha:** `r` is zsh's history-recall builtin. To use the alias from a
zsh prompt, either add `disable r` to `~/.zshenv` (works for interactive AND
non-interactive shells), or escape with `\r wrap -- ...`. Bash users can use
`r wrap` directly.

```bash
# CORRECT — only acceptable shape
redactor wrap -- ./run.sh
redactor wrap -- python my_script.py --flag
redactor wrap -- bash -c "./step1 && ./step2"
redactor wrap --keywords "PROJECT-X" -- kubectl logs deploy/api

# REJECTED — bare command
./run.sh

# REJECTED — pipe form (allowed by the underlying redactor binary, but
# blocked here on purpose for consistency)
./run.sh | redactor
```

If your call is rejected with `redactor strict mode: every Bash call must
use 'redactor wrap --'`, the fix is mechanical: prepend `redactor wrap --`
to your command and retry. Do NOT write a shell wrapper that hides the
inner command — the hook reads `tool_input.command` and rejects anything
not starting with `redactor wrap`.

If a command genuinely cannot be wrapped (e.g. it produces binary output a
downstream tool consumes byte-exact), ask the user to add a one-off
exception in `.claude/hooks/bash-strict.sh`.

## Output you will see

Once redacted, secrets show as opaque placeholders:

```text
ERR=<redacted:aws_access_key>
TOKEN=<redacted:github_token>
PASSWORD=<redacted>
customer=<redacted:keyword>
```

Treat these as sealed values. Do **not**:
- Try to reconstruct the original from context
- Ask the user to "share the unredacted version"
- Suggest disabling redaction or the strict-bash hook

If a `<redacted:keyword>` blocks legitimate work (e.g. a customer name in a
log file you actually need to debug), surface that to the user with the
specific token name so they can decide whether to add an exception via
`--no-config` for that specific call.

## How to read files here

The `Read` tool is **fully disabled** in strict mode (read-strict.sh) —
there is no allowlist. Every file, including TOML manifests and lock files,
must go through `redactor` so its content can be sanitized before the model
or the UI sees it.

Use `redactor` directly. The CLI has two modes that both pass `bash-strict`:

### Direct file mode — preferred for structured files

```bash
redactor --type json <file.json>     # structure preserved, leaves -> <redacted>, lists keep first item
redactor --type csv  <file.csv>      # header verbatim, row 2 -> <redacted>, rest dropped
redactor --type env  <file.env>      # KEY=<redacted>, comments/blank lines preserved
redactor             <log-or-text>   # auto-detects mode by extension; falls back to pattern
redactor -n          <file>          # `redactor cat -n` equivalent? No — use wrap for that
```

Direct mode **sanitizes the bytes BEFORE they reach any output stream** —
the user's UI shows the masked version too, not just the model context.
This is the right choice for any file where the structure is interesting
but the values are not (config, secrets stores, exported data).

### Wrap mode — for subprocesses and free-form text

```bash
redactor wrap -- cat <file>          # plain stream of bytes through pattern mode
redactor wrap -- cat -n <file>       # with line numbers (like Read)
redactor wrap -- head -50 <file>     # first 50 lines
redactor wrap -- tail -F <file>      # tail-follow a log
redactor wrap -- ./run.sh            # any subprocess, both stdout+stderr filtered
```

Wrap is line-buffered and runs in **pattern mode only** — it catches
known secret regexes (`sk-…`, `AKIA…`, `ghp_…`, JWTs, PEM blocks, your
keyword list). It does **not** apply structural redaction. For
structured files, prefer the direct file mode above.

### What happens after either form

Both go through:

1. `path-guard` (rejects sensitive paths even when wrapped or direct)
2. `bash-strict` (allows any `redactor …` invocation, blocks bare commands)
3. The redactor itself (sanitizes during execution)
4. `post-tool-redact` (fail-closed safety net — re-runs the
   extension-appropriate redactor mode on the final stdout; if the result
   differs from the raw, blocks with the sanitized text in the reason)

Net effect: the model never sees raw values. With direct file mode, the
**user's UI** also never shows raw values. With wrap+cat for structured
files, the UI shows the wrap-pattern-mode output (structural values still
visible) and the model sees the post-tool-redact'd version — that's a UX
gap to be aware of. Use direct file mode when this matters.

If a binary or non-text file genuinely needs `Read` (image, PDF, notebook),
ask the user to add a one-off exception in `.claude/hooks/read-strict.sh`.

### Knowledge discovery

For thematic search across project notes or PKM wiki, use `redactor search`:

    redactor search "topic"                # default: current project
    redactor search "topic" -a             # extended: PKM wiki + Projects
    redactor search "topic" --format json  # agent-friendly

This is the **canonical first call** when looking for "where did we discuss X" or "have we documented Y" — it ranks results, sanitizes snippets, and audit-logs in one step. Use `Grep` / `redactor wrap -- rg` only when you know the exact symbol or string to find.


## Sensitive-file reads

Reads of `.env`, SSH keys, AWS creds etc. are blocked at PreToolUse. The
block applies to **both**:
- `Read` calls on those paths (`path-guard` on the Read matcher), and
- `Bash` commands that touch those paths, even via `redactor wrap -- cat`
  (`path-guard` on the Bash matcher).

If you genuinely need such a file:

1. Don't try to bypass via `cat`, `head`, `tail`, or shell redirection — the
   `path-guard` + `bash-strict` chain applies to those too.
2. Ask the user explicitly: *"path X is blocked by the path-guard hook —
   can you grant a one-off exception or share the relevant excerpt?"*
3. The user can either:
   - Edit `path-guard.sh` to remove the pattern (project-wide)
   - Provide an excerpt directly in chat
   - Run the command themselves and paste the (already-redacted) output

## Custom keyword list

The user maintains literal terms (customer names, codenames, hostnames) in
`~/.config/redactor/keywords.txt` (or `~/Library/Application Support/redactor/`
on macOS, `%APPDATA%\redactor\` on Windows). These are auto-loaded by every
redactor call.

To see the current list: `redactor config-path`
To edit: `${EDITOR:-vi} ~/.config/redactor/keywords.txt`

Per-call additions: `redactor wrap --keywords "extra-term" -- <cmd>`

## Audit log

Every redaction is logged to `<cwd>/logs/YYYY-MM-DD-redacted.log` (or wherever
`$REDACTOR_LOG_DIR` points). The fields are:

| field | example | meaning |
|-------|---------|---------|
| timestamp | `2026-04-28T01:39:50+02:00` | when |
| source | `wrap:bash` / `stdin` / `path` | input shape |
| command | `bash -c deploy.sh` / `Read test.csv` | what triggered it |
| mode | `pattern` / `wrap` / `csv` / ... | redactor mode |
| rule | `openai_key` / `keyword` / ... | which rule fired |
| count | `1` / `3` | matches in this call |
| sample | `sk-proj-FAKE...` (truncated) | first match |

If you need to debug what the model "should have seen" before redaction, the
user can show you the log — never ask them to disable redaction.
