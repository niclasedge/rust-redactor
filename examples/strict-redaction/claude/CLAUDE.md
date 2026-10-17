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

This project's `bash-strict.sh` enforces a **single canonical form**: every
`Bash` tool call must start with `redactor wrap --`. The pipe form
(`cmd | redactor`) is intentionally NOT accepted — wrap works in any shell,
preserves the wrapped exit code automatically, and gives the audit log a
clean joined-argv `command=` field.

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

### When the struct-file guard blocks (and when it doesn't)

The pre-bash struct-file guard rejects `redactor wrap -- <cmd> <struct-file>`
to force you onto direct mode for `.json`/`.jsonl`/`.ndjson`/`.csv`/`.tsv`/
`.env`/`.envrc`. **JSON can be opted out per-project** by dropping a
`.redactor.toml` at the repo root with:

```toml
[policy]
strict_json = false
```

CSV / TSV / ENV cannot be opted out — pattern-mode is unsafe for arbitrary
cell contents and env-var values. As of rred-35 the check is
**position-aware** — it only fires when a known read-tool consumes the file
as an actual argument, not when the extension appears as a string elsewhere.

| Command | Default policy | With `[policy] strict_json = false` |
|---------|---------------|------------------------------------|
| `r wrap -- cat data.json` | **block** | allow |
| `r wrap -- jq '.k' data.json` | **block** | allow |
| `r wrap -- cat data.csv` | **block** | **block** (no opt-out) |
| `r wrap -- head -50 cfg.csv` | **block** | **block** |
| `r wrap -- tail -F app.env` | **block** | **block** |
| `redactor wrap -- bash -c "cat > x.rs <<EOF … data.json … EOF"` | allow | `data.json` is a string literal in the heredoc, not a file argument |
| `redactor wrap -- echo "see data.csv for details"` | allow | `echo` is not a read-tool |
| `redactor wrap -- sed -i 's\|\.json\|.jsonl\|g' file.rs` | allow | `sed`/`awk`/`grep` deliberately not in the read-tool list (too noisy) |
| `redactor wrap -- task add 'fix .json parsing'` | allow | `task` is not a read-tool; `.json` is just text in the title |
| `redactor wrap -- python my_script.py --output data.csv` | allow | `python` is not a read-tool |

The guard is a **heuristic, not a bash parser**. If a future false-positive
turns up, raise it as a follow-up task — extending the read-tool list or
adding a quote/heredoc-stripping pre-pass is straightforward.

## Disabled tools in this profile

The following tools are **always blocked** at PreToolUse with a fixed-deny
matcher (no per-call check, no payload inspection — the answer is always
"no"). The reasons returned to Claude include the canonical replacement
where one exists.

| Tool | Why disabled | Replacement |
|------|--------------|-------------|
| `mcp__*` (every MCP tool) | High-density PII (Gmail, Drive, Memory, ...) returned directly into Claude's context, no per-server redaction layer here | none in this profile — ask the user to remove the `deny-mcp` matcher for the session if you genuinely need an MCP tool |
| `Grep` | Bypasses the Read+path-guard chain — matching lines from `.env`/`*.pem`/`/secrets/` would arrive in the model context unfiltered | `redactor wrap -- rg "<pat>" <path>` or `redactor wrap -- grep -r "<pat>" <path>` via Bash. Goes through `pre-bash` and wrap pattern-mode. |
| `NotebookEdit` | Not used in this profile; would add a code-and-output read/write path that no current hook sanitizes | none — ask the user to remove the matcher if a notebook genuinely needs editing |

`PowerShell` is NOT disabled — it's hooked under the same `pre-bash`
matcher as `Bash` (`Bash|PowerShell`). The same rules apply: every call
must start with `redactor wrap …` or `redactor --type X …`, the path-guard
applies, the struct-file guard applies. On Windows / when
`CLAUDE_CODE_USE_POWERSHELL_TOOL=1` is set, you'll see the strict-prefix
message refer to "Bash / PowerShell" — both routes are equivalent.

`Monitor` is intentionally NOT hooked. It runs background commands and
streams output line-by-line back to Claude. If you need to tail a log,
prefer `redactor wrap -- tail -F <log>` via Bash so wrap's pattern-mode
sanitizes the stream.

## Recommended workflow in this profile

This is the **operational manual** for working in a project that has
strict-redaction wired in. Follow it from the top.

### 1. Default mindset

- Treat every value with a `<redacted:…>` placeholder as **opaque and sealed**.
  Do not try to reconstruct it from context, do not ask the user to "share the
  unredacted version", do not suggest disabling the redactor.
- Treat every refusal from a pre-hook as **load-bearing**. If `pre-bash` says
  "use direct mode for .csv", reformulate to direct mode — do not write a
  shell wrapper that hides the inner command.
- The redactor is **fail-closed**. An empty / malformed hook payload blocks.
  A network-guard config that fails to parse blocks. This is by design.

### 2. Reading files — decision tree

```
Need to look at a file?
├─ Structured (.json / .jsonl / .csv / .tsv / .env / .envrc)
│  └─ redactor --type <mode> <file>          ← direct mode, sanitizes pre-stdout
│  └─ JSON exception: `.redactor.toml` with `[policy] strict_json = false`
│     allows regular Read / `r wrap -- cat <file>` for that project
│
├─ Free text (.log / .txt / .md / source code)
│  └─ redactor wrap -- cat <file>            ← pattern-mode sanitizer in line buffer
│  └─ redactor wrap -- head -50 <file>       ← partial reads, same path
│  └─ redactor wrap -- tail -F <file>        ← live tail, line-buffered
│
├─ Sensitive (.env / .ssh/ / .aws/ / *.pem / *.key / /secrets/)
│  └─ STOP. Path-guard blocks this. Ask the user to paste an excerpt.
│
└─ Notebook / binary / non-text
   └─ STOP. Read is disabled. Ask the user for an excerpt or
      a temporary exception in .claude/settings.json.
```

### 3. Running commands

Every Bash / PowerShell call MUST start with `redactor `. The two acceptable
shapes:

```bash
# A. Wrap a subprocess (most calls)
redactor wrap -- <your-command>
redactor wrap -- bash -c "<step1> && <step2>"
redactor wrap --keywords "EXTRA-CODENAME" -- <your-command>

# B. Direct mode for structured files
redactor --type json <file.json>
redactor --type csv  <file.csv>
redactor --type env  <file.env>
```

Anything else gets blocked by `bash-strict`. The blocker message tells you
the canonical replacement — apply it mechanically.

### 4. Searching code — Grep is disabled

The `Grep` tool is blocked. Use Bash:

```bash
redactor wrap -- rg "<pattern>" <path>      # preferred
redactor wrap -- grep -r "<pattern>" <path> # fallback
```

This routes through `pre-bash` (path-guard prevents you from grepping inside
`.env` / `/secrets/`) and through `wrap` pattern-mode (any matching line
that contains a known secret is redacted before you see it).

### 5. Web access — narrow allowlist

The network-guard reads `.redactor-urls.json` (walking up from cwd). When
present:

- Only domains in `erlaubte_domains` (glob-supported, e.g. `*.github.com`) pass
- Specific URLs in `erlaubte_urls` are matched by substring
- `blockierte_domains` always wins, even against an allowlist match
- `fail_closed: true` means: if neither allowlist matches, block

If you need to fetch a URL that isn't allowlisted, ask the user to extend
`.redactor-urls.json` — don't pipe the URL through `bash -c 'echo …'` to
hide it. The hook reads the literal command string.

### 6. When you genuinely need protected data — ask the user

If a task legitimately needs the value of a secret (debugging an auth flow,
verifying a config, reproducing a customer issue), the workflow is:

> **Don't try to read `.env` / SSH keys / cred files.** Ask the user to
> paste the relevant value into the chat.

The user's paste flows through `UserPromptSubmit` → `prompt-scan`, which
also runs the secret patterns. Two outcomes:

- **The value isn't a known secret pattern** (e.g. customer name, ticket ID,
  test data) → passes cleanly into your context, you can use it.
- **The value matches a secret pattern** (sk-…, AKIA…, ghp_…, JWT, PEM
  block) → the prompt is REFUSED with a redacted preview. The user should
  remove the secret and paste a placeholder, or the user can grant a
  one-shot exception by temporarily disabling the prompt hook.

### 7. Writing files

`Write` and `Edit` are not hooked at PreToolUse — you can write whatever.
The only PostToolUse coverage is `post-write` for `.json` / `.toml` files,
which validates syntax (a pre-existing edit producing invalid JSON is
flagged so you fix it).

Two operational rules:

- **Don't write secrets to files.** If you find yourself about to write a
  literal API key into source code, that's a bug — write a placeholder and
  document the env-var name.
- **Don't write to `.env*` / `.aws/credentials` / `.ssh/`.** These are
  blocked at PreToolUse Read but NOT at PreToolUse Write today; treat that
  as a self-discipline rule.

### 8. Disabled tools — quick reference

| Tool | What you do instead |
|------|---------------------|
| `Read` | `redactor --type X <file>` (struct) or `redactor wrap -- cat <file>` (free text) |
| `Grep` | `redactor wrap -- rg "<pat>" <path>` via Bash |
| `NotebookEdit` | not used in this profile — ask user to remove the matcher if needed |
| `mcp__*` | not used in this profile — ask user to remove `deny-mcp` for the session |

`PowerShell` is allowed, hooked under the same rules as Bash. `Monitor` is
not hooked — prefer `redactor wrap -- tail -F` for log-following.

## False-positive surface — known gotchas

The default rules are tuned for catching real secrets, not for being
maximally precise. The following legitimate inputs DO get redacted today.
The right response is usually to reformulate, not to disable the rule.

| Input shape | Redacted as | Why | Workaround |
|-------------|-------------|-----|------------|
| `28.04.2026` (German date DD.MM.YYYY) | `<redacted:birthdate>` | matches German birthdate regex | use ISO 8601 `2026-04-28` |
| `28/04/2026` (German date with slashes) | `<redacted:birthdate>` | same regex | use ISO 8601 |
| `1.2.3.4` (version string) | passes clean if quoted (`'1.2.3.4'`, `"1.2.3.4"`) or preceded by a version vocab word (`version`/`ver`/`v`/`build`/`rev`/`release`/`semver`/`tag`); otherwise `<redacted:ipv4>` | contextual ipv4 FP-filter | reformulate (`v1.2.3.4`, `1.2.3-4`) **or** add the missing vocab word |

The following inputs PASS cleanly (verified in `tests/red_team.rs`
section 9):

- ISO 8601 dates `2026-04-28` and datetimes `2026-04-28T20:50:00+02:00`
- Private/loopback IPs (`192.168.x.x`, `10.x.x.x`, `127.x.x.x`,
  `172.16-31.x.x`) — the smart FP-filter exempts RFC1918 ranges
- UUIDs (`550e8400-e29b-41d4-a716-446655440000`)
- Git commit hashes (short or full hex)
- `example.com` / `example.test` / `example.org` / `localhost` /
  `noreply@…` substrings — substring whitelist
- Test IBAN starting with `DE00…`
- Order IDs / SKUs without spaces and without leading `0` followed by space

Treat false-positives as a "rewrite to unambiguous shape" problem. The
strict-redaction posture deliberately errs on the side of false positive
over false negative.

## Filter tuning — where to change behavior

The redactor has three layers of configuration. Use the layer that matches
the scope of the change.

### Layer 1 — Project-local (preferred for one-off rules)

`.redactor.toml` in your project root (walking up from cwd):

```toml
# Add a project-specific rule
[[patterns.custom]]
name = "internal_ticket"
re = '\bINT-\d{6}\b'
sub = "<redacted:ticket>"

# Whitelist paths so path-guard doesn't block them.
# These globs WIN against the sensitive-path regex set.
[whitelist]
paths = [
    "docs/example.cfg",       # exact path
    "fixtures/*.crt",         # glob
    "tests/data/.env.fixture" # exact .env-shaped fixture
]

# Override mode detection for non-standard extensions
[modes]
".tmpl"        = "json"
".env.example" = "env"
```

`[whitelist] paths` is the right escape hatch when path-guard refuses a
file you legitimately need (test fixture, documentation example, etc.).
Globs supported: `*` and `?`.

### Layer 2 — User-global (your terms across all projects)

`~/.config/redactor/keywords.txt` (or `$REDACTOR_CONFIG_DIR/keywords.txt`):

```
# One literal term per line. Case-insensitive. Replaced with <redacted:keyword>.
ACME-INTERNAL
PROJECT-DOLPHIN
customer-mueller
```

Display path: `redactor config-path`. Edit:
`${EDITOR:-vi} $(redactor config-path)/keywords.txt`. Auto-loaded by every
redactor call.

`patterns.json` in the same directory adds custom regex rules globally:

```json
[
  {"name": "internal_jira", "re": "\\bACME-\\d{4}\\b", "sub": "<redacted:jira>"}
]
```

### Layer 3 — Per-call override (single command, no persistence)

```bash
# Add ad-hoc keywords for this one call
redactor wrap --keywords "EXTRA-CODENAME,SECRET-WORD" -- <command>

# Disable user-global keywords + custom patterns for this one call
# (still applies the 17 built-in default rules)
redactor --no-config <file>

# Disable the 17 built-in defaults (last resort — pattern-mode becomes a no-op
# unless --keywords or .redactor.toml supplies rules)
redactor --no-defaults <file>
```

`--no-defaults` and `--no-config` are blocked when applied to a structured
file (`.json`/`.csv`/`.env`) — the pre-bash flag-bypass guard refuses them.
JSON can be opted out per project via `[policy] strict_json = false` in
`.redactor.toml`. For a free-text file you can use either.

### What you CAN'T tune without recompiling

These live in the binary and require a code change in `src/patterns.rs` or
`src/hook.rs`:

- The built-in default patterns (anthropic_key, openai_key, …, ipv4,
  birthdate_de, iban_de, …)
- The path-guard sensitive-path regex set (.env, id_rsa, .aws/, .ssh/,
  .pem, .key, .netrc, /secrets/)
- The smart FP-filter (private-IPv4 exemption, DE00-prefix IBAN exemption,
  example.com substring whitelist)
- The READ_TOOLS list in `detect_struct_file_argument`
- The strict-prefix requirement (`redactor ` literal at start)

### Decision rule for tuning

| Symptom | Layer to touch |
|---------|----------------|
| One specific test fixture blocked by path-guard | Layer 1 — `[whitelist] paths` in `.redactor.toml` |
| Project-specific term should always be redacted | Layer 1 — `[[patterns.custom]]` or Layer 2 — keywords.txt |
| Personal codename across all your projects | Layer 2 — keywords.txt |
| One-off command needs an extra keyword | Layer 3 — `redactor wrap --keywords "…"` |
| Built-in pattern is too eager (e.g. birthdate_de) | Document a workaround in your CLAUDE.md, OR open a PR to refine the regex in `src/patterns.rs` |
| New legit shape getting flagged as FP | First check `tests/red_team.rs` section 9 — if it isn't there yet, add a test asserting expected behavior, then tune |

If the same false positive keeps biting, that's signal to refine the
underlying regex rather than papering over it with whitelist entries.

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
