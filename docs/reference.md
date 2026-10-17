# redactor — reference

Single-binary Rust CLI that scrubs secrets from text and structured files. Built
to slot into agent-CLI **pre-tool-use / post-tool-use hooks** (Codex, OpenCode,
Claude Code) so the LLM never sees raw API keys, tokens, PEM blocks, or whole
secret files.

## Quickstart (2 minutes)

### 1. Install the redactor binary

```bash
git clone https://github.com/niclasedge/rust-redactor
cd rust-redactor

just install                       # cargo install --path . under the hood
just install-alias                 # symlinks `r` -> `redactor` (shorter hook commands)
```

Without `just`:

```bash
cargo install --path .
ln -s "$HOME/.cargo/bin/redactor" "$HOME/.cargo/bin/r"
```

> **zsh users:** `r` is the history-recall builtin — add `disable r` to
> `~/.zshenv` (works for interactive **and** non-interactive shells) so the
> symlink wins. Bash is fine as-is.

Once GitHub releases are live, the prebuilt binary works without rustup:

```bash
# Linux / macOS — replace TARGET with your triple, e.g. x86_64-unknown-linux-musl
curl -L https://github.com/niclasedge/rust-redactor/releases/latest/download/redactor-VERSION-TARGET.tar.gz | tar -xz
```

### 2. Smoke test

```bash
echo "OPENAI_API_KEY=sk-proj-realtoken123abcdefgh" | redactor
# → OPENAI_API_KEY=<redacted:openai_key>

r wrap -- echo "github=ghp_realtokenwouldbeahere1234567890"
# → github=<redacted:github_token>
```

### 3. Wire into Claude Code

**Per-project install** (recommended starting point — drops `settings.json` +
`CLAUDE.md` into the project's `.claude/`):

```bash
cd /path/to/your/project

# New canonical command:
redactor install-plugin local .

# Backward-compatible alias (identical behavior):
redactor install-hooks .
```

Preview what would be written without touching the filesystem:

```bash
redactor install-plugin local --dry-run .
```

Merge only missing hooks into an existing `.claude/settings.json` (leaves other
settings untouched, no backup needed):

```bash
redactor install-plugin local --merge .
```

**Global install** (every Claude Code session uses redactor unless overridden by
a project's local `.claude/settings.json`):

```bash
# Preview first — no writes:
redactor install-plugin global --dry-run

# Install: merges hooks into ~/.claude/settings.json (timestamped backup
# created automatically), appends a managed block to ~/.claude/CLAUDE.md:
redactor install-plugin global
```

The global install is idempotent — running it a second time adds 0 hooks and
reports the managed block as already up-to-date.

**As a Claude Code plugin** (alternative to the global install — the hooks ship
inside the plugin, so enabling/disabling it wires/unwires them, and the native
binary is fetched per-OS by `/redactor:install`):

```text
/plugin marketplace add niclasedge/rust-redactor
/plugin install redactor@hook-redactor
/redactor:install
```

See [`docs/claude-code-plugin.md`](docs/claude-code-plugin.md) for the full
plugin workflow. Use either the plugin **or** `install-plugin global`, not both.

**Check installation state:**

```bash
redactor plugin-status                          # local (cwd)
redactor plugin-status --target /path/to/proj  # local (specific dir)
redactor plugin-status --global                 # ~/.claude/
```

**Uninstall from a local project:**

```bash
redactor uninstall-plugin .           # removes .claude/
redactor uninstall-plugin --dry-run . # preview only
```

Then **restart Claude Code**. The hook matchers fire from any cwd:

| Event | Matcher | Subcommand |
|-------|---------|------------|
| SessionStart | — | `redactor hook session-start` |
| UserPromptSubmit | — | `redactor hook prompt` |
| PreToolUse | `Bash\|PowerShell` | `redactor hook pre-bash` |
| PreToolUse | `Read` | `redactor hook pre-read` |
| PreToolUse | `Edit\|MultiEdit\|Write` | `redactor hook pre-edit` *(v0.7+)* |
| PreToolUse | `Grep` | `redactor hook deny-grep` |
| PreToolUse | `NotebookEdit` | `redactor hook deny-notebook` |
| PreToolUse | `mcp__.*` | `redactor hook deny-mcp` |

On macOS and Windows, every hard block also fires a top-right desktop
notification (sound `Sosumi` on macOS, `Reminder` on Windows) so the user
sees what was blocked and why. Linux gets the toast without a sound (system
default). Suppress with `REDACTOR_NOTIFY=0` (useful in CI / batch runs).
Implementation: a single `notify-rust` call covering all three platforms —
no separate osascript / WinRT / libnotify code paths.

When the **UserPromptSubmit** hook blocks because the prompt contains a
secret or keyword, the redacted version is automatically copied to the
system clipboard (Win/Mac/Linux via `arboard`) — paste with `Ctrl+V` /
`Cmd+V` to resubmit without manually fixing the offending value. Suppress
with `REDACTOR_CLIPBOARD=0`.

### 4. Personal keyword list

Add customer / codename / hostname terms that should always be masked:

```bash
redactor init-config
${EDITOR:-vi} "$(redactor config-path | grep keywords_file | head -1 | cut -d= -f2 | cut -d' ' -f1)"
```

**Per-project rules** — drop a .redactor.toml at the repo root:

```toml
[[patterns.custom]]
name = "internal_id"
re = 'INT-\d{6}'

[whitelist]
paths = ["docs/example.cfg"]

[modes]
"tf" = "pattern"

# Opt out of strict JSON read-policy for this project
# (Power Automate exports, package manifests, hook-payload fixtures, …):
[policy]
strict_json = false
```

For the network-guard: drop a .redactor-urls.json:

```json
{
  "erlaubte_domains": ["github.com", "*.crates.io", "*.anthropic.com"],
  "blockierte_domains": [],
  "fail_closed": true
}
```

Without the URL whitelist file, the network-guard is disabled (opt-in).

## Features

- 4 modes: `csv` (header + redacted row), `json` (structure preserved, leaves redacted),
  `env` (keys kept, values redacted), `pattern` (regex scrubbing for arbitrary text).
- `auto` mode picks by file basename/extension. `.env` / `.envrc` / `.env.*`
  basenames detected even without suffix.
- Built-in patterns for OpenAI, Anthropic, AWS, GitHub, Slack, Stripe, JWTs,
  PEM private keys, and generic `password=...` / `api_key: ...` assignments.
- Custom regex rules via JSON file; literal keyword list via `--keywords`.
- **Append-only daily log** at `<log-dir>/YYYY-MM-DD-redacted.log` showing
  exactly what was redacted, when, where, and a truncated sample.

## Install

### Recommended: via `just`

```bash
git clone https://github.com/niclasedge/rust-redactor.git
cd rust-redactor

# macOS / Linux / Windows (PowerShell or cmd)
just install               # installs to ~/.cargo/bin/redactor

# macOS only — system-wide install
just install-system        # /usr/local/bin/redactor (sudo)

# Windows alternative
just install-win           # %USERPROFILE%\.cargo\bin\redactor.exe
```

If you don't have `just`:

```bash
brew install just                     # macOS
winget install --id Casey.Just        # Windows
cargo install just                    # any platform
```

### Without `just`

```bash
cargo install --path .                # all platforms
```

### Verify

```bash
redactor --version
echo "key=sk-proj-fake1234567890abcdefghij" | redactor
# → key=<redacted:openai_key>

redactor wrap -- echo "AKIAIOSFODNN7EXAMPLE"
# → <redacted:aws_access_key>
```

## Robustness — which invocation to use?

| Style | Cross-platform | Exit code preserved | Streaming | Best for |
|-------|---:|---:|---:|---|
| `cmd \| redactor` | bash/zsh/fish/PowerShell | needs `PIPESTATUS` / `pipefail` | yes (line buffered) | quick interactive use, bash scripts |
| **`redactor wrap -- cmd`** | **all shells, all OS** | **automatic** | **yes** | **hooks, CI, Windows, the default choice** |
| `redactor file.csv` | all | n/a | no (full read) | one-shot file scrubbing |

**Recommendation: prefer `redactor wrap` for anything that runs unattended**
(hooks, CI, scheduled jobs, Windows). Use the pipe form only for ad-hoc Bash
use where you already have your shell-fu sorted.

## CLI

```text
redactor [FILE] [OPTIONS]                      # filter mode (stdin/file → stdout)
redactor wrap [OPTIONS] -- <cmd> [args...]     # wrap mode (run cmd, filter both streams)
redactor init-config [--force]                 # write starter config files
redactor config-path                           # print where config lives

OPTIONS:
  -t, --type <csv|json|env|pattern|auto>
      --patterns <FILE>           JSON [{"name","re","sub"?}]
      --keywords <list>           comma-separated literal terms (case-insensitive)
      --keywords-file <FILE>      .txt (line-per-keyword) or .json (string array)
      --no-defaults               skip built-in regex patterns
      --no-config                 skip auto-loading from config dir
      --log-dir <DIR>             override log location
      --no-log                    disable logging
```

### `redactor search <query>`

Ranked full-text search over markdown corpora with sanitized snippets.

    redactor search "rust async"                  # current project
    redactor search "rust async" -a               # PKM wiki + projects
    redactor search "redact_pattern" --code       # source files

Flags:
- `-a`, `--all` — extend to global scope (PKM wiki + projects, configurable via `REDACTOR_SEARCH_GLOBAL_ROOTS`)
- `--code` — search source files (`.rs/.py/.js/.ts/.go/.sh/.toml/.yaml`) instead of markdown
- `--limit <N>` — max results (default 10)
- `--format text|json|yml` — output format (default text)
- `--no-decay` — disable temporal scoring
- `--decay <rate>` — override decay rate (default 0.05)

Snippets are sanitized through redactor's pattern engine before render — secrets in PKM notes are masked just like any other tool output. Audit log entries appear under `source=search:project` or `source=search:global`.


## Personal sensitivity list — `~/.redactorignore` (v0.7+)

The canonical place for your **personal** literal keywords AND personal
protected file paths. One file, gitignore-style syntax, self-protected
(tools cannot Read or Write it via Claude Code / Codex / etc. — only your
editor in a separate terminal can edit it).

`~/.redactorignore` **replaces** the older `<config>/keywords.txt` as of
v0.7.0. If both exist, only `~/.redactorignore` is used (with a warning).
Run `redactor migrate-keywords` to retire the legacy file.

### Format

```text
# ~/.redactorignore
# Lines starting with # and blank lines are ignored.

# === Keywords (literal terms, case-insensitive match) ===
Alice Mustermann
PROJECT-NIGHTHAWK
internal-host.corp

# === Paths (gitignore-style globs) ===
~/Documents/Steuer/
~/Documents/Personalakten/**
*.kdbx
~/Projects/kunde-X/legal/*

# === Negation (re-allow a previously matched path) ===
!~/Documents/Steuer/musterbeleg.pdf

# === Escape hatch for keywords that look like paths ===
"https://example.com/internal-route"
```

**Heuristic per line**:
1. Empty / `#` comment → skipped.
2. Leading `!` → negation (path entries only).
3. Wrapped in `"..."` → forced to be a **keyword** (escape hatch).
4. Contains `/`, `\`, `~`, or a glob char (`*`, `?`, `[`) → **path pattern**.
5. Otherwise → **keyword**.

### What happens

| Entry type | Effect |
|------------|--------|
| Keyword (e.g. `Alice Mustermann`) | Replaced with `<redacted:keyword>` in every tool output |
| Path pattern (e.g. `~/Documents/Steuer/**`) | `Read` and `Bash` tool calls touching that path are **blocked** |
| `~/.redactorignore` itself | **Self-protected** — `Read`, `Edit`, `MultiEdit`, `Write`, and `Bash` are all blocked from touching it |

### Default extra blocks (v0.7)

In addition to the existing path-guard (`.env`, `.ssh/`, `.aws/credentials`, `.pem`, `.key`, `/secrets/`), v0.7 adds:

- **Crypto containers** (`.kdbx`, `.kdb`, `.gpg`, `.pgp`, `.asc`, `.age`, `.p12`, `.pfx`, `.keychain-db`) — blocked at **Read AND Bash**. No `[allow]` override.
- **Office docs** (`.xlsx`, `.xls`, `.xlsm`, `.docx`, `.doc`, `.pptx`, `.ppt`, `.pdf`) — blocked at **Read only** (Bash still works, so the `xlsx` / `docx` / `pdf` skills can parse them structurally). Project-level `[allow]` can override.

### Project-level overrides — `.redactor.toml [allow]`

To unblock specific files **just for the current project**, add to `.redactor.toml`:

```toml
[allow]
# gitignore-style globs that bypass v0.7 path-guard extensions
paths = [
    "fixtures/sample-customer.xlsx",
    "fixtures/**/*.docx",
    "data/test-fixtures/*",
]
# whole file types — re-enables office-doc reads in this project
filetypes = ["xlsx", "docx"]
```

`[allow]` overrides `.redactorignore` user paths and office-doc defaults.  
It **cannot** override: `~/.redactorignore` self-protect, crypto containers, or the hardcoded `.env`-family.

## ML-based file classification (v0.7+) — `redactor classify-files`

Optional companion subcommand that walks a directory, uses Microsoft
Presidio + GLiNER (zero-shot NER) to detect sensitive files, and writes
suggestions you can review and merge into `~/.redactorignore`.

The classifier runs as a Python sidecar under `<config>/classifier/`.
It is strictly **optional** — `.redactorignore` works without it.

### Install

```bash
redactor classifier-install     # creates uv venv, downloads ~550 MB of models
redactor classifier-status      # show install state, model versions, disk usage
redactor classifier-uninstall   # cleanup
```

Requires `uv` on PATH. Python `>=3.10,<3.14` (spaCy wheel constraint).
Models downloaded by default:

- GLiNER: `urchade/gliner_multi_pii-v1` (~350 MB, multilingual PII)
- spaCy: `de_core_news_sm` + `en_core_web_sm` (~100 MB)

Override the model via `<config>/classifier/config.toml`.

### Use

```bash
# Walk a directory, classify each file, write suggestions
redactor classify-files ~/Documents/

# Useful flags
redactor classify-files ~/Documents/ \
    --max-depth 3 \              # default unlimited
    --max-file-size 10MB \       # default 5 MB
    --threshold 0.7 \            # default 0.6
    --output ~/.redactorignore.suggested \   # default
    --format text                # text | json | yaml

# Review suggestions interactively and append to ~/.redactorignore
redactor classify-merge ~/.redactorignore.suggested

# Non-interactive
redactor classify-merge ~/.redactorignore.suggested --yes
redactor classify-merge ~/.redactorignore.suggested --dry-run
```

The walker pre-filters: `.git`, `.venv`, `node_modules`, `__pycache__`,
`target`, `dist`, `build`, hidden dirs, symlinks, files larger than
`--max-file-size`, binary files (NUL byte in first 1 KB), and crypto
containers (already hardcoded-blocked).

### Output format

```text
# redactor classify-files — suggestions
# generated: 2026-05-13T10:00:00+02:00
# input:     /Users/x/Documents
# files:     1247 scanned, 89 above threshold
# threshold: 0.6

# confidence=0.92  labels=TAX_DOC,FINANCIAL_RECORD
# evidence="Detected 'Einkommensteuer' (TAX_DOC, score=0.94), …"
/Users/x/Documents/Steuer/2024/erklaerung.pdf
```

`classify-merge` parses this format back, asks `y/n/s/q` per entry, and
appends accepted paths to `~/.redactorignore` (dedup'd against existing
entries, no comment propagation).

### Exit codes

| Scenario | Exit |
|----------|------|
| Successful run | 0 |
| Classifier sidecar not installed | 2 |
| Classifier crashed | 3 |
| Classifier timeout (partial results written + warning) | 0 |
| Input directory missing | 4 |

## Config dir — keywords + custom patterns persist across calls

Long-lived keyword lists (customer names, internal codenames, hostnames) and
custom regex rules live in a config directory. They're loaded **automatically**
on every redactor invocation — no flags needed.

**Default location** (set `$REDACTOR_CONFIG_DIR` to override):

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/redactor/` |
| Linux | `~/.config/redactor/` |
| Windows | `%APPDATA%\redactor\` |

**Files inside:**
- `keywords.txt` — one literal term per line, `#` comments OK
- `patterns.json` — `[{"name":"x","re":"...","sub":"..."}]` extra regex rules

**Bootstrap:**

```bash
redactor init-config       # writes starter files (idempotent)
redactor config-path       # show where they live
just edit-keywords         # open in $EDITOR
```

**Example `keywords.txt`:**

```text
# Customers (one per line, case-insensitive match)
Alice Mustermann
Bob Schmidt

# Project codenames
PROJECT-NIGHTHAWK

# Internal hosts
internal-host.corp
```

After this, **every** redactor call (filter or wrap) automatically scrubs these
terms — no `--keywords` flag needed. Use `--no-config` to bypass.

### `--keywords-file FILE` — ad-hoc lists

For one-off use (e.g. an export from your CRM):

```bash
# Plain text — recommended
echo "kunden.txt format:"
cat <<EOF > kunden.txt
Alice Mustermann
Bob Schmidt
Carol Weber
EOF
./run.sh | redactor --keywords-file kunden.txt

# JSON array of strings — works too
cat <<EOF > kunden.json
["Alice Mustermann","Bob Schmidt","Carol Weber"]
EOF
./run.sh | redactor --keywords-file kunden.json
```

**Format choice — why `.txt` is the default recommendation:**

| Format | Pro | Contra |
|--------|-----|--------|
| `.txt` (default) | trivial to write/edit, comments via `#`, blank lines OK, plays nicely with `cat`/`sort`/`uniq`/`xargs` | no metadata |
| `.json` array | structured, can be produced by `jq -r '.[].name'` from a CRM export | escaping, no comments |
| `--patterns FILE` (separate flag) | full regex + custom replacement labels | for non-literal patterns only |

For a CRM export like `customers.json` with objects, transform first:

```bash
jq -r '.[].name' customers.json > ~/.config/redactor/keywords.txt
```

- `FILE` — path or `-` for stdin (default).
- `--type` — force mode. Default: `auto` (detect by ext; falls back to `pattern` for stdin).
- `--patterns FILE` — JSON `[{"name":"...","re":"...","sub":"..."}]` extra rules.
- `--keywords w1,w2` — literal terms scrubbed case-insensitively.
- `--no-defaults` — skip built-in patterns (only custom + keywords).
- `--log-dir DIR` — override log location (default: `$REDACTOR_LOG_DIR` or `./logs/`).
- `--no-log` — disable the daily log.

## Logging — what/when/where

Every redaction appends one TSV line to today's log. Fields:

- `source` — `stdin` / file path / `wrap:<cmd>`
- `command` — what triggered the redaction. **Wrap mode** auto-fills the joined
  argv (e.g. `bash -c "deploy.sh"`); **filter mode** takes it from the
  `--source-label` flag (e.g. a hook passes `--source-label "Read test.csv"`).
  Default `-` when no label is supplied.
- `mode` — `csv` / `json` / `env` / `pattern` / `wrap`
- `rule` — which built-in or custom rule fired
- `count` — number of matches replaced in this call
- `sample` — first match (truncated to 60 chars), so you can audit

```text
2026-04-28T01:17:22+02:00  source=stdin       command=Read test.csv  mode=pattern  rule=github_token  count=1  sample=ghp_abc...
2026-04-28T01:17:22+02:00  source=wrap:bash   command=bash -c deploy.sh  mode=wrap     rule=openai_key  count=1  sample=sk-proj-FAKE...
2026-04-28T01:18:05+02:00  source=.env        command=-  mode=env  rule=env_var  count=3  sample=OPENAI_API_KEY
```

The directory is auto-created. Log writes are non-fatal: if the disk is full
the redaction still succeeds (we'd rather lose telemetry than leak data).

Override location:
```bash
export REDACTOR_LOG_DIR="$HOME/.local/share/redactor/logs"
redactor --log-dir /var/log/redactor < some.log
```

## Wrap mode — the cross-platform default

```bash
redactor wrap -- ./run.sh
redactor wrap -- bash -c 'echo $SOME_VAR; ./inner.sh'
redactor wrap -- python my_script.py --flag
redactor wrap -- docker logs my-container
redactor wrap --keywords "PROJECT-X" -- kubectl logs deploy/api
```

What `wrap` does:
1. Spawns the subprocess with the given argv, inheriting your stdin.
2. Captures the child's stdout and stderr line-by-line in two threads.
3. Runs each line through pattern-mode redaction.
4. Forwards the redacted lines to **your** stdout / stderr (preserved separately).
5. Forwards the child's exit code as the redactor exit code.
6. Logs every redaction to `logs/YYYY-MM-DD-redacted.log` with `mode=wrap`.

It's binary-safe: invalid UTF-8 in a chunk is replaced (lossy), the subprocess
keeps running, and downstream redaction still finds embedded text secrets.

## Windows / PowerShell

`redactor` is a static Rust binary — it works identically on Windows, macOS,
and Linux. PowerShell users should prefer **wrap** because piping object
streams between PowerShell and a byte-stream tool is fiddly.

```powershell
# Recommended: wrap mode (no pipe gymnastics)
redactor wrap -- python .\my_script.py
redactor wrap -- .\run.ps1
redactor wrap --keywords "secret-codename" -- .\deploy.ps1

# Pipe form works too, but watch out for:
#   - $LASTEXITCODE only sees the last command in the pipe (the redactor)
#   - Default encoding may be UTF-16; force UTF-8 for stable input:
$OutputEncoding = [Text.UTF8Encoding]::new()
.\my_script.exe | redactor

# cmd.exe pipe (also works, but no PIPESTATUS equivalent)
my_script.exe | redactor
```

Install on Windows:

```powershell
# via just
winget install --id Casey.Just
git clone https://github.com/niclasedge/rust-redactor.git
cd rust-redactor
just install-win

# or directly
cargo install --path .
```

The binary lands at `%USERPROFILE%\.cargo\bin\redactor.exe`. Make sure
`%USERPROFILE%\.cargo\bin` is on `PATH` (rustup adds it automatically).

## Universal Bash recipe book

This is the practical part — every Bash invocation pattern you'll meet, with the
correct redactor wiring.

### 1. Plain pipe (the standard case)

```bash
./run.sh | redactor
curl -s https://api.example.com | redactor
docker logs my-container | redactor
journalctl -u my-service -n 100 | redactor
```

### 2. Capture stderr too

```bash
./run.sh 2>&1 | redactor                         # merge stderr into stdout
./run.sh > >(redactor) 2> >(redactor >&2)        # filter both streams separately
```

### 3. Preserve exit code (PIPESTATUS)

```bash
./run.sh | redactor; exit ${PIPESTATUS[0]}        # bash
set -o pipefail; ./run.sh | redactor              # safer default
```

### 4. Force a mode regardless of suffix

```bash
cat /tmp/some-binary-config | redactor -t pattern
redactor -t json < weird-extension-file
```

### 5. File arg with auto-detect

```bash
redactor data.csv         # csv mode
redactor api.json         # json mode
redactor /etc/.env        # env mode
redactor app.log          # pattern mode
```

### 6. Multiple files via xargs

```bash
find . -name "*.log" -print0 | xargs -0 -I{} redactor {} > {}.redacted
# or with parallelism:
fd -e log . | parallel 'redactor {} > {.}.redacted.log'
```

### 7. Adding project-specific keywords / codenames

```bash
./deploy.sh | redactor --keywords "PROJECT-NIGHTHAWK,internal-host.corp"
```

### 8. Loading custom regex rules

```bash
cat > /tmp/extra.json <<'JSON'
[
  {"name": "email",  "re": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"},
  {"name": "ipv4",   "re": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"}
]
JSON
./script.sh | redactor --patterns /tmp/extra.json
```

### 9. Strict mode (custom rules only, no built-ins)

```bash
./script.sh | redactor --patterns /tmp/only-my-rules.json --no-defaults
```

### 10. Subshells & here-docs

```bash
( ./step1.sh && ./step2.sh ) 2>&1 | redactor
redactor <<EOF
config: api_key=ghp_abcdefghij1234567890ABCDEFGHIJ
EOF
```

### 11. Process substitution

```bash
diff <(curl -s api.dev) <(curl -s api.prod) | redactor
```

### 12. Tee — keep raw on disk, send redacted upstream

```bash
./run.sh 2>&1 | tee /var/log/raw.log | redactor
# raw.log is the unredacted source-of-truth (chmod 0600!), stdout is redacted.
```

### 13. SSH

```bash
ssh prod-host 'cat /var/log/app.log' | redactor
```

### 14. Containerized

```bash
docker run --rm app:latest 2>&1 | redactor
kubectl logs deploy/api 2>&1 | redactor --keywords "$(cat company-codenames.txt)"
```

### 15. Long-running tail

```bash
tail -F /var/log/app.log | redactor
# stays interactive — redactor flushes line-by-line via stdout
```

## Quickstart for an agent project — strict redaction

A complete drop-in `.claude/` config that enforces redaction at every tool
boundary lives at [`examples/strict-redaction/`](examples/strict-redaction/).
It has:

- **PreToolUse `Bash`** — rejects any bash command that doesn't start with
  `redactor wrap --` or pipe through `| redactor`
- **PreToolUse `Read`** — rejects sensitive paths (`.env*`, SSH keys,
  `.aws/credentials`, `*.pem`, `*.key`, `**/secrets/**`)
- **PostToolUse Read|Bash** — pipes results through redactor before the
  model sees them
- **UserPromptSubmit** — scans the user prompt and blocks if it contains a
  secret
- **`CLAUDE.md`** — agent guidance explaining the policy

Install into your project:

```bash
cd /path/to/your/project
~/GITHUB/rust-redactor/examples/strict-redaction/install.sh
```

See [`examples/strict-redaction/README.md`](examples/strict-redaction/README.md)
for the full walkthrough.

## Hook integration

The whole point: agent CLIs run shell commands on your behalf. Wire `redactor`
into the pre-tool-use hook so the LLM never sees raw secrets.

### Codex CLI (`PostToolUse` — replace tool result)

`~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "^(Bash|Read)$",
      "hooks": [{
        "type": "command",
        "command": "redactor --no-log <<<\"$TOOL_RESPONSE_OUTPUT\""
      }]
    }]
  }
}
```

(Exact field names depend on Codex's hook payload — see Codex docs. The pattern
is: stdin = tool output, stdout = redacted output, return JSON `{"decision":"replace","output":...}`.)

### Codex CLI (`PreToolUse` — block sensitive paths)

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "^(Read|Bash)$",
      "hooks": [{ "type": "command", "command": "/usr/local/bin/codex-redact-guard" }]
    }]
  }
}
```

`codex-redact-guard` (small shell wrapper, ~20 lines) parses the hook JSON,
checks for sensitive paths (`*.env`, `id_rsa*`, `.aws/credentials`), and emits
`{"permissionDecision":"deny",...}` if matched.

### OpenCode (`tool.execute.before` — rewrite the bash command)

Because OpenCode's `tool.execute.after` hook is **read-only** (no `output`
argument), the workaround is to rewrite the bash command itself in `before`.
The recommended rewrite uses `redactor wrap` (no PIPESTATUS dance, exit code
preserved automatically, works in any shell):

```ts
// .opencode/plugin/redact-bash.ts  (or `just hook-opencode-install` to copy)
import type { Plugin } from "@opencode-ai/plugin"

const SENSITIVE = [
  /\.env(\.|$)/, /id_rsa/, /\.aws\/credentials/, /\.ssh\/(?!known_hosts)/,
]

export const RedactBash: Plugin = async () => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool === "read" || input.tool === "bash") {
      const target = String(
        (output.args as any).filePath ?? (output.args as any).command ?? "")
      if (SENSITIVE.some((re) => re.test(target))) {
        throw new Error(`redactor: blocked sensitive path (${target})`)
      }
    }
    if (input.tool === "bash") {
      const cmd = String((output.args as any).command)
      if (cmd.startsWith("redactor wrap") || cmd.includes("| redactor")) return
      const escaped = cmd.replace(/'/g, `'\\''`)
      ;(output.args as any).command = `redactor wrap -- sh -c '${escaped}'`
    }
  },
})
```

This template ships at `docs/hooks/opencode-redact-bash.ts`; install with
`just hook-opencode-install`.

### Claude Code (`PostToolUse` hook)

`.claude/settings.json` (global or project):

```json
{
  "hooks": {
    "PostToolUse": [{
      "matcher": "Bash|Read",
      "hooks": [{
        "type": "command",
        "command": "jq -r '.tool_response.stdout // .tool_response.content' | redactor"
      }]
    }]
  }
}
```

## Enforcement: fail tool calls without redactor

If you want hard enforcement ("every Bash call MUST end in `| redactor` or
fail"), put this in the pre-hook:

```ts
"tool.execute.before": async (input, output) => {
  if (input.tool === "bash") {
    const cmd = String(output.args.command)
    if (!cmd.match(/\|\s*redactor(\s|$)/)) {
      throw new Error("policy: bash commands must pipe through `redactor`")
    }
  }
}
```

The auto-rewrite version above is gentler — it adds `| redactor` if missing,
rather than failing. Pick based on how strict you want to be.

## Testing

```bash
cargo test                # 11 unit + 12 integration tests
cargo build --release     # optimized binary at target/release/redactor
```

## Tradeoffs / known limits

- **Pattern mode is best-effort.** A novel secret format won't be caught.
  Combine with structural modes (`env`/`json`) where possible.
- **OpenCode bypass:** subagent-spawned tool calls and MCP tool calls don't
  trigger plugin hooks (upstream issues #5894, #2319). Defense-in-depth via OS
  filesystem permissions is still required for true isolation.
- **No streaming yet.** stdin is read to a single buffer. Fine for log files up
  to a few hundred MB, slow for multi-GB streams.
- **No diff mode.** The redacted output replaces the input — there is no
  "show me what changed" view beyond the daily log.

## License

MIT.
