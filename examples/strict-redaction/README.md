# Example: strict-redaction

A drop-in `.claude/` config that enforces full redaction at every tool boundary
in Claude Code.

## What it does

| Hook | Subcommand | Effect |
|------|------------|--------|
| **SessionStart** | `redactor hook session-start` | best-effort audit log of session start |
| **UserPromptSubmit** | `redactor hook prompt` | scans the user's prompt; blocks with a redacted preview if a secret is found |
| **PreToolUse `Bash\|PowerShell`** | `redactor hook pre-bash` | rejects shell commands that don't start with `redactor` / `r` (single canonical form — pipe form is intentionally not accepted in this profile); `path-guard` for sensitive paths; `network-guard` for unlisted URLs; `struct-file-guard` forces structured reads through direct mode (JSON opt-out via `[policy] strict_json = false`) |
| **PreToolUse `Read`** | `redactor hook pre-read` | rejects sensitive paths (`.env*`, SSH keys, `.aws/credentials`, `*.pem`, `*.key`, `**/secrets/**`) and structured files (forces `redactor --type X <file>`); JSON can be opted out per project via `.redactor.toml` |
| **PreToolUse `Grep`** | `redactor hook deny-grep` | hard-deny — Grep can leak content from blocked paths via matching lines; use `r wrap -- rg` instead |
| **PreToolUse `NotebookEdit`** | `redactor hook deny-notebook` | hard-deny — notebooks have no sanitization path |
| **PreToolUse `mcp__.*`** | `redactor hook deny-mcp` | hard-deny — MCP servers return unsanitized PII |

On macOS and Windows, every block fires a desktop notification (top-right
banner) so the user sees what was blocked and why — sound `Sosumi` on macOS,
`Reminder` on Windows (Linux falls back to the system default). Set
`REDACTOR_NOTIFY=0` to suppress for CI / batch runs.

The **UserPromptSubmit** hook additionally writes the redacted prompt to the
system clipboard (Win/Mac/Linux via `arboard`) when it blocks. Paste with
`Ctrl+V` / `Cmd+V` to resubmit without manual cleanup. Set
`REDACTOR_CLIPBOARD=0` to disable.

## Layout

Since v0.3.0 every hook subcommand is served by the `redactor` binary itself —
no external `*.sh` files are deployed.

```
examples/strict-redaction/
├── README.md                   ← you are here
├── install.sh                  ← thin wrapper around `redactor install-hooks`
├── demo.sh                     ← spits out log lines + secrets, for testing
└── claude/                     ← deployed verbatim to <project>/.claude/
    ├── settings.json           ← hook registrations (`redactor hook <name>`)
    └── CLAUDE.md               ← per-project agent guidance
```

## Install

### Per-project (most common)

The redactor binary itself ships an installer that bakes the templates in:

```bash
cd /path/to/your/project
redactor install-hooks .
```

Or via the bundled bash wrapper (equivalent — useful when you want to install
into a directory without `cd`-ing first):

```bash
~/GITHUB/rust-redactor/examples/strict-redaction/install.sh /path/to/your/project
```

Both copy `claude/settings.json` + `claude/CLAUDE.md` to `<project>/.claude/`,
back up an existing `.claude/` to `.claude.bak.<unix-ts>/`, and exit cleanly.

### Global (every Claude Code session, unless overridden per-project)

`redactor install-hooks` only does per-project. For global, merge the `hooks`
block from this example into your global Claude Code `settings.json` — this
preserves any other top-level keys (permissions, env, statusLine, …) you may
already have:

```bash
python3 - <<'PY'
import json, shutil, time, os
src = os.path.expanduser("~/.claude/settings.json")
ex  = os.path.expanduser("~/GITHUB/rust-redactor/examples/strict-redaction/claude/settings.json")
with open(src) as f: cfg = json.load(f)
with open(ex)  as f: tpl = json.load(f)
shutil.copy(src, f"{src}.bak.{int(time.time())}")
cfg["hooks"] = tpl["hooks"]
json.dump(cfg, open(src, "w"), indent=2)
print(f"merged; backup at {src}.bak.<ts>")
PY
```

Then **restart Claude Code**. The hook matchers in the table above now fire
from any cwd. Per-project `.claude/settings.json` still wins where present.

## Try it without an agent

```bash
# 1) Install redactor itself
cd ~/GITHUB/rust-redactor && cargo install --path .

# 2) Seed your keyword list
redactor init-config
$EDITOR ~/.config/redactor/keywords.txt   # add: Alice Mustermann, PROJECT-NIGHTHAWK, internal-host.corp

# 3) Run the demo raw (you'll see all secrets)
./demo.sh

# 4) Run it via wrap (everything redacted, exit code preserved)
redactor wrap -- ./demo.sh

# 5) Inspect the log
cat logs/$(date +%Y-%m-%d)-redacted.log
```

## Try it with Claude Code

Once installed in your project:

```bash
cd /path/to/your/project
claude
```

Then ask Claude to read a file or run a command:

- **Allowed:** "run `redactor wrap -- ./run.sh` and tell me what it prints"
- **Allowed:** "read `data.csv`" (Read on safe paths is fine)
- **Blocked:** `cat .env` → path-guard rejects, agent must back off
- **Blocked:** `./run.sh` → bash-strict rejects, agent must rewrap
- **Blocked:** `./run.sh | redactor` → bash-strict rejects (this project
  enforces wrap-only; the underlying redactor binary still supports pipe
  form, but the hook treats wrap as the single canonical shape)

The agent reads `.claude/CLAUDE.md` and learns the policy automatically.

## Customize

All hook logic is now in the `redactor` binary; there are no per-project
`*.sh` files to edit. Customisation is data-driven via config files:

- **Per-project keywords / patterns / whitelists:** drop a `.redactor.toml`
  at the project root. See the main README's `[[patterns.custom]]` and
  `[whitelist]` sections.
- **Per-project URL allowlist** (network-guard): drop `.redactor-urls.json`
  at the project root with `erlaubte_domains` / `blockierte_domains` /
  `fail_closed`.
- **Global keywords:** `redactor init-config` then edit
  `~/.config/redactor/keywords.txt` (path differs on macOS / Windows — see
  `redactor config-path`).
- **Disable a specific deny matcher** (e.g. you genuinely need MCP for a
  session): edit `.claude/settings.json` and remove the matcher entry.
  Restart Claude Code.

## Caveats

- **Subagent bypass:** if your agent uses subagents, those tool calls may not
  trigger the same hooks (Claude Code currently does fire hooks for spawned
  subagents — verify on your version).
- **MCP tools:** in some agent CLIs (notably OpenCode), MCP tool calls
  bypass plugin hooks entirely. Consider OS-level filesystem permissions
  as a backstop for truly sensitive paths.
- **Prompt-scan is best-effort:** novel secret formats not in the built-in
  pattern list won't be caught. Add custom rules in
  `~/.config/redactor/patterns.json`.
