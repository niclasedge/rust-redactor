# redactor

A single-binary Rust CLI that masks secrets and personal data in text and
structured files. It is built to run as a **pre-/post-tool-use hook** for
agent CLIs (Claude Code, Codex CLI, OpenCode, pi), so that the model never sees
raw API keys, tokens, PEM blocks, or whole secret files.

## Problem

Coding agents read files and run shell commands on your machine. Everything
they read ends up in the model context, and from there in provider logs and
transcripts. Prompting an agent to "not look at `.env`" is not a control.
`redactor` puts a deterministic filter in the hook layer: tool calls that touch
sensitive paths are blocked, and tool output is sanitised before the model
receives it.

## What it does

- **Redaction engine.** Four modes: `pattern` (regex scrubbing for free text),
  `json` (structure kept, leaf values masked), `csv` (header kept, rows
  masked), `env` (keys kept, values masked). `auto` picks a mode from the file
  name or extension.
- **Built-in rules** (`src/patterns.rs`) for Anthropic, OpenAI, AWS, GitHub,
  Slack and Stripe keys, JWTs, PEM private keys, connection strings, bearer and
  authorization headers, generic `password=` / `api_key:` assignments, e-mail
  addresses, IBANs, private IPs and hostnames, home-directory user names, and
  paths to crypto containers (`.kdbx`, `.pfx`, `.gpg`, ...).
- **Custom rules.** Literal keywords (customer names, codenames), regex rules
  from a JSON file, a personal `~/.redactorignore`, and per-project
  `.redactor.toml` overrides.
- **Hook subcommands** (`redactor hook <event>`) for session start, prompt
  submit, pre-bash, pre-read, pre-edit, post-tool and post-write, plus fixed
  denies for `Grep`, `NotebookEdit` and `mcp__*` tools. A path guard blocks
  reads of `.env*`, SSH keys, cloud credentials, `*.pem` and similar.
- **Wrap mode.** `redactor wrap -- <cmd>` runs a command and filters both
  streams; the exit code is preserved.
- **Search.** `redactor search` does ranked full-text search over markdown and
  code with sanitised snippets.
- **Optional file classifier.** `redactor classify-files` suggests entries for
  `~/.redactorignore` using a Python sidecar (Presidio, GLiNER) or a local
  Ollama model. It is opt-in and installed separately.
- **Audit log.** Append-only daily log of what was redacted, where, and a
  truncated sample.

## Architecture

```text
agent CLI ──hook event (JSON on stdin)──▶ redactor hook <event>
                                            │
                    ┌───────────────────────┼────────────────────────┐
                    ▼                       ▼                        ▼
               path guard            rule engine               network guard
          (block sensitive       (defaults + keywords       (URL allowlist from
           paths / files)         + .redactorignore          .redactor-urls.json,
                                  + .redactor.toml)          opt-in)
                    └───────────────────────┼────────────────────────┘
                                            ▼
                         stdout: {}  (allow)  or  {"decision":"block",...}
```

| Path | Role |
|------|------|
| `src/hook.rs` | Hook event handlers, path guard, block/allow decisions |
| `src/patterns.rs`, `src/redactor.rs` | Built-in rules and the four redaction modes |
| `src/config.rs`, `src/ignorefile.rs` | Config dir, keywords, `.redactorignore` |
| `src/wrap.rs` | `redactor wrap` |
| `src/install.rs` | `install-plugin` / `install-hooks` for Claude Code settings |
| `src/classify*.rs`, `classifier-py/` | Optional file classifier |
| `hooks/`, `.claude-plugin/`, `commands/` | Claude Code plugin packaging |
| `extensions/pi/` | Extension for the pi agent (TypeScript) |
| `tests/` | Integration and red-team tests |

## Quickstart

Requires a Rust toolchain.

```bash
git clone https://github.com/niclasedge/rust-redactor
cd rust-redactor
cargo install --path .          # installs `redactor`

echo "OPENAI_API_KEY=sk-proj-EXAMPLE" | redactor
redactor wrap -- env | head     # run a command, filter its output
```

Wire it into a Claude Code project (writes `.claude/settings.json` and a
`CLAUDE.md` block; preview first with `--dry-run`):

```bash
redactor install-plugin local --dry-run .
redactor install-plugin local .
```

Restart Claude Code afterwards. For the global install, the plugin route, the
keyword list and all other options, see [`docs/reference.md`](docs/reference.md)
and [`docs/claude-code-plugin.md`](docs/claude-code-plugin.md).

Development:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Status and limits

- Version 0.8.x. No stability guarantee for CLI flags or
  config format.
- Redaction is rule-based. A secret that matches no rule, keyword or path
  pattern is not masked. Pattern mode is line-oriented; for structured files
  use `--type json|csv|env` or let the hooks enforce it.
- A hook only covers the tools it is wired to. Anything the agent can do
  outside those matchers (other tools, other MCP servers) is not filtered.
- The classifier is advisory: it proposes entries, and you review them before
  they take effect.
- Prebuilt binaries are produced by the GitHub release workflows
  (`.github/workflows/`); the install scripts under `scripts/` expect a release
  to exist in this repository.
- CI builds and tests on Linux (musl) and Windows. macOS targets are built only
  by the release workflows, not by CI.

## License

MIT, see [`LICENSE`](LICENSE).
