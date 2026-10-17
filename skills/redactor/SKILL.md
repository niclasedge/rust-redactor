---
name: redactor
description: How to work in a project where the redactor strict-redaction plugin is active. USE WHEN a tool call is blocked by a redactor hook, when output contains <redacted:...> placeholders, when reading files / running Bash / searching under strict redaction, or when the user asks about redactor, strict mode, redacted secrets, or the redaction audit log.
allowed-tools: Read, Bash, Glob
---

# Working under the redactor strict-redaction plugin

This plugin scrubs secrets/PII at every tool boundary via the plugin-local
`redactor` binary (`${CLAUDE_PLUGIN_ROOT}/bin/redactor`). Hooks: prompt-scan
(UserPromptSubmit), pre-bash, pre-read, pre-edit, deny grep/mcp/notebook
(PreToolUse), post-write (PostToolUse).

## Placeholders are sealed

Redacted values appear as opaque tokens: `<redacted>`, `<redacted:openai_key>`,
`<redacted:aws_access_key>`, `<redacted:github_token>`, `<redacted:jwt>`,
`<redacted:private_key>`, `<redacted:keyword>`, `<redacted:<custom>>`. Do **not**
try to reconstruct them, ask the user for the unredacted version, or suggest
disabling the redactor. If a `<redacted:keyword>` blocks legitimate work,
surface the specific token name so the user can decide on an exception.

## Running commands — strict bash

Every Bash/PowerShell call must start with `redactor wrap --` (or its alias
`r wrap --`). Bare commands and pipe form (`cmd | redactor`) are rejected.

```bash
redactor wrap -- ./run.sh
redactor wrap -- bash -c "./step1 && ./step2"
redactor wrap --keywords "PROJECT-X" -- kubectl logs deploy/api
```

If a call is rejected with `redactor strict mode: every Bash call must use
'redactor wrap --'`, prepend the wrapper and retry. Do **not** write a script
that hides the inner command — the hook reads `tool_input.command`.

## Reading files — Read is disabled

The `Read` tool is blocked. Use the binary instead:

```bash
redactor --type json <file.json>     # structured: leaves -> <redacted>
redactor --type csv  <file.csv>
redactor --type env  <file.env>
redactor wrap -- cat <file>          # free text / source / logs
redactor wrap -- head -50 <file>
```

Structured files (`.json/.jsonl/.ndjson/.csv/.tsv/.env`) must go through direct
`--type` mode. JSON can be opted out per project via `.redactor.toml`
(`[policy] strict_json = false`); CSV/TSV/ENV cannot.

## Searching — Grep is disabled

```bash
redactor wrap -- rg "<pattern>" <path>
```

## Sensitive paths are blocked

`.env*`, `id_rsa*`, `.ssh/*` (except `known_hosts`), `.aws/credentials`,
`**/*.pem`, `**/*.key`, `**/secrets/**` are denied at PreToolUse — even via
`redactor wrap -- cat`. If you genuinely need one, ask the user for an excerpt
or a one-off exception; do not try to bypass.

## Audit log

Every redaction is appended to `<log-dir>/YYYY-MM-DD-redacted.log`
(or `$REDACTOR_LOG_DIR`). To debug what was redacted, ask the user to show the
log — never ask for the original unredacted data.

## If the binary is missing

If hooks error because `${CLAUDE_PLUGIN_ROOT}/bin/redactor` is absent, run
`/redactor:install` to fetch the prebuilt binary.
