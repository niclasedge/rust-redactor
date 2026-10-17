---
description: Show redactor plugin status — whether the plugin-local binary is present, its version, the config path, and which strict hooks are active.
---

# /redactor:status — installation + health check

Report the current state of the redactor plugin.

## Step 1 — is the binary present?

```bash
ls -l "${CLAUDE_PLUGIN_ROOT}/bin/" 2>/dev/null || dir "%CLAUDE_PLUGIN_ROOT%\bin"
"${CLAUDE_PLUGIN_ROOT}/bin/redactor" --version
```

If the binary is missing, tell the user to run `/redactor:install`.

## Step 2 — config + keyword list location

```bash
"${CLAUDE_PLUGIN_ROOT}/bin/redactor" config-path
```

## Step 3 — which hooks are wired

The active hook set is declared in `${CLAUDE_PLUGIN_ROOT}/hooks/hooks.json`.
Read it and summarise the events/matchers to the user:

```bash
"${CLAUDE_PLUGIN_ROOT}/bin/redactor" --type json "${CLAUDE_PLUGIN_ROOT}/hooks/hooks.json"
```

## Step 4 — report

```text
redactor plugin status
  binary:  <present vX.Y.Z | MISSING — run /redactor:install>
  config:  <config-path output>
  hooks:   SessionStart, UserPromptSubmit, PreToolUse (Bash|PowerShell, Read,
           Edit|MultiEdit|Write, Grep, NotebookEdit, mcp__.*), PostToolUse (Write|Edit)
```
