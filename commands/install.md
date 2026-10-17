---
description: Install the redactor plugin — fetch the prebuilt redactor binary (Windows / macOS / Linux) into the plugin's bin/ and activate the strict-redaction hooks. Idempotent.
---

# /redactor:install — fetch binary + activate strict redaction

This plugin's hooks (`hooks/hooks.json`) call `${CLAUDE_PLUGIN_ROOT}/bin/redactor`.
That binary is **not** committed to the repo — this command downloads the
prebuilt, SHA256-verified binary for the current OS/arch into
`${CLAUDE_PLUGIN_ROOT}/bin`. Run it once right after
`/plugin install redactor@hook-redactor`. Running it again is safe (no-op
unless `--force`).

## Step 0 — locate the plugin root

The plugin root is in `$CLAUDE_PLUGIN_ROOT`. The bootstrap scripts live at:

- `${CLAUDE_PLUGIN_ROOT}/scripts/install-binary.sh`  (Linux + macOS)
- `${CLAUDE_PLUGIN_ROOT}/scripts/install-binary.ps1` (Windows)

## Step 1 — detect the OS and run the matching bootstrap

Determine the operating system, then run **exactly one** of the following.

**Linux / macOS:**

```bash
bash "${CLAUDE_PLUGIN_ROOT}/scripts/install-binary.sh"
```

**Windows (PowerShell / pwsh):**

```powershell
pwsh -NoProfile -File "$env:CLAUDE_PLUGIN_ROOT/scripts/install-binary.ps1"
```

(If `pwsh` is unavailable, use `powershell -NoProfile -ExecutionPolicy Bypass -File ...`.)

Each script:
1. resolves `${CLAUDE_PLUGIN_ROOT}/bin` as the target dir,
2. detects the target triple (linux-musl / apple-darwin / windows-msvc, x86_64 or arm64),
3. downloads `redactor-<target>.tar.gz` (or `.zip`) **and** `SHA256SUMS.txt`
   from the `rolling` GitHub release of `niclasedge/rust-redactor`,
4. verifies the SHA256, extracts, and installs `redactor` / `redactor.exe` into `bin/`.

It fails closed (non-zero exit) on any download or checksum error — surface
that to the user rather than continuing.

> **Strict-mode interaction — read this:**
>
> - **First run (no binary yet):** the `pre-bash` hook tries to call the
>   still-missing binary. If Claude Code surfaces that as a non-blocking hook
>   error, the bare `bash …` / `pwsh …` above runs and fetches the binary. If
>   instead it blocks the call, run the bootstrap once from a real terminal
>   (outside Claude), or temporarily disable the plugin via `/plugin`, run the
>   install, then re-enable.
> - **Re-install / `--force` (binary already present):** strict mode now
>   requires every Bash call to start with `redactor wrap --`. Use the wrapped
>   form instead:
>   ```bash
>   redactor wrap -- bash "${CLAUDE_PLUGIN_ROOT}/scripts/install-binary.sh" --force
>   ```

## Step 2 — verify

```bash
"${CLAUDE_PLUGIN_ROOT}/bin/redactor" --version
```

Confirm it prints a version. The hooks are now live for this and future
sessions (the plugin's `hooks/hooks.json` is already wired by Claude Code —
no `settings.json` edit needed).

## Step 3 — (optional) keyword list

The redactor auto-loads literal terms (customer names, codenames, hostnames)
from the per-user config dir. To see / edit it:

```bash
"${CLAUDE_PLUGIN_ROOT}/bin/redactor" config-path
```

## Step 4 — report

Summarise to the user:

```text
redactor plugin installed
  binary:   <plugin-root>/bin/redactor[.exe]  (vX.Y.Z)
  hooks:    strict mode active (prompt-scan, pre-bash, pre-read, pre-edit,
            deny grep/mcp/notebook, post-write)
  next:     every Bash call now goes through `redactor wrap -- <cmd>`;
            structured files via `redactor --type <json|csv|env> <file>`.
```

## What this command does NOT do

- It does not edit `~/.claude/settings.json` — the hooks come from the plugin
  itself, so disabling/uninstalling the plugin cleanly removes them.
- It does not install a system-wide `redactor` on PATH. The binary is
  plugin-local. If you also want it on PATH, install separately via
  `cargo install --git https://github.com/niclasedge/rust-redactor` or
  copy `bin/redactor` to a PATH dir.
