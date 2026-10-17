---
description: Uninstall the redactor plugin's local binary. Removes the fetched binary from the plugin's bin/. To fully remove the hooks, disable/remove the plugin via /plugin.
---

# /redactor:uninstall — remove the plugin-local binary

The strict-redaction hooks are owned by the plugin itself, so the clean way to
turn them off is to **disable or remove the plugin** via the `/plugin` menu
(or `claude plugin uninstall redactor@hook-redactor`). This command only
removes the downloaded binary from the plugin's `bin/`.

## Step 1 — remove the binary

```bash
rm -f "${CLAUDE_PLUGIN_ROOT}/bin/redactor" "${CLAUDE_PLUGIN_ROOT}/bin/redactor.exe"
```

On Windows:

```powershell
Remove-Item -Force "$env:CLAUDE_PLUGIN_ROOT/bin/redactor.exe" -ErrorAction SilentlyContinue
```

## Step 2 — tell the user how to finish

```text
Plugin-local binary removed.
To fully deactivate the hooks, disable or uninstall the plugin:
  /plugin           (toggle "redactor" off)
  claude plugin uninstall redactor@hook-redactor

Per-user keyword/config files (redactor config-path) are left untouched.
```
