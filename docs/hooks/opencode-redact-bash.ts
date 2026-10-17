// OpenCode plugin: rewrites bash commands to wrap them in `redactor wrap`.
//
// Install:   just hook-opencode-install     (copies into .opencode/plugin/)
// Or paste manually at:  .opencode/plugin/redact-bash.ts
//
// Behavior:
//   - Blocks reads of sensitive paths outright (.env, id_rsa, .aws/credentials)
//   - Rewrites every bash command to `redactor wrap -- <cmd>` so both stdout
//     and stderr are filtered before the LLM sees them, and exit code is
//     preserved automatically (no PIPESTATUS dance, works under any shell).

import type { Plugin } from "@opencode-ai/plugin"

const SENSITIVE = [
  /\.env(\.|$)/,
  /id_rsa/,
  /\.aws\/credentials/,
  /\.ssh\/(?!known_hosts)/,
]

export const RedactBash: Plugin = async () => ({
  "tool.execute.before": async (input, output) => {
    // Layer 1: block sensitive reads/bash targets entirely
    if (input.tool === "read" || input.tool === "bash") {
      const target = String(
        (output.args as { filePath?: string; command?: string }).filePath ??
          (output.args as { command?: string }).command ??
          "",
      )
      if (SENSITIVE.some((re) => re.test(target))) {
        throw new Error(`redactor: blocked sensitive path (${target})`)
      }
    }

    // Layer 2: wrap bash through `redactor wrap` for output filtering
    if (input.tool === "bash") {
      const cmd = String((output.args as { command: string }).command)
      // already wrapped? leave alone
      if (cmd.startsWith("redactor wrap") || cmd.includes("| redactor")) return
      // shell-quote the original command for `sh -c`
      const escaped = cmd.replace(/'/g, `'\\''`)
      ;(output.args as { command: string }).command =
        `redactor wrap -- sh -c '${escaped}'`
    }
  },
})
