/**
 * redactor — pi agent extension
 *
 * Ensures no secret, email, or blocked keyword ever reaches the LLM API.
 * Integrates the `redactor` Rust CLI into pi's event system:
 *
 *   tool_call (bash)     → path-guard + bash-strict
 *   tool_call (read)     → path-guard + read-strict (structured files)
 *   tool_call (edit/write) → path-guard (self-protect, crypto, sensitive)
 *   tool_call (grep)     → denied (use `redactor wrap -- rg/grep …`)
 *   tool_result          → post-tool output redaction
 *   input                → prompt secret-scan (blocks if secrets found)
 *   before_provider_request → last-resort API payload scrub
 *   session_start        → audit log
 *
 * Project config via .redactor.toml:
 *   [policy] strict_json = true/false
 *   [allow]  paths = ["..."]
 *   [allow]  filetypes = ["..."]
 *   [whitelist] paths = ["..."]
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { existsSync, readFileSync } from "node:fs";

import { autoloadProjectConfig } from "./config.js";
import {
  matchSensitivePath,
  matchCryptoContainer,
  matchOfficeDoc,
  matchSelfProtect,
  matchRedactorignorePath,
  isProjectAllowed,
  startsWithRedactor,
  isRedactorWrap,
  stripPatternArgs,
  matchOfficeDocInBash,
  detectStructFileInWrap,
  detectFileMode,
  type FileMode,
} from "./path-guard.js";
import {
  redactPattern,
  scanPattern,
  redactStructured,
  redactPrompt,
  type StructMode,
} from "./redact.js";

// ============================================================================
// Extension entry point
// ============================================================================

export default function (pi: ExtensionAPI) {
  let cwd = process.cwd();
  let config = autoloadProjectConfig(cwd);

  // ------------------------------------------------------------------
  // session_start — audit log + config reload
  // ------------------------------------------------------------------
  pi.on("session_start", (_event, ctx) => {
    cwd = ctx.cwd;
    config = autoloadProjectConfig(cwd);

    if (ctx.hasUI) {
      ctx.ui.setStatus("redactor", "🛡️ active");
    }
    console.error(`[redactor] session start — cwd=${cwd} strict_json=${config.policy.strict_json}`);
  });

  // ------------------------------------------------------------------
  // tool_call — pre-execution gates
  // ------------------------------------------------------------------
  pi.on("tool_call", async (event, ctx) => {
    const toolName = event.toolName;

    // ---- Grep tool: always denied ----
    if (toolName === "grep" || toolName === "Grep") {
      return {
        block: true,
        reason:
          "[redactor] Grep is disabled — matching lines bypass path-guard.\n" +
          'Use Bash instead: redactor wrap -- rg "<pattern>" <path>',
      };
    }

    // ---- Bash ----
    if (toolName === "bash") {
      const cmd: string = (event.input as any)?.command?.trim() || "";
      if (!cmd) return undefined;
      return preBashGate(cmd, ctx);
    }

    // ---- Read ----
    if (toolName === "read") {
      const path: string = (event.input as any)?.path?.trim() || "";
      if (!path) return undefined;
      return preReadGate(path, ctx);
    }

    // ---- Edit / Write ----
    if (toolName === "edit" || toolName === "write") {
      const input = event.input as any;
      const path: string = input?.path?.trim() || input?.file_path?.trim() || "";
      if (!path) return undefined;
      return preEditGate(path, ctx);
    }

    return undefined;
  });

  // ------------------------------------------------------------------
  // tool_result — post-execution redaction
  // ------------------------------------------------------------------
  pi.on("tool_result", async (event, _ctx) => {
    const toolName = event.toolName;

    // ---- Bash output redaction ----
    if (toolName === "bash") {
      const cmd: string = (event.input as any)?.command || "";

      // Skip if already redacted by a direct redactor call
      if (startsWithRedactor(cmd) && !isRedactorWrap(cmd)) {
        return undefined;
      }

      // Redact stdout content blocks
      if (event.content && Array.isArray(event.content)) {
        const newContent = event.content.map((block: any) => {
          if (block.type === "text" && typeof block.text === "string") {
            return { ...block, text: redactPattern(block.text) };
          }
          return block;
        });
        return { content: newContent };
      }
      return undefined;
    }

    // ---- Read output redaction ----
    if (toolName === "read") {
      if (event.content && Array.isArray(event.content)) {
        const path: string = (event.input as any)?.path || "";
        const fileMode = detectFileMode(path);

        const newContent = event.content.map((block: any) => {
          if (block.type === "text" && typeof block.text === "string") {
            if (fileMode && fileMode !== "pattern") {
              return { ...block, text: redactStructured(block.text, fileMode as StructMode) };
            } else {
              return { ...block, text: redactPattern(block.text) };
            }
          }
          return block;
        });
        return { content: newContent };
      }
      return undefined;
    }

    // ---- Write/Edit post-validation ----
    if (toolName === "write" || toolName === "edit") {
      const input = event.input as any;
      const path: string = input?.path || input?.file_path || "";
      if (path && existsSync(path)) {
        const validationError = validateWrittenFile(path);
        if (validationError) {
          console.error(`[redactor] post-write validation: ${validationError}`);
          // Don't block — just warn. The write already happened.
        }
      }
      return undefined;
    }

    return undefined;
  });

  // ------------------------------------------------------------------
  // input — silently redact secrets in user prompts
  // ------------------------------------------------------------------
  pi.on("input", async (event, ctx) => {
    // Skip extension-generated messages and empty/command inputs
    if (event.source === "extension") return undefined;
    const text = event.text;
    if (!text || text.startsWith("/")) return undefined;

    const { sanitized, hasSecrets } = redactPrompt(text);
    if (!hasSecrets) return undefined;

    if (ctx.hasUI) {
      ctx.ui.notify(
        "🛡️ [redactor] Prompt redacted — secrets masked before sending to API.",
        "info",
      );
    }

    return { action: "transform", text: sanitized };
  });

  // ------------------------------------------------------------------
  // before_provider_request — last-resort API payload scrub
  // ------------------------------------------------------------------
  pi.on("before_provider_request", (event, _ctx) => {
    try {
      const payload = event.payload as any;
      if (!payload) return undefined;

      // Deep-clone and scrub
      const scrubbed = JSON.parse(JSON.stringify(payload));

      // Scrub messages array
      if (Array.isArray(scrubbed.messages)) {
        for (const msg of scrubbed.messages) {
          if (typeof msg.content === "string") {
            msg.content = redactPattern(msg.content);
          } else if (Array.isArray(msg.content)) {
            for (const block of msg.content) {
              if (block.type === "text" && typeof block.text === "string") {
                block.text = redactPattern(block.text);
              }
            }
          }
        }
      }

      // Scrub system prompt
      if (typeof scrubbed.system === "string") {
        scrubbed.system = redactPattern(scrubbed.system);
      }

      return scrubbed;
    } catch (err) {
      console.error(`[redactor] before_provider_request error: ${err}`);
      return undefined;
    }
  });
}

// ============================================================================
// Gate implementations
// ============================================================================

function preBashGate(
  cmd: string,
  ctx: ExtensionContext,
): { block: boolean; reason?: string } | undefined {
  const cfg = autoloadProjectConfig(ctx.cwd);

  // 0a. Self-protect
  if (matchSelfProtect(cmd)) {
    return {
      block: true,
      reason:
        "[redactor] ~/.redactorignore is self-protected.\n" +
        "Edit with $EDITOR outside the agent session.",
    };
  }

  // Strip pattern-literal args before path matching
  const cmdForGuard = stripPatternArgs(cmd);

  // 0b. Crypto containers
  const crypto = matchCryptoContainer(cmdForGuard);
  if (crypto) {
    return {
      block: true,
      reason:
        `[redactor] Crypto container (${crypto}) in command.\n` +
        "Encrypted containers have no LLM-readable use case.",
    };
  }

  // 1. Sensitive paths
  const sensitive = matchSensitivePath(cmdForGuard, cfg.whitelist);
  if (sensitive) {
    return {
      block: true,
      reason:
        `[redactor] Sensitive path (${sensitive}) in command.\n` +
        "Ask the user for an exception.",
    };
  }

  // 1a. Project [allow]
  if (isProjectAllowed(cmd, cfg.allow)) {
    return undefined;
  }

  // 1b. ~/.redactorignore
  const ignPattern = matchRedactorignorePath(cmd);
  if (ignPattern) {
    return {
      block: true,
      reason:
        `[redactor] Path in ~/.redactorignore (matches \`${ignPattern}\`).\n` +
        "Add to .redactor.toml [allow] to unblock.",
    };
  }

  // Phase 7e: Office-doc in bash
  const officeInBash = matchOfficeDocInBash(cmdForGuard);
  if (officeInBash) {
    return {
      block: true,
      reason:
        `[redactor] Office document (${officeInBash}) in command.\n` +
        "Office docs (.xlsx/.docx/.pptx/.pdf) blocked at Bash. Use [allow] to permit.",
    };
  }

  // 2. Bash-strict
  if (!startsWithRedactor(cmd)) {
    return {
      block: true,
      reason:
        "[redactor] Every shell command must go through redactor.\n" +
        `Wrap it:\n    redactor wrap -- ${cmd}\n` +
        "For files: redactor --type json/csv/env <file>\n" +
        "           redactor <text-file>",
    };
  }

  // 3. Struct-file inside `redactor wrap`
  const structInWrap = detectStructFileInWrap(cmd);
  if (structInWrap) {
    const { mode } = structInWrap;
    const jsonExempt = mode === "json" && !cfg.policy.strict_json;
    if (!jsonExempt) {
      return {
        block: true,
        reason:
          `[redactor] Structured file (${mode.toUpperCase()}) inside \`redactor wrap\` — ` +
          `wrap is pattern-mode only. Use:\n    redactor --type ${mode} <file>`,
      };
    }
  }

  // 4. Flag-bypass guard
  if (startsWithRedactor(cmd)) {
    const structMode = detectFileMode(cmd);
    if (structMode && structMode !== "pattern") {
      const jsonExempt = structMode === "json" && !cfg.policy.strict_json;
      if (!jsonExempt) {
        const forcesPattern =
          /-t\s+pattern|--type\s+pattern|-t=pattern|--type=pattern/.test(cmd);
        const disablesRules = /--no-defaults|--no-config/.test(cmd);
        if (forcesPattern || disablesRules) {
          return {
            block: true,
            reason:
              `[redactor] Cannot bypass structural redaction for ${structMode.toUpperCase()}.\n` +
              `Use:  redactor --type ${structMode} <file>`,
          };
        }
      }
    }
  }

  return undefined;
}

function preReadGate(
  target: string,
  ctx: ExtensionContext,
): { block: boolean; reason?: string } | undefined {
  const cfg = autoloadProjectConfig(ctx.cwd);

  // 0a. Self-protect
  if (matchSelfProtect(target)) {
    return {
      block: true,
      reason:
        "[redactor] ~/.redactorignore is self-protected.\n" +
        "Inspect with $EDITOR outside the agent session.",
    };
  }

  // 0b. Crypto containers
  const crypto = matchCryptoContainer(target);
  if (crypto) {
    return {
      block: true,
      reason: `[redactor] ${target} is a ${crypto}. Cannot be parsed as text.`,
    };
  }

  // 1. Sensitive paths
  const sensitive = matchSensitivePath(target, cfg.whitelist);
  if (sensitive) {
    return {
      block: true,
      reason:
        `[redactor] Sensitive path: ${target} (matches ${sensitive}).\n` +
        "Ask the user for an exception.",
    };
  }

  // 1a. Project [allow]
  if (isProjectAllowed(target, cfg.allow)) {
    return undefined;
  }

  // 1b. ~/.redactorignore
  const ignPattern = matchRedactorignorePath(target);
  if (ignPattern) {
    return {
      block: true,
      reason:
        `[redactor] ${target} is in ~/.redactorignore (matches \`${ignPattern}\`).\n` +
        "Add to .redactor.toml [allow] to unblock.",
    };
  }

  // 1c. Office docs
  const officeDoc = matchOfficeDoc(target);
  if (officeDoc) {
    return {
      block: true,
      reason:
        `[redactor] ${target} is a ${officeDoc}. Read cannot parse this format.\n` +
        "Use a skill (docx/xlsx/pdf) via Bash, or add to .redactor.toml [allow].",
    };
  }

  // 2. Read-strict: structured files
  const mode = detectFileMode(target);
  if (mode && mode !== "pattern") {
    const jsonExempt = mode === "json" && !cfg.policy.strict_json;
    if (!jsonExempt) {
      return {
        block: true,
        reason:
          `[redactor] ${mode.toUpperCase()} files cannot be Read directly.\n` +
          `Use:  redactor --type ${mode} "${target}"\n` +
          (mode === "json" ? "Or set strict_json = false in .redactor.toml.\n" : ""),
      };
    }
  }

  return undefined;
}

function preEditGate(
  target: string,
  ctx: ExtensionContext,
): { block: boolean; reason?: string } | undefined {
  const cfg = autoloadProjectConfig(ctx.cwd);

  // 0a. Self-protect (most important for Write protection)
  if (matchSelfProtect(target)) {
    return {
      block: true,
      reason:
        "[redactor] ~/.redactorignore is self-protected.\n" +
        "Edit with $EDITOR outside the agent session.",
    };
  }

  // 0b. Crypto containers
  const crypto = matchCryptoContainer(target);
  if (crypto) {
    return {
      block: true,
      reason: `[redactor] Cannot Write/Edit ${target} (${crypto}).`,
    };
  }

  // 1. Sensitive paths
  const sensitive = matchSensitivePath(target, cfg.whitelist);
  if (sensitive) {
    return {
      block: true,
      reason:
        `[redactor] Write/Edit at sensitive path: ${target} (matches ${sensitive}).\n` +
        "Ask the user for an exception.",
    };
  }

  // 1a. Project [allow]
  if (isProjectAllowed(target, cfg.allow)) {
    return undefined;
  }

  // 1b. ~/.redactorignore
  const ignPattern = matchRedactorignorePath(target);
  if (ignPattern) {
    return {
      block: true,
      reason:
        `[redactor] Write/Edit at ${target} is in ~/.redactorignore (matches \`${ignPattern}\`).\n` +
        "Add to .redactor.toml [allow] to unblock.",
    };
  }

  return undefined;
}

// ============================================================================
// Post-write validation
// ============================================================================

function validateWrittenFile(path: string): string | null {
  try {
    const ext = path.split(".").pop()?.toLowerCase() || "";

    if (ext === "json") {
      JSON.parse(readFileSync(path, "utf-8"));
      return null;
    }

    if (ext === "toml") {
      const raw = readFileSync(path, "utf-8");
      for (const line of raw.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        if (trimmed.startsWith("[")) continue; // section header
        if (!/^\S+\s*=\s*/.test(trimmed)) {
          return `Invalid TOML line: "${trimmed.slice(0, 80)}"`;
        }
      }
      return null;
    }
  } catch (e: any) {
    return `Validation error in ${path}: ${e.message}`;
  }
  return null;
}
