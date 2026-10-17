/**
 * Calls the `redactor` Rust binary for text scrubbing.
 *
 * Three modes:
 *   1. `redactPattern(text)` — stdin→stdout pattern-mode, returns sanitized text
 *   2. `scanPattern(text)` — returns array of findings (JSONL)
 *   3. `redactStructured(text, mode)` — CSV/JSON/ENV structural redaction
 */

import { spawnSync } from "node:child_process";

const REDACTOR_BIN = process.env.REDACTOR_BIN || "redactor";

// ---------------------------------------------------------------------------
// Pattern-mode redaction
// ---------------------------------------------------------------------------

export interface RedactResult {
  /** Sanitized output text */
  output: string;
  /** Number of redactions applied (estimated from output diff) */
  redacted: boolean;
}

/**
 * Redact text through pattern-mode (regex + keywords).
 * Uses `redactor` binary with stdin pipe.
 */
export function redactPattern(text: string, extraKeywords?: string[]): string {
  const args = ["--no-log"];
  if (extraKeywords && extraKeywords.length > 0) {
    args.push("--keywords", extraKeywords.join(","));
  }

  const result = spawnSync(REDACTOR_BIN, args, {
    input: text,
    encoding: "utf-8",
    timeout: 10_000,
    maxBuffer: 10 * 1024 * 1024, // 10 MB
  });

  if (result.error) {
    console.error(`[redactor] pattern redaction failed: ${result.error.message}`);
    return text; // Fail-open: return original
  }
  // redactor always appends a trailing newline; trim it to match original
  const out = result.stdout;
  return text.endsWith("\n") ? out : out.replace(/\n$/, "");
}

// ---------------------------------------------------------------------------
// Scan mode — find secrets without redacting
// ---------------------------------------------------------------------------

export interface Finding {
  rule: string;
  line: number;
  col: number;
  text: string;
}

/**
 * Scan text for secrets. Returns findings (empty array if clean).
 */
export function scanPattern(text: string): Finding[] {
  const result = spawnSync(REDACTOR_BIN, ["scan", "--no-log", "-"], {
    input: text,
    encoding: "utf-8",
    timeout: 10_000,
    maxBuffer: 10 * 1024 * 1024,
  });

  if (result.error) {
    console.error(`[redactor] scan failed: ${result.error.message}`);
    return [];
  }

  const lines = result.stdout.trim().split("\n").filter(Boolean);
  return lines.map((l) => {
    try {
      return JSON.parse(l) as Finding;
    } catch {
      return { rule: "parse_error", line: 0, col: 0, text: l };
    }
  });
}

// ---------------------------------------------------------------------------
// Structured redaction (CSV, JSON, ENV)
// ---------------------------------------------------------------------------

export type StructMode = "csv" | "json" | "env";

const MODE_FLAG: Record<StructMode, string> = {
  csv: "--type csv",
  json: "--type json",
  env: "--type env",
};

/**
 * Redact a structured file's content structurally.
 * CSV: header preserved, row data redacted.
 * JSON: structure preserved, leaf values redacted.
 * ENV: KEY=<redacted>, comments preserved.
 */
export function redactStructured(text: string, mode: StructMode): string {
  const args = [...MODE_FLAG[mode].split(" "), "--no-log", "-"];

  const result = spawnSync(REDACTOR_BIN, args, {
    input: text,
    encoding: "utf-8",
    timeout: 10_000,
    maxBuffer: 10 * 1024 * 1024,
  });

  if (result.error) {
    console.error(`[redactor] structural redaction (${mode}) failed: ${result.error.message}`);
    return text;
  }
  const out = result.stdout;
  return text.endsWith("\n") ? out : out.replace(/\n$/, "");
}

// ---------------------------------------------------------------------------
// Prompt-specific: redact and check if anything changed
// ---------------------------------------------------------------------------

/**
 * Redact a user prompt. Returns `{ sanitized, hasSecrets }`.
 * Used by the input hook to block prompts containing secrets.
 */
export function redactPrompt(prompt: string): { sanitized: string; hasSecrets: boolean } {
  const sanitized = redactPattern(prompt);
  const hasSecrets = sanitized !== prompt;
  return { sanitized, hasSecrets };
}

// ---------------------------------------------------------------------------
// Wrap mode: run a command through redactor
// ---------------------------------------------------------------------------

/**
 * Generate a `redactor wrap -- <cmd>` command string.
 */
export function wrapCommand(cmd: string): string {
  return `redactor wrap -- ${cmd}`;
}
