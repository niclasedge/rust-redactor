/**
 * Path-guard logic — mirrors the Rust hook.rs sensitive-path detection.
 *
 * Detects sensitive paths (.env, .ssh, .aws, crypto containers, office docs,
 * .redactorignore self-protection) and provides allow-list matching.
 *
 * This runs in-process (no binary call) for speed — every bash/read/write/edit
 * tool_call goes through this before execution.
 */

import type { AllowSection, RedactorIgnore } from "./config.js";
import { loadRedactorIgnore, globToRegex, ignorefilePath } from "./config.js";
import { basename } from "node:path";
import { homedir } from "node:os";

// ============================================================================
// Sensitive-path patterns (hardcoded, mirrors Rust)
// ============================================================================

const SENSITIVE_PATH_RULES: [string, RegExp][] = [
  [".env", /(^|[\s/=:])\.env(\.|$|[\s])/],
  [".envrc", /(^|[\s/=:])\.envrc($|\.|[\s])/],
  ["id_rsa", /\/id_rsa($|\.|\/)/],
  ["AWS creds", /\/\.aws\/(credentials|config)/],
  ["/secrets/ folder", /\/secrets\//],
  [".pem", /[/~]\S*\.pem($|[^A-Za-z0-9_])/],
  [".key", /[/~]\S*\.key($|[^A-Za-z0-9_])/],
  [".netrc", /\/\.netrc($|\.)/],
  [".ssh/", /\/\.ssh\/[^\s]+/],
];

const CRYPTO_EXTS: [string, string][] = [
  [".kdbx", "KeePass database"],
  [".kdb", "KeePass database (legacy)"],
  [".gpg", "GPG-encrypted file"],
  [".pgp", "PGP-encrypted file"],
  [".asc", "ASCII-armored PGP file"],
  [".age", "age-encrypted file"],
  [".p12", "PKCS#12 cert bundle"],
  [".pfx", "PKCS#12 cert bundle"],
  [".keychain-db", "macOS Keychain"],
];

const OFFICE_EXTS: [string, string][] = [
  [".xlsx", "Excel workbook"],
  [".xls", "Excel workbook (legacy)"],
  [".xlsm", "Excel workbook (macro)"],
  [".docx", "Word document"],
  [".doc", "Word document (legacy)"],
  [".pptx", "PowerPoint presentation"],
  [".ppt", "PowerPoint presentation (legacy)"],
  [".pdf", "PDF document"],
];

// ============================================================================
// File mode detection (structured vs unstructured)
// ============================================================================

export type FileMode = "csv" | "json" | "env" | "pattern";

const STRUCT_EXTENSIONS: [string, FileMode][] = [
  [".json", "json"],
  [".jsonl", "json"],
  [".ndjson", "json"],
  [".csv", "csv"],
  [".tsv", "csv"],
];

export function detectFileMode(target: string): FileMode | null {
  // Check basename for env files first
  const base = basename(target).toLowerCase();
  if (base === ".env" || base === ".envrc" || base.startsWith(".env.") || base.endsWith(".env")) {
    return "env";
  }

  const lower = target.toLowerCase();
  for (const [ext, mode] of STRUCT_EXTENSIONS) {
    if (lower.endsWith(ext)) return mode;
  }
  return null;
}

// ============================================================================
// Sensitive path detection
// ============================================================================

export function matchSensitivePath(target: string, whitelist: string[]): string | null {
  // Whitelist check first
  if (whitelist.some((w) => pathMatchesGlob(target, w))) {
    return null;
  }

  for (const [label, re] of SENSITIVE_PATH_RULES) {
    if (!re.test(target)) continue;
    // .ssh allowlist: known_hosts is intentionally readable
    if (label === ".ssh/" && target.includes(".ssh/known_hosts")) continue;
    return label;
  }
  return null;
}

// ============================================================================
// Crypto container detection
// ============================================================================

export function matchCryptoContainer(target: string): string | null {
  const lower = target.toLowerCase();
  for (const [ext, label] of CRYPTO_EXTS) {
    const idx = lower.indexOf(ext);
    if (idx === -1) continue;
    // Boundary check
    const after = lower.slice(idx + ext.length);
    const nextChar = after.charAt(0);
    const boundaryOk =
      !nextChar || /\s|"|'|\)|;|\||`|&/.test(nextChar);
    if (boundaryOk) return label;
  }
  return null;
}

// ============================================================================
// Office document detection
// ============================================================================

export function matchOfficeDoc(target: string): string | null {
  const lower = target.toLowerCase();
  for (const [ext, label] of OFFICE_EXTS) {
    if (lower.endsWith(ext)) return label;
  }
  return null;
}

// ============================================================================
// Self-protection (.redactorignore)
// ============================================================================

export function matchSelfProtect(target: string): boolean {
  const igPath = ignorefilePath();
  if (!igPath) return false;

  // Quick string match
  if (target === igPath || target.includes(igPath)) return true;

  // Tilde form
  const home = homedir();
  const tildeForm = igPath.replace(home, "~");
  if (target.includes(tildeForm)) return true;

  return false;
}

// ============================================================================
// Project-level [allow] matching
// ============================================================================

export function isProjectAllowed(target: string, allow: AllowSection): boolean {
  if (allow.paths.length === 0 && allow.filetypes.length === 0) return false;

  // Path globs
  if (allow.paths.some((p) => pathMatchesGlob(target, p))) return true;

  // Filetype checks
  if (allow.filetypes.length > 0) {
    const lower = target.toLowerCase();
    if (allow.filetypes.some((ft) => lower.endsWith(ft.startsWith(".") ? ft : `.${ft}`))) {
      return true;
    }
  }

  return false;
}

// ============================================================================
// ~/.redactorignore matching
// ============================================================================

let _cachedIgnore: RedactorIgnore | null | undefined = undefined;

function getIgnore(): RedactorIgnore | null {
  if (_cachedIgnore === undefined) {
    _cachedIgnore = loadRedactorIgnore();
  }
  return _cachedIgnore;
}

export function matchRedactorignorePath(target: string): string | null {
  const ign = getIgnore();
  if (!ign || ign.paths.length === 0) return null;

  let matchPattern: string | null = null;
  for (const entry of ign.paths) {
    try {
      const re = globToRegex(entry.glob);
      if (re.test(target)) {
        matchPattern = entry.negate ? null : entry.raw;
      }
    } catch {
      // Bad glob, skip
    }
  }
  return matchPattern;
}

// ============================================================================
// Bash-strict: command analysis
// ============================================================================

const REDACTOR_BIN = "redactor";

/**
 * True if cmd starts with `redactor` (or `r`) as a bare command.
 */
export function startsWithRedactor(cmd: string): boolean {
  const trimmed = cmd.trimStart();
  return trimmed.startsWith(REDACTOR_BIN + " ") || trimmed === REDACTOR_BIN;
}

/**
 * True if cmd is `redactor wrap -- ...`
 */
export function isRedactorWrap(cmd: string): boolean {
  const trimmed = cmd.trimStart();
  return /^redactor\s+wrap\b/.test(trimmed);
}

// ============================================================================
// Shell tokenizer for pattern-literal stripping (Phase 7d)
// ============================================================================

const PATTERN_FLAGS = [
  "-e", "-E", "-P", "-G", "-g",
  "--regex", "--regexp", "--grep",
  "--include", "--exclude", "--include-glob", "--exclude-glob", "--glob",
];

/**
 * Tokenize a shell command respecting single/double quotes.
 */
function tokenizeShell(cmd: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inSingle = false;
  let inDouble = false;

  for (const ch of cmd) {
    if (ch === "'" && !inDouble) { inSingle = !inSingle; continue; }
    if (ch === '"' && !inSingle) { inDouble = !inDouble; continue; }
    if (/\s/.test(ch) && !inSingle && !inDouble) {
      if (cur) { out.push(cur); cur = ""; }
      continue;
    }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

/**
 * Strip pattern-literal arguments so `grep -E "\.pfx" file.txt` isn't blocked.
 */
export function stripPatternArgs(cmd: string): string {
  const tokens = tokenizeShell(cmd);
  const kept: string[] = [];
  let skipNext = false;

  for (const tok of tokens) {
    if (skipNext) { skipNext = false; continue; }
    // Glued form: `--regex=PATTERN`, `-E=PATTERN`
    if (PATTERN_FLAGS.some((f) => tok.startsWith(`${f}=`) || (f.length === 2 && tok.startsWith(f) && tok.length > 2))) {
      continue;
    }
    if (PATTERN_FLAGS.includes(tok)) {
      kept.push(tok);
      skipNext = true;
      continue;
    }
    kept.push(tok);
  }
  return kept.join(" ");
}

/**
 * Check if a bash command references an office document (for Read→Bash consistency).
 */
export function matchOfficeDocInBash(cmd: string): string | null {
  for (const tok of tokenizeShell(cmd)) {
    const bare = tok.replace(/[;,)"']/g, "");
    const lower = bare.toLowerCase();
    for (const [ext, label] of OFFICE_EXTS) {
      if (lower.endsWith(ext)) return label;
    }
  }
  return null;
}

// Show warning when bash references a structured file inside `redactor wrap`.
const READ_TOOLS = ["cat", "head", "tail", "less", "more", "view", "bat", "tac", "nl", "zcat", "gzcat", "jq", "yq"];

export function detectStructFileInWrap(cmd: string): { mode: FileMode; arg: string } | null {
  // Only relevant inside `redactor wrap`
  if (!isRedactorWrap(cmd)) return null;

  const tokens = tokenizeShell(cmd);
  let active = false;

  for (const tok of tokens) {
    const bare = tok.replace(/['"]/g, "");
    if (["|", "&", "&&", "||", ";", ">", "<", ">>", "<<"].includes(bare)) {
      active = false;
      continue;
    }
    if (bare.startsWith("-")) continue;

    if (active) {
      const mode = detectFileMode(bare);
      if (mode) return { mode, arg: bare };
    } else if (READ_TOOLS.some((t) => bare === t || bare.endsWith(`/${t}`) || bare.endsWith(`\\${t}`))) {
      active = true;
    }
  }
  return null;
}

// ============================================================================
// Helpers
// ============================================================================

function pathMatchesGlob(target: string, glob: string): boolean {
  try {
    return globToRegex(glob).test(target);
  } catch {
    // Direct substring match as fallback
    return target.includes(glob);
  }
}
