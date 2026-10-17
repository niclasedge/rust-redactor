/**
 * Config loading for the redactor pi extension.
 *
 * Reads .redactor.toml from the project root and resolves ~/.redactorignore.
 * Mirrors the Rust config.rs logic.
 */

import { readFileSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { homedir } from "node:os";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PolicySection {
  strict_json: boolean;
  mask_username: boolean;
}

export interface AllowSection {
  paths: string[];
  filetypes: string[];
}

export interface ProjectConfig {
  policy: PolicySection;
  allow: AllowSection;
  whitelist: string[];
  patterns: string[];
}

const DEFAULT_POLICY: PolicySection = {
  strict_json: true,
  mask_username: false,
};

const DEFAULT_ALLOW: AllowSection = {
  paths: [],
  filetypes: [],
};

// ---------------------------------------------------------------------------
// .redactor.toml
// ---------------------------------------------------------------------------

function parseRedactorToml(raw: string): Partial<ProjectConfig> {
  const cfg: Partial<ProjectConfig> = {
    policy: { ...DEFAULT_POLICY },
    allow: { ...DEFAULT_ALLOW },
    whitelist: [],
    patterns: [],
  };
  let section: string | null = null;

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1].trim();
      continue;
    }

    const kvMatch = trimmed.match(/^(\S+)\s*=\s*(.+)$/);
    if (!kvMatch || !section) continue;

    const [, key, rawVal] = kvMatch;
    const val = rawVal.trim().replace(/^"|"$/g, "").replace(/^'|'$/g, "");

    if (section === "policy") {
      if (key === "strict_json") cfg.policy!.strict_json = val === "true";
      else if (key === "mask_username") cfg.policy!.mask_username = val === "true";
    } else if (section === "allow") {
      if (key === "paths") cfg.allow!.paths = parseTomlArray(val);
      else if (key === "filetypes") cfg.allow!.filetypes = parseTomlArray(val);
    } else if (section === "whitelist") {
      if (key === "paths") cfg.whitelist = parseTomlArray(val);
    } else if (section === "patterns.custom") {
      cfg.patterns!.push(`${key} = ${val}`);
    }
  }
  return cfg;
}

function parseTomlArray(raw: string): string[] {
  const inner = raw.replace(/^\[|\]$/g, "").trim();
  if (!inner) return [];
  return inner
    .split(",")
    .map((s) => s.trim().replace(/^"|"$/g, "").replace(/^'|'$/g, ""))
    .filter(Boolean);
}

export function autoloadProjectConfig(cwd: string): ProjectConfig {
  const tomlPath = join(cwd, ".redactor.toml");
  try {
    const raw = readFileSync(tomlPath, "utf-8");
    const parsed = parseRedactorToml(raw);
    return {
      policy: { ...DEFAULT_POLICY, ...parsed.policy },
      allow: { ...DEFAULT_ALLOW, ...parsed.allow },
      whitelist: parsed.whitelist || [],
      patterns: parsed.patterns || [],
    };
  } catch {
    return {
      policy: { ...DEFAULT_POLICY },
      allow: { ...DEFAULT_ALLOW },
      whitelist: [],
      patterns: [],
    };
  }
}

// ---------------------------------------------------------------------------
// ~/.redactorignore
// ---------------------------------------------------------------------------

export interface RedactorIgnore {
  paths: { raw: string; glob: string; negate: boolean }[];
  keywords: string[];
}

export function ignorefilePath(): string | null {
  if (process.env.REDACTOR_IGNOREFILE_PATH) {
    return process.env.REDACTOR_IGNOREFILE_PATH;
  }
  return join(homedir(), ".redactorignore");
}

export function loadRedactorIgnore(): RedactorIgnore | null {
  const p = ignorefilePath();
  if (!p || !existsSync(p)) return null;

  const raw = readFileSync(p, "utf-8");
  const paths: RedactorIgnore["paths"] = [];
  const keywords: string[] = [];

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // Keywords: lines starting with "keyword:" or "keywords:"
    if (trimmed.startsWith("keyword:") || trimmed.startsWith("keywords:")) {
      const kw = trimmed.slice(trimmed.indexOf(":") + 1).trim();
      if (kw) keywords.push(kw);
      continue;
    }

    // Path globs
    const negate = trimmed.startsWith("!");
    const glob = negate ? trimmed.slice(1).trim() : trimmed;
    if (glob) paths.push({ raw: trimmed, glob, negate });
  }

  return { paths, keywords };
}

// ---------------------------------------------------------------------------
// Glob → Regex (for path matching)
// ---------------------------------------------------------------------------

export function globToRegex(glob: string): RegExp {
  let re = "^";
  let i = 0;
  while (i < glob.length) {
    if (glob[i] === "*" && glob[i + 1] === "*") {
      re += ".*";
      i += 2;
    } else if (glob[i] === "*") {
      re += "[^/]*";
      i += 1;
    } else if (glob[i] === "?") {
      re += "[^/]";
      i += 1;
    } else {
      // Escape regex special chars
      const ch = glob[i];
      if ("\\^$.*+?()[]{}|".includes(ch)) {
        re += "\\" + ch;
      } else {
        re += ch;
      }
      i += 1;
    }
  }
  re += "$";
  return new RegExp(re);
}
