/**
 * Smoke test for the redactor pi extension path-guard module.
 * Run: redactor wrap -- npx tsx path-guard.test.ts
 */

import {
  matchSensitivePath,
  matchCryptoContainer,
  matchOfficeDoc,
  matchSelfProtect,
  startsWithRedactor,
  isRedactorWrap,
  stripPatternArgs,
  matchOfficeDocInBash,
  detectStructFileInWrap,
  detectFileMode,
} from "./path-guard.js";

import { autoloadProjectConfig, loadRedactorIgnore, ignorefilePath } from "./config.js";

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e: any) {
    failed++;
    console.log(`  ✗ ${name}: ${e.message}`);
  }
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

function assertEq<T>(actual: T, expected: T, msg: string) {
  if (actual !== expected) throw new Error(`${msg}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

// ============================================================================
// Tests
// ============================================================================

console.log("\n=== matchSensitivePath ===");
test(".env blocked", () => {
  assert(matchSensitivePath("cat .env", []) !== null, ".env should be blocked");
});
test("README.md allowed", () => {
  assert(matchSensitivePath("cat README.md", []) === null, "README.md should be allowed");
});
test("id_rsa blocked", () => {
  assert(matchSensitivePath("cat ~/.ssh/id_rsa", []) !== null, "id_rsa should be blocked");
});
test("known_hosts allowed", () => {
  assert(matchSensitivePath("cat ~/.ssh/known_hosts", []) === null, "known_hosts should be allowed");
});
test(".pem blocked", () => {
  assert(matchSensitivePath("cat /home/user/key.pem", []) !== null, ".pem should be blocked");
});
test(".envrc blocked", () => {
  assert(matchSensitivePath("cat .envrc", []) !== null, ".envrc should be blocked");
});
test("/secrets/ blocked", () => {
  assert(matchSensitivePath("cat /secrets/token", []) !== null, "/secrets/ should be blocked");
});
test("whitelist allows", () => {
  assert(matchSensitivePath("cat .env", ["*.env"]) === null, "whitelist glob *.env should allow .env");
});

console.log("\n=== matchCryptoContainer ===");
test("vault.kdbx detected", () => {
  assertEq(matchCryptoContainer("cat vault.kdbx"), "KeePass database", "kdbx");
});
test("secret.gpg detected", () => {
  assertEq(matchCryptoContainer("secret.gpg"), "GPG-encrypted file", "gpg");
});
test("cert.p12 detected", () => {
  assertEq(matchCryptoContainer("certs/client.p12"), "PKCS#12 cert bundle", "p12");
});
test("foo.txt not crypto", () => {
  assert(matchCryptoContainer("foo.txt") === null, "txt should not match");
});

console.log("\n=== matchOfficeDoc ===");
test("sheet.xlsx detected", () => {
  assertEq(matchOfficeDoc("sheet.xlsx"), "Excel workbook", "xlsx");
});
test("report.pdf detected", () => {
  assertEq(matchOfficeDoc("report.pdf"), "PDF document", "pdf");
});
test("readme.md not office", () => {
  assert(matchOfficeDoc("readme.md") === null, "md should not match");
});

console.log("\n=== detectFileMode ===");
test("data.json → json", () => {
  assertEq(detectFileMode("data.json"), "json", "json");
});
test("data.csv → csv", () => {
  assertEq(detectFileMode("data.csv"), "csv", "csv");
});
test(".env → env", () => {
  assertEq(detectFileMode(".env"), "env", "env");
});
test("README.md → null", () => {
  assertEq(detectFileMode("README.md"), null, "null");
});

console.log("\n=== bash-strict ===");
test("redactor wrap is accepted", () => {
  assert(startsWithRedactor("redactor wrap -- ls"), "should accept redactor wrap");
});
test("ls is rejected", () => {
  assert(!startsWithRedactor("ls -la"), "should reject bare ls");
});

console.log("\n=== isRedactorWrap ===");
test("redactor wrap -- cat", () => {
  assert(isRedactorWrap("redactor wrap -- cat file.txt"), "should match wrap");
});
test("redactor --type csv is not wrap", () => {
  assert(!isRedactorWrap("redactor --type csv data.csv"), "should not match");
});

console.log("\n=== stripPatternArgs ===");
test("grep -E drops pattern arg", () => {
  const result = stripPatternArgs('grep -E ".pfx" file.txt');
  assert(!result.includes(".pfx"), "pattern arg should be removed");
});
test("cat keeps path", () => {
  const result = stripPatternArgs("cat /Users/x/vault.pfx");
  assert(result.includes("vault.pfx"), "path should be kept");
});

console.log("\n=== detectStructFileInWrap ===");
test("cat data.json in wrap", () => {
  const result = detectStructFileInWrap("redactor wrap -- cat data.json");
  assert(result !== null, "should detect json");
  assertEq(result!.mode, "json", "mode");
});
test("cat data.csv in wrap", () => {
  const result = detectStructFileInWrap("redactor wrap -- cat data.csv");
  assert(result !== null, "should detect csv");
});
test("echo not detected", () => {
  const result = detectStructFileInWrap("redactor wrap -- echo 'data.json'");
  assert(result === null, "echo should not trigger");
});

console.log("\n=== config ===");
test("autoloadProjectConfig works", () => {
  const cfg = autoloadProjectConfig(process.cwd());
  assert(typeof cfg.policy.strict_json === "boolean", "strict_json should be boolean");
  assert(typeof cfg.policy.mask_username === "boolean", "mask_username should be boolean");
  assert(Array.isArray(cfg.allow.paths), "paths should be array");
});
test("ignorefilePath resolves", () => {
  const p = ignorefilePath();
  console.log(`    ignorefilePath: ${p}`);
  assert(p !== null, "should have path");
});

// Summary
console.log(`\n${"=".repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
