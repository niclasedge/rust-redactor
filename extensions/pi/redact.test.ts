/**
 * Smoke test for the redact module.
 * Run: redactor wrap -- bash -c 'cd ~/.pi/agent/extensions/redactor && npx tsx redact.test.ts'
 */

import { redactPattern, scanPattern, redactStructured, redactPrompt } from "./redact.js";

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

// ============================================================================

console.log("\n=== redactPattern ===");
test("redacts OpenAI key", () => {
  const result = redactPattern("OPENAI_API_KEY=sk-proj-realtoken123abcdefgh");
  assert(result.includes("<redacted:openai_key>"), "should redact key");
  assert(!result.includes("sk-proj"), "should remove secret");
});
test("redacts GitHub token", () => {
  const result = redactPattern("github=ghp_realtokenwouldbeahere1234567890");
  assert(result.includes("<redacted:github_token>"), "should redact token");
});
test("redacts Anthropic key", () => {
  const result = redactPattern("ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
  assert(result.includes("<redacted:anthropic_key>"), "should redact anthropic key");
});
test("redacts email when keyword configured", () => {
  // Email redaction requires keywords. Default patterns don't include generic email.
  // Test that the redactor is loaded properly by verifying it doesn't crash.
  const result = redactPattern("Contact: user@example.com for support");
  assert(typeof result === "string", "should return string");
  // Without keyword config, email passes through — that's expected default behavior.
  // Add a keyword to test full flow.
  const result2 = redactPattern("Contact: user@example.com for support", ["user@example.com"]);
  assert(result2.includes("<redacted:keyword>"), "should redact when keyword set");
});
test("passes clean text through", () => {
  const result = redactPattern("The quick brown fox jumps over the lazy dog.");
  assert(result.trim() === "The quick brown fox jumps over the lazy dog.", "should be unchanged");
});

console.log("\n=== scanPattern ===");
test("finds OpenAI key", () => {
  const findings = scanPattern("OPENAI_API_KEY=sk-proj-realtoken123abcdefgh");
  assert(findings.length > 0, "should find secrets");
  assert(findings.some(f => f.rule === "openai_key"), "should have openai_key rule");
});
test("no findings for clean text", () => {
  const findings = scanPattern("Hello world, nothing to see here.");
  assert(findings.length === 0, "should have no findings");
});

console.log("\n=== redactStructured ===");
test("redacts JSON structurally", () => {
  const result = redactStructured('{"api_key": "sk-secret123", "name": "test"}', "json");
  assert(result.includes("<redacted>"), "should have redacted values");
});
test("redacts CSV structurally", () => {
  const result = redactStructured("name,email,age\nAlice,alice@example.com,30", "csv");
  assert(result.includes("<redacted>"), "should redact data rows");
  assert(result.includes("name,email,age"), "should keep header");
});
test("redacts ENV structurally", () => {
  const result = redactStructured("SECRET=abc123\nDEBUG=true\n# comment", "env");
  assert(result.includes("SECRET=<redacted>"), "should redact SECRET");
  assert(result.includes("DEBUG=<redacted>"), "should redact DEBUG");
  assert(result.includes("# comment"), "should keep comment");
});

console.log("\n=== redactPrompt ===");
test("detects secret in prompt", () => {
  // Use a key long enough to match the built-in pattern
  const { sanitized, hasSecrets } = redactPrompt("My API key is sk-proj-this-is-a-real-looking-key-1234567890");
  assert(hasSecrets, "should detect secret");
  assert(sanitized.includes("<redacted:openai_key>"), "should redact");
});
test("clean prompt no detection", () => {
  const { sanitized, hasSecrets } = redactPrompt("What is the weather today?");
  assert(!hasSecrets, "should not detect secret in clean text");
  assert(sanitized === "What is the weather today?", "should be unchanged");
});

// Summary
console.log(`\n${"=".repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
