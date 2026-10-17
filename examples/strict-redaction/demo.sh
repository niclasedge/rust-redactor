#!/usr/bin/env bash
# Demo script that prints a mix of public log lines + secrets.
# Use it to verify the strict-redaction hook chain end-to-end.
#
# Strict mode is wrap-only:
#   ./demo.sh                  # raw, all secrets visible (use only for inspection)
#   redactor wrap -- ./demo.sh # all secrets redacted, stdout+stderr both filtered,
#                              # exit code preserved
#
# Note: pipe form `./demo.sh | redactor` is intentionally NOT used here —
# the strict bash hook in this project only accepts `redactor wrap --`.

set -euo pipefail

echo "[2026-04-28 01:00:01] INFO  service starting"
echo "[2026-04-28 01:00:02] DEBUG OPENAI_API_KEY=sk-proj-DEMO1234567890abcdefghij"
echo "[2026-04-28 01:00:03] DEBUG anthropic=sk-ant-api03-DEMO1234567890abcdefghij"
echo "[2026-04-28 01:00:04] WARN  AWS creds: AKIAIOSFODNN7EXAMPLE"
echo "[2026-04-28 01:00:05] AUTH  Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signaturefakehere" >&2
echo "[2026-04-28 01:00:06] DEBUG password = 'hunter2-very-secret'"
echo "[2026-04-28 01:00:07] DEBUG token=ghp_DEMOdemodemodemodemo1234567890aaaa"
echo "[2026-04-28 01:00:08] INFO  customer Alice Mustermann placed order #4711"
echo "[2026-04-28 01:00:09] INFO  shipped PROJECT-NIGHTHAWK to internal-host.corp"
echo "[2026-04-28 01:00:10] INFO  done"
