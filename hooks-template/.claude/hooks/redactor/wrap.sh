#!/usr/bin/env bash
# Thin wrapper invoked by .claude/settings.json hook commands.
#
# Sources _bootstrap.sh (idempotent: ~1ms when binary is already on PATH or
# cached, ~2-3s the first time on a clean GitHub Actions runner) and then
# execs `redactor` with whatever arguments the hook config supplies.
#
# Usage from settings.json:
#     "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/redactor/wrap.sh hook pre-bash"
set -e
_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_bootstrap.sh
. "${_dir}/_bootstrap.sh"
exec redactor "$@"
