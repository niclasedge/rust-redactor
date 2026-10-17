#!/usr/bin/env bash
# Install the strict-redaction config into a target project.
# Requires: redactor 0.3.0+ on PATH (no bash, no jq runtime deps).
#
# Usage:
#   bash install.sh                 # installs into $PWD
#   bash install.sh /path/to/proj   # installs into another project

set -euo pipefail
target="${1:-$PWD}"
src_dir="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -d "$target" ]]; then
    echo "error: target directory does not exist: $target" >&2
    exit 1
fi

dest="$target/.claude"
if [[ -e "$dest" ]]; then
    backup="$dest.bak.$(date +%s)"
    echo "info: backing up existing $dest -> $backup"
    mv "$dest" "$backup"
fi

mkdir -p "$dest"
cp "$src_dir/claude/settings.json" "$dest/settings.json"
cp "$src_dir/claude/CLAUDE.md"     "$dest/CLAUDE.md"

echo "installed strict-redaction config at: $dest"
echo
echo "next steps:"
echo "  1. ensure redactor 0.3.0+ is installed (cargo install --path . or just install-win)"
echo "  2. seed keywords:  redactor init-config"
echo "  3. start Claude Code in $target — hooks fire automatically"
echo
echo "test it without an agent:"
echo "  redactor --type csv <some.csv>     # in-line structural redaction"
echo "  redactor wrap -- ./demo.sh         # wrap mode for subprocesses"
