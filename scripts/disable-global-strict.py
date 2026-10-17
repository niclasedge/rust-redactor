"""Reversal of install-global-strict.py.

- restores ~/.claude/settings.json from the most recent .bak.<ts> file
  (with a fresh backup of the current state, in case)
- removes the marker-fenced 'redactor strict mode (managed)' block from
  ~/.claude/CLAUDE.md, leaving the file otherwise untouched

Idempotent: if backup is missing or block is absent, just reports it.
"""

import pathlib
import shutil
import sys
import time

HOME = pathlib.Path.home()
SETTINGS = HOME / ".claude" / "settings.json"
CLAUDE_MD = HOME / ".claude" / "CLAUDE.md"

# ---- 1. settings.json: restore from latest backup --------------------------
backups = sorted(SETTINGS.parent.glob("settings.json.bak.*"))
if not backups:
    print("warn: no settings.json.bak.* found — skipping restore", file=sys.stderr)
else:
    latest = backups[-1]
    if SETTINGS.exists():
        side = SETTINGS.with_name(f"settings.json.pre-disable.{int(time.time())}")
        shutil.copy2(SETTINGS, side)
        print(f"side-saved current: {side.name}")
    shutil.copy2(latest, SETTINGS)
    print(f"settings.json restored from: {latest.name}")

# ---- 2. CLAUDE.md: drop the managed block ---------------------------------
MARKER_START = "<!-- BEGIN: redactor strict mode (managed block — do not edit between markers) -->"
MARKER_END = "<!-- END: redactor strict mode -->"

if not CLAUDE_MD.exists():
    print("note: ~/.claude/CLAUDE.md does not exist — nothing to clean")
else:
    text = CLAUDE_MD.read_text(encoding="utf-8")
    i = text.find(MARKER_START)
    j = text.find(MARKER_END)
    if i == -1 or j == -1 or j < i:
        print("CLAUDE.md: no managed block found — no changes")
    else:
        # Strip the block plus one surrounding blank line on each side if present.
        before = text[:i].rstrip("\n")
        after = text[j + len(MARKER_END):].lstrip("\n")
        joined = (before + ("\n\n" if before and after else "") + after).rstrip() + "\n"
        CLAUDE_MD.write_text(joined, encoding="utf-8")
        print(f"CLAUDE.md: removed managed block ({j + len(MARKER_END) - i} chars)")

print("done — global strict mode disabled. Re-enable later with install-global-strict.py.")
