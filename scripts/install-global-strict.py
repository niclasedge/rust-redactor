"""Install redactor strict-mode globally (~/.claude/).

Idempotent:
  - settings.json: merges hook entries; existing entries (SessionStart, Stop, etc.)
    stay untouched. Re-runs add nothing.
  - CLAUDE.md: writes a managed block delimited by HTML comment markers.
    Re-runs replace the existing block in place so wording updates flow through.

Backups:
  - settings.json -> settings.json.bak.<unix-ts> (only on first run)
"""

import json
import pathlib
import shutil
import sys
import time

HOME = pathlib.Path.home()
SETTINGS = HOME / ".claude" / "settings.json"
CLAUDE_MD = HOME / ".claude" / "CLAUDE.md"

# ---- Hook map -----------------------------------------------------------------
# (event, matcher, command). matcher=None means "no matcher field" (event-wide).
HOOKS = [
    ("PreToolUse",       "Bash|PowerShell",        "redactor hook pre-bash"),
    ("PreToolUse",       "Read",                   "redactor hook pre-read"),
    ("PreToolUse",       "Grep",                   "redactor hook deny-grep"),
    ("PreToolUse",       "NotebookEdit",           "redactor hook deny-notebook"),
    ("PreToolUse",       "mcp__.*",                "redactor hook deny-mcp"),
    ("PostToolUse",      "Read|Bash|PowerShell",   "redactor hook post-tool"),
    ("PostToolUse",      "Write|Edit",             "redactor hook post-write"),
    ("UserPromptSubmit", None,                     "redactor hook prompt"),
    ("SessionStart",     None,                     "redactor hook session-start"),
]

# ---- settings.json ------------------------------------------------------------
SETTINGS.parent.mkdir(parents=True, exist_ok=True)
if SETTINGS.exists():
    backup = SETTINGS.with_name(f"settings.json.bak.{int(time.time())}")
    shutil.copy2(SETTINGS, backup)
    print(f"backup: {backup.name}")
    data = json.loads(SETTINGS.read_text(encoding="utf-8"))
else:
    print("note: ~/.claude/settings.json does not exist — creating fresh")
    data = {}

hooks = data.setdefault("hooks", {})

added = []
for event, matcher, cmd in HOOKS:
    entries = hooks.setdefault(event, [])
    found = False
    for e in entries:
        if e.get("matcher") == matcher and any(
            h.get("command") == cmd for h in e.get("hooks", [])
        ):
            found = True
            break
    if found:
        continue
    entry = {"hooks": [{"type": "command", "command": cmd}]}
    if matcher is not None:
        entry["matcher"] = matcher
    entries.append(entry)
    added.append(f"{event} [{matcher or '*'}] -> {cmd}")

SETTINGS.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"settings.json: {len(added)} new hook(s) added")
for a in added:
    print(f"  + {a}")

# ---- CLAUDE.md ----------------------------------------------------------------
MARKER_START = "<!-- BEGIN: redactor strict mode (managed block — do not edit between markers) -->"
MARKER_END   = "<!-- END: redactor strict mode -->"

SECTION = f"""{MARKER_START}

# Redactor Strict Mode (global)

`redactor` ist global an Claude-Code-Hooks gebunden. Tool-Output und User-Input werden gefiltert; manche Tools sind komplett deaktiviert.

## Was du SIEHST in Tool-Output

`<redacted:LABEL>`-Platzhalter ersetzen jeden Wert, der einer Pattern oder Keyword entspricht:

| Platzhalter | Bedeutung |
|---|---|
| `<redacted>` | strukturelle Redaktion (CSV-Zelle, JSON-Leaf, env-Wert) |
| `<redacted:openai_key>` / `:anthropic_key` / `:aws_access_key` / `:github_token` / `:slack_token` / `:stripe_live>` / `:jwt` / `:private_key` | bekannte Secret-Patterns |
| `<redacted:keyword>` | Treffer aus `~/.config/redactor/keywords.txt` |
| `<redacted:<custom>>` | User-Regex aus `patterns.json` |

**Behandle Platzhalter als sealed.** NIEMALS:
- versuchen, den Original-Wert zu rekonstruieren
- den User um die unredacted Version bitten
- vorschlagen, den Hook zu deaktivieren

Wenn ein Platzhalter legitime Arbeit blockiert: nenne den spezifischen Token (`<redacted:keyword> blockiert X`) — der User entscheidet über Ausnahmen.

## Was deaktiviert ist (in JEDEM Projekt)

| Tool | Status | Workaround |
|---|---|---|
| `Read` | strukturierte Files block (`.json/.csv/.tsv/.env/.envrc`); Source/Text geht durch | `r --type X <file>` für die genannten · sonst Read direkt; `post-tool` sanitisiert pattern-matches (`<redacted:LABEL>`) |
| `Grep` | komplett aus | `r wrap -- rg "pattern" <path>` |
| `NotebookEdit` | komplett aus | bei Bedarf User um Ausnahme bitten |
| `mcp__*` (alle MCP-Tools) | komplett aus | bei Bedarf User um Ausnahme bitten |
| `Bash` / `PowerShell` | strict — jeder Call muss `r wrap --` (oder `redactor wrap --`) prefixen | `r wrap -- <cmd>` |

`r` ist der globale Short-Alias für `redactor` (gleiche Binary, 8 Zeichen kürzer). zsh-Nutzer: `r` kollidiert mit dem History-Recall-Builtin — entweder `disable r` in `~/.zshenv` oder `\\r wrap -- ...` escapen. Bash/pwsh ist out-of-the-box OK.

## Bash/PowerShell — die einzig akzeptierte Form

```bash
r wrap -- ./run.sh
r wrap -- bash -c "./step1 && ./step2"
r wrap --keywords "EXTRA-SECRET" -- kubectl logs deploy/api
```

REJECTED:
```bash
./run.sh                     # bare command
./run.sh | redactor          # pipe form (works for binary, not for hook)
```

Wenn ein Call abgelehnt wird mit `redactor strict mode: every shell command must go through redactor`: einfach `r wrap --` voranstellen und retry. Niemals einen Wrapper-Script bauen, der den inneren Befehl versteckt.

## Read — was geht und was nicht

`Read` ist nur für **strukturierte Files** geblockt — dort kann pattern-mode Werte verfehlen, die keinem Regex folgen (z.B. Customer-IDs in CSV-Spalte 4). Für diese musst du Strukturmodus nutzen:

```bash
r --type json   <file.json>      # JSON: Leaves redacted, erste Liste-Item bleibt
r --type csv    <file.csv>       # CSV:  Header verbatim, Row 2 redacted, Rest weg
r --type env    <file.env>       # ENV:  KEY=<redacted>, Kommentare bleiben
r              <file>            # Auto-detect via Endung
```

Strukturmodus sanitisiert die Bytes BEVOR sie auf stdout gehen → die UI zeigt dem User auch den maskierten Output, nicht nur dem Modell. Richtig für Configs, Secret-Stores, exportierte Daten.

**Source/Markdown/Text geht direkt** — `Read` darf `.rs`/`.py`/`.ts`/`.md`/`Justfile`/`Makefile`/usw. öffnen. `post-tool` läuft auf das Ergebnis und ersetzt Secret-Pattern-Treffer durch `<redacted:LABEL>`, bevor das Modell den Output sieht. Keyword-Treffer aus `~/.config/redactor/keywords.txt` ebenso.

Wenn du absichtlich raw-Bytes brauchst (z.B. Binary-File-Header), `r wrap -- cat` benutzen — line-buffered Pattern-Mode, kein Strukturwissen.

## Sensitive Paths (path-guard)

Read und Bash-Calls auf folgende Patterns werden gepfändet:
- `*.env`, `*.envrc`, `.env.*`
- `id_rsa*`, `.ssh/*` (außer `known_hosts`)
- `.aws/credentials`, `.aws/config`
- `**/secrets/**`, `**/*.pem`, `**/*.key`

Bei Bedarf: User um spezifische Ausnahme bitten. Niemals via `cat`/`head`/`tail`/Shell-Redirection umgehen — der Hook applied auf alle Bash-Formen.

## Audit-Log

Jede Redaktion wird nach `<cwd>/logs/YYYY-MM-DD-redacted.log` (oder `$REDACTOR_LOG_DIR`) geschrieben. Felder: `timestamp / source / command / mode / rule / count / sample`. Wenn du wissen willst, was redacted wurde: User kann das Log zeigen — frag NIE nach Original-Daten.

## Keyword-Liste pflegen

```bash
r config-path                                           # zeigt Pfad
${{EDITOR:-vi}} $(r config-path | head -2 | tail -1 | cut -d= -f2 | cut -d' ' -f1)
```

Per-Call Keyword zusätzlich:
```bash
r wrap --keywords "EXTRA-TERM" -- <cmd>
```

Default-Pfad: `~/.config/redactor/keywords.txt` (Linux/Git Bash) · `%APPDATA%\\redactor\\` (Windows native).

{MARKER_END}
"""

CLAUDE_MD.parent.mkdir(parents=True, exist_ok=True)
current = CLAUDE_MD.read_text(encoding="utf-8") if CLAUDE_MD.exists() else ""
if MARKER_START in current:
    # Replace existing block in-place so re-runs pick up updated wording.
    i = current.find(MARKER_START)
    j = current.find(MARKER_END)
    if j == -1 or j < i:
        print("ERROR: CLAUDE.md has BEGIN marker but no matching END", file=sys.stderr)
        sys.exit(1)
    new_text = current[:i] + SECTION.rstrip() + current[j + len(MARKER_END):]
    if new_text != current:
        CLAUDE_MD.write_text(new_text, encoding="utf-8")
        print(f"CLAUDE.md: refreshed managed block ({len(SECTION)} chars)")
    else:
        print("CLAUDE.md: managed block already up-to-date")
else:
    if current and not current.endswith("\n"):
        current += "\n"
    CLAUDE_MD.write_text(current + "\n" + SECTION, encoding="utf-8")
    print(f"CLAUDE.md: appended managed block ({len(SECTION)} chars)")

print("done.")
