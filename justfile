# redactor — Justfile
#
# Cross-platform task runner. Works on macOS, Linux, and Windows (PowerShell or
# cmd.exe). `just` is required: https://github.com/casey/just
#
#   brew install just                                  # macOS
#   winget install --id Casey.Just                     # Windows
#   cargo install just                                 # any platform
#
# List recipes: `just`           Run a recipe: `just <name>`

# Default: show available recipes
default:
    @just --list

# ---------- core dev loop ----------

# Run all tests (unit + integration). Cross-platform.
test:
    cargo test

# Build optimized release binary at target/release/redactor[.exe]
build:
    cargo build --release

# Lint with clippy (warnings as errors)
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
    cargo fmt

# Clean build artifacts AND local logs
clean:
    cargo clean
    rm -rf logs

# ---------- preflight ----------

# Verify build/runtime dependencies and print fix instructions for any
# missing pieces. Run before `just install-*` on a fresh machine. The
# Windows variant additionally checks for the PortableMSVC linker that
# `[windows] install-win` needs.
[unix]
doctor:
    #!/usr/bin/env bash
    set -u
    fail=0; warn=0
    G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; N=$'\033[0m'
    chk() {
        local label="$1" cmd="$2" fix="$3"
        if v=$(eval "$cmd" 2>/dev/null | head -1) && [ -n "$v" ]; then
            printf "  %sOK%s    %-25s %s%s%s\n" "$G" "$N" "$label" "$D" "$v" "$N"
        else
            printf "  %sMISS%s  %-25s missing\n        -> %s\n" "$R" "$N" "$label" "$fix"
            fail=$((fail+1))
        fi
    }
    opt() {
        local label="$1" cmd="$2" fix="$3"
        if v=$(eval "$cmd" 2>/dev/null | head -1) && [ -n "$v" ]; then
            printf "  %sOK%s    %-25s %s%s%s\n" "$G" "$N" "$label" "$D" "$v" "$N"
        else
            printf "  %sWARN%s  %-25s missing (optional)\n        -> %s\n" "$Y" "$N" "$label" "$fix"
            warn=$((warn+1))
        fi
    }
    PATH="$HOME/.cargo/bin:$PATH"
    echo "redactor — dependency check"
    echo "Required:"
    chk "cargo (rustup)" "cargo --version" \
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   (per-user, no admin)"
    chk "rustfmt"        "rustfmt --version"      "rustup component add rustfmt"
    chk "clippy"         "cargo clippy --version" "rustup component add clippy"
    chk "git"            "git --version"          "macOS: brew install git · Linux: distro package"
    chk "bash"           "bash --version"         "should ship with the OS"
    echo "Optional:"
    opt "jq"             "jq --version"           "macOS: brew install jq · Linux: distro package"
    echo
    if [ "$fail" -gt 0 ]; then
        printf "%sFAIL%s: %d required dependency missing — fix above, re-run 'just doctor'.\n" "$R" "$N" "$fail"
        exit 1
    fi
    [ "$warn" -gt 0 ] && printf "%sOK%s: all required deps present (%d optional missing).\n" "$G" "$N" "$warn" \
                       || printf "%sOK%s: all dependencies present.\n" "$G" "$N"

[windows]
doctor:
    #!/usr/bin/env bash
    set -u
    fail=0; warn=0
    G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; N=$'\033[0m'
    # Normalize Windows-style env vars to bash-friendly paths so eval'd commands work.
    USR=$(cygpath -u "$USERPROFILE" 2>/dev/null || printf '%s' "$USERPROFILE")
    LAD=$(cygpath -u "$LOCALAPPDATA" 2>/dev/null || printf '%s' "$LOCALAPPDATA")
    PATH="$USR/.cargo/bin:$PATH"
    chk() {
        local label="$1" cmd="$2" fix="$3"
        if v=$(eval "$cmd" 2>/dev/null | head -1) && [ -n "$v" ]; then
            printf "  %sOK%s    %-25s %s%s%s\n" "$G" "$N" "$label" "$D" "$v" "$N"
        else
            printf "  %sMISS%s  %-25s missing\n        -> %s\n" "$R" "$N" "$label" "$fix"
            fail=$((fail+1))
        fi
    }
    chk_file() {
        local label="$1" path="$2" fix="$3"
        if [ -f "$path" ]; then
            printf "  %sOK%s    %-25s %s%s%s\n" "$G" "$N" "$label" "$D" "$path" "$N"
        else
            printf "  %sMISS%s  %-25s not found at %s\n        -> %s\n" "$R" "$N" "$label" "$path" "$fix"
            fail=$((fail+1))
        fi
    }
    opt() {
        local label="$1" cmd="$2" fix="$3"
        if v=$(eval "$cmd" 2>/dev/null | head -1) && [ -n "$v" ]; then
            printf "  %sOK%s    %-25s %s%s%s\n" "$G" "$N" "$label" "$D" "$v" "$N"
        else
            printf "  %sWARN%s  %-25s missing (optional)\n        -> %s\n" "$Y" "$N" "$label" "$fix"
            warn=$((warn+1))
        fi
    }
    echo "redactor — dependency check (Windows)"
    echo "Required:"
    chk      "cargo (rustup)"      "cargo --version" \
             "winget install Rustlang.Rustup  -or-  https://win.rustup.rs/x86_64  (per-user, no admin)"
    chk      "rustfmt"             "rustfmt --version" \
             "rustup component add rustfmt"
    chk      "clippy"              "cargo clippy --version" \
             "rustup component add clippy"
    chk_file "PortableMSVC linker" "$LAD/PortableMSVC/msvc/setup_x64.bat" \
             "https://github.com/Data-Oriented-House/PortableBuildTools  (per-user, no admin)"
    chk      "git"                 "git --version"  "winget install Git.Git"
    chk      "bash"                "bash --version" "ships with Git for Windows (winget install Git.Git)"
    if command -v rustup >/dev/null 2>&1; then
        tc=$(rustup show active-toolchain 2>/dev/null | head -1 || true)
        if echo "$tc" | grep -q msvc; then
            printf "  %sOK%s    %-25s %s%s%s\n" "$G" "$N" "active toolchain" "$D" "$tc" "$N"
        else
            printf "  %sMISS%s  %-25s %s\n        -> rustup default stable-x86_64-pc-windows-msvc\n" \
                "$R" "$N" "active toolchain" "${tc:-unknown}"
            fail=$((fail+1))
        fi
    fi
    echo "Optional:"
    opt "jq"             "jq --version"        "winget install jqlang.jq"
    opt "PowerShell 7+"  "pwsh --version"      "winget install Microsoft.PowerShell"
    echo
    if [ "$fail" -gt 0 ]; then
        printf "%sFAIL%s: %d required dependency missing — fix above, re-run 'just doctor'.\n" "$R" "$N" "$fail"
        exit 1
    fi
    [ "$warn" -gt 0 ] && printf "%sOK%s: all required deps present (%d optional missing).\n" "$G" "$N" "$warn" \
                       || printf "%sOK%s: all dependencies present.\n" "$G" "$N"

# ---------- install ----------

# Install the binary to ~/.cargo/bin (works on macOS, Linux, Windows)
install:
    cargo install --path . --force

# Uninstall
uninstall:
    cargo uninstall redactor

# macOS: install to /usr/local/bin (system-wide, requires sudo)
[macos]
install-system:
    cargo build --release
    sudo install -m 0755 target/release/redactor /usr/local/bin/redactor
    @echo "installed to /usr/local/bin/redactor"

# Mirrors the cc-task build-win pattern so a system without VS Build Tools
# can still produce redactor.exe.
#
# PATH order matters: cargo *first*, MSVC via setup_x64.bat *second* —
# reversing it can cause cmd to silently truncate %PATH% and cargo falls
# back to Git Bash's GNU `link` ("link: extra operand" error).
#
# Prereqs (per-user, no admin needed):
#   - rustup:       https://win.rustup.rs/x86_64
#   - PortableMSVC: https://github.com/Data-Oriented-House/PortableBuildTools
#                   installed to %LOCALAPPDATA%\PortableMSVC\msvc
#
# Windows: build with PortableMSVC (per-user, no admin) + cargo install.
[windows]
install-win: && install-alias
    #!/usr/bin/env bash
    set -eu
    test -f "$USERPROFILE/.cargo/bin/cargo.exe" \
        || { echo "rustup missing — install from https://win.rustup.rs/x86_64 (per-user, no admin)"; exit 1; }
    test -f "$LOCALAPPDATA/PortableMSVC/msvc/setup_x64.bat" \
        || { echo "PortableMSVC missing at %LOCALAPPDATA%\\PortableMSVC\\msvc — see https://github.com/Data-Oriented-House/PortableBuildTools"; exit 1; }
    cmd //c "set PATH=%USERPROFILE%\.cargo\bin;%PATH% && call %LOCALAPPDATA%\PortableMSVC\msvc\setup_x64.bat && cargo install --path . --force"
    # Mirror the binary into ~/bin (Git Bash default PATH) so `redactor`
    # resolves in shells that don't have ~/.cargo/bin on PATH. NTFS locks
    # an open .exe against `cp` (overwrite) but allows `mv` (rename) — so
    # we move the live copy aside first, then drop in the new one. Old
    # .exe.old stays on disk until the locking process exits and a future
    # run can clean it up.
    mkdir -p "$HOME/bin"
    src="$USERPROFILE/.cargo/bin/redactor.exe"
    dest="$HOME/bin/redactor.exe"
    if [ -f "$dest" ] && ! cp "$src" "$dest" 2>/dev/null; then
        mv "$dest" "$dest.old.$(date +%s)" 2>/dev/null || true
        cp "$src" "$dest"
    elif [ ! -f "$dest" ]; then
        cp "$src" "$dest"
    fi
    [ -f "$HOME/bin/redactor.exe.old."* ] 2>/dev/null && echo "note: previous ~/bin/redactor.exe was locked; renamed to .old.<ts> — cleanup in a fresh shell."
    echo "installed: $src and $dest"

# ---------- smoke ----------

# Quick smoke check that the installed binary works
smoke:
    @echo "=== filter mode ==="
    echo "key=sk-proj-FAKE12345678901234567890" | redactor
    @echo "=== wrap mode ==="
    redactor wrap -- echo "AKIA1234567890ABCDEF and ghp_abcdefghij1234567890ABCDEFGHIJaaaaaa"

# ---------- hook deployment ----------

# Print Codex hook config snippet (for ~/.codex/hooks.json or config.toml)
hook-codex-print:
    @cat docs/hooks/codex-hooks.json

# Install Codex hook config to ~/.codex/hooks.json (BACKS UP existing one)
hook-codex-install:
    @mkdir -p ~/.codex
    @if [ -f ~/.codex/hooks.json ]; then cp ~/.codex/hooks.json ~/.codex/hooks.json.bak.$(date +%s); fi
    cp docs/hooks/codex-hooks.json ~/.codex/hooks.json
    @echo "installed to ~/.codex/hooks.json (backup made if existed)"

# Print OpenCode plugin (paste into .opencode/plugin/redact-bash.ts)
hook-opencode-print:
    @cat docs/hooks/opencode-redact-bash.ts

# Install OpenCode plugin to current project's .opencode/plugin/
hook-opencode-install:
    @mkdir -p .opencode/plugin
    cp docs/hooks/opencode-redact-bash.ts .opencode/plugin/redact-bash.ts
    @echo "installed to .opencode/plugin/redact-bash.ts"

# Print Claude Code hook snippet
hook-claude-print:
    @cat docs/hooks/claude-code-hooks.json

# ---------- config ----------

# Write starter keywords.txt + patterns.json into the config dir
init-config:
    redactor init-config

# Show resolved config dir + whether files exist there
config-path:
    redactor config-path

# Edit the config keyword list (uses $EDITOR or 'vi')
edit-keywords:
    @${EDITOR:-vi} "$(redactor config-path | head -2 | tail -1 | cut -d= -f2 | cut -d' ' -f1)"

# ---------- maintenance ----------

# Show today's redaction log (current dir's logs/)
log:
    @cat logs/$(date +%Y-%m-%d)-redacted.log 2>/dev/null || echo "no log for today"

# Tail today's log live
log-tail:
    tail -F logs/$(date +%Y-%m-%d)-redacted.log

# Install the strict-redaction example into a target project (default: $PWD)
install-strict target=".":
    examples/strict-redaction/install.sh "{{target}}"

# Syntax-check all example shell scripts and validate settings.json
check-example:
    @for f in examples/strict-redaction/*.sh; do \
        bash -n "$f" && echo "  ok: $f" || (echo "  FAIL: $f"; exit 1); \
    done
    @if ls examples/strict-redaction/claude/hooks/*.sh 2>/dev/null | grep -q .; then \
        for f in examples/strict-redaction/claude/hooks/*.sh; do \
            bash -n "$f" && echo "  ok: $f" || (echo "  FAIL: $f"; exit 1); \
        done; \
    fi
    @jq . examples/strict-redaction/claude/settings.json > /dev/null && echo "  ok: settings.json"

# Run all checks before commit
ci: fmt lint test check-example
    @echo "all green"

# Install the `r` short-alias.
# unix:    symlink ~/.cargo/bin/r -> redactor
# windows: copy redactor.exe -> r.exe in ~/.cargo/bin and ~/bin (NTFS
#          symlinks need admin/dev-mode), and patch PowerShell $PROFILE
#          so the built-in `r -> Invoke-History` alias stops shadowing
#          the binary in interactive PowerShell.
[unix]
install-alias:
    #!/usr/bin/env bash
    set -euo pipefail
    bin_dir="${CARGO_HOME:-$HOME/.cargo}/bin"
    target="$bin_dir/redactor"
    link="$bin_dir/r"
    if [ ! -x "$target" ]; then
        echo "error: $target not found. run 'cargo install --path .' first." >&2
        exit 1
    fi
    if [ -L "$link" ] || [ -e "$link" ]; then
        rm -f "$link"
    fi
    ln -s "$target" "$link"
    echo "linked: $link -> $target"
    "$link" --version

[windows]
install-alias:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo_bin="${CARGO_HOME:-$HOME/.cargo}/bin"
    target="$cargo_bin/redactor.exe"
    if [ ! -x "$target" ]; then
        echo "error: $target not found. run 'just install-win' first." >&2
        exit 1
    fi
    install_r() {
        local dest="$1"
        local tmp="$dest.new.$$"
        # Stage to a fresh path first — never racy.
        cp "$target" "$tmp"
        # Try atomic replace via mv. NTFS MoveFileEx can rename over an
        # open .exe. If mv fails (rare locks), fall back to side-rename.
        if ! mv -f "$tmp" "$dest" 2>/dev/null; then
            [ -f "$dest" ] && mv -f "$dest" "$dest.old.$(date +%s)" 2>/dev/null || true
            mv -f "$tmp" "$dest"
        fi
    }
    install_r "$cargo_bin/r.exe"
    mkdir -p "$HOME/bin"
    install_r "$HOME/bin/r.exe"
    echo "installed: $cargo_bin/r.exe and $HOME/bin/r.exe"
    # pwsh (7+) and powershell.exe (5.1) have separate $PROFILE paths
    # (Documents\PowerShell vs Documents\WindowsPowerShell). Patch each
    # if present so the alias works regardless of which shell starts.
    patched_any=0
    for sh in pwsh powershell.exe; do
        if command -v "$sh" >/dev/null 2>&1; then
            "$sh" -NoProfile -ExecutionPolicy Bypass -File scripts/install-r-alias.ps1
            patched_any=1
        fi
    done
    [ "$patched_any" = "0" ] && echo "note: no PowerShell host found — skip profile patch"
    "$cargo_bin/r.exe" --version

# ---------- pi agent integration ----------

# Install redactor globally for pi coding agent.
# 1. Builds + installs the redactor binary
# 2. Copies the pi extension into ~/.pi/agent/extensions/redactor/
# 3. Smoke-tests that pi detects the extension
#
# After install, every pi session in every project runs redactor:
#   - Bash commands forced through `redactor wrap --`
#   - Sensitive paths (.env, .ssh, .pem) blocked at Read/Bash/Write
#   - Tool output scrubbed before the model sees it
#   - User prompts redacted before API call
#
# Prereqs: pi (npm i -g @earendil-works/pi-coding-agent)
[unix]
install-pi: && install-alias
    #!/usr/bin/env bash
    set -euo pipefail

    RED="\033[31m"; GREEN="\033[32m"; BOLD="\033[1m"; RESET="\033[0m"

    # ---- 1. Install pi if missing ----
    if ! command -v pi &>/dev/null; then
        echo "pi not found — installing via npm…"
        npm install -g --ignore-scripts @earendil-works/pi-coding-agent
    fi
    echo "pi: $(pi --version 2>/dev/null || echo 'installed')"

    # ---- 2. Redactor binary ----
    echo ""
    echo "${BOLD}installing redactor binary…${RESET}"
    cargo install --path . --force --quiet 2>&1 | tail -1 || {
        echo "${RED}cargo install failed — run 'rustup update' and retry${RESET}"
        exit 1
    }
    redactor --version

    # ---- 3. Pi extension ----
    EXT_DIR="$HOME/.pi/agent/extensions/redactor"
    JUSTFILE_DIR="$(dirname "{{justfile()}}")"
    SRC_DIR="$JUSTFILE_DIR/extensions/pi"

    if [ ! -d "$SRC_DIR" ]; then
        echo "${RED}extension source not found at $SRC_DIR${RESET}"
        exit 1
    fi

    mkdir -p "$EXT_DIR"
    cp "$SRC_DIR"/*.ts "$EXT_DIR/"
    echo "${GREEN}extension installed:${RESET} $EXT_DIR"
    ls -1 "$EXT_DIR"

    # ---- 4. Smoke test ----
    echo ""
    echo "${BOLD}smoke test — pi with redactor extension…${RESET}"
    SMOKE_OUT="$(pi -p -e "$EXT_DIR/index.ts" --no-tools "test" 2>&1 || true)"
    if echo "$SMOKE_OUT" | grep -q 'redactor.*session start'; then
        echo "${GREEN}✓${RESET} pi detects redactor extension"
    else
        echo "${RED}✗${RESET} extension smoke test failed — output:"
        echo "$SMOKE_OUT"
        exit 1
    fi

    echo ""
    echo "${GREEN}${BOLD}done.${RESET} redactor is active in every pi session globally."
    echo "Configure per-project overrides in .redactor.toml:"
    echo "  [policy]            strict_json = false"
    echo "  [allow]             paths = [\"*.env\"]"
