# redactor as a Claude Code plugin

`hook-redactor` doubles as a Claude Code **plugin**: installing it wires the
full strict-redaction hook stack into Claude Code and ships a `/redactor:install`
command that fetches the prebuilt binary for your OS. Works on Windows, macOS,
and Linux.

## Layout

The plugin lives at the repo root (auto-discovered dirs — do **not** list them
in `plugin.json`):

```
.claude-plugin/plugin.json        # plugin manifest (name: redactor)
.claude-plugin/marketplace.json   # marketplace (name: hook-redactor)
commands/install.md               # /redactor:install
commands/status.md                # /redactor:status
commands/uninstall.md             # /redactor:uninstall
hooks/hooks.json                  # 9 strict hooks -> ${CLAUDE_PLUGIN_ROOT}/bin/redactor
skills/redactor/SKILL.md          # agent behaviour guidance under strict mode
scripts/install-binary.sh         # binary bootstrap (Linux/macOS)
scripts/install-binary.ps1        # binary bootstrap (Windows)
bin/                              # binary lands here (git-ignored)
```

The hooks call `"${CLAUDE_PLUGIN_ROOT}/bin/redactor"` (quoted, PATH-independent).
The binary is **not** committed — `/redactor:install` downloads it.

## Install

```text
/plugin marketplace add niclasedge/rust-redactor
/plugin install redactor@hook-redactor
/redactor:install          # fetch the prebuilt binary into the plugin's bin/
```

For local development without a marketplace:

```bash
claude --plugin-dir /path/to/hook-redactor
```

Then `/redactor:install` inside that session.

## How the binary is delivered (prebuilt, cross-platform)

`/redactor:install` runs the OS-appropriate bootstrap:

| OS | Script | Asset |
|----|--------|-------|
| Linux | `scripts/install-binary.sh` | `redactor-x86_64-unknown-linux-musl.tar.gz` |
| macOS | `scripts/install-binary.sh` | `redactor-{x86_64,aarch64}-apple-darwin.tar.gz` |
| Windows | `scripts/install-binary.ps1` | `redactor-x86_64-pc-windows-msvc.zip` |

Each script downloads the asset **plus** `SHA256SUMS.txt` from the `rolling`
GitHub release, verifies the checksum, and installs into `bin/`.

## Releases — built on every push

`.github/workflows/rolling-release.yml` builds Linux + Windows + macOS binaries
on **every push to `main`** and republishes them to the `rolling` pre-release
with stable, version-less asset names:

```
https://github.com/niclasedge/rust-redactor/releases/download/rolling/redactor-<target>.tar.gz
```

Immutable, versioned releases are still produced by `release.yml` on `v*` tags.

Override the release tag at install time (version-aware: `v*` tags pull the
versioned asset names produced by `release.yml`):

```bash
REDACTOR_RELEASE_TAG=v0.8.0 bash scripts/install-binary.sh
```

### Platform coverage

Prebuilt: **x86_64** Linux (musl), **x86_64** Windows, and **x86_64 + arm64**
macOS. Windows-on-ARM uses the x64 build under emulation. **ARM64 Linux is not
prebuilt** — the bootstrap prints a clear message; build from source with
`cargo install --git https://github.com/niclasedge/rust-redactor`.

## Uninstall

```text
/redactor:uninstall          # removes the plugin-local binary
/plugin                      # toggle "redactor" off / uninstall the plugin
```

Per-user keyword/config files (`redactor config-path`) are left untouched.

## Notes / caveats

- Run `/redactor:install` **right after** installing the plugin. Until the
  binary exists, the hooks have nothing to call.
- A plugin update may re-fetch the plugin cache and clear `bin/` — just rerun
  `/redactor:install`.
- The hooks are owned by the plugin, so disabling the plugin removes them
  cleanly (no `~/.claude/settings.json` edits). The older
  `redactor install-plugin global/local` path (merging into `settings.json`)
  still exists for non-plugin setups.
