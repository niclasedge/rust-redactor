#!/usr/bin/env bash
# install-binary.sh — fetch the prebuilt `redactor` binary into the plugin's
# bin/ directory. Invoked by the /redactor:install slash command on
# Linux and macOS. The Windows equivalent is install-binary.ps1.
#
# Behaviour:
#   1. Resolve the plugin root (prefer $CLAUDE_PLUGIN_ROOT, else the parent of
#      this script's directory).
#   2. Detect the target triple from uname.
#   3. Download redactor-<target>.tar.gz + SHA256SUMS.txt from the rolling
#      GitHub release (tag "rolling" by default; override with --tag / env),
#      verify the checksum, extract, and install into <plugin-root>/bin.
#
# Fails closed (non-zero exit) on any download / checksum error so the caller
# can surface the problem instead of silently leaving hooks broken.
#
# Usage:
#   bash install-binary.sh [--tag <release-tag>] [--force]
# Env overrides:
#   CLAUDE_PLUGIN_ROOT   plugin root (set by Claude Code)
#   REDACTOR_RELEASE_TAG release tag to pull (default: rolling)
#   REDACTOR_REPO        owner/repo (default: niclasedge/rust-redactor)

set -euo pipefail

REPO="${REDACTOR_REPO:-niclasedge/rust-redactor}"
TAG="${REDACTOR_RELEASE_TAG:-rolling}"
FORCE=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --tag) [ "$#" -ge 2 ] || { echo "install-binary.sh: --tag requires a value" >&2; exit 2; }; TAG="$2"; shift 2 ;;
        --tag=*) TAG="${1#--tag=}"; shift ;;
        --force) FORCE=1; shift ;;
        *) echo "install-binary.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

# --- resolve plugin root + bin dir -----------------------------------------
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_root="${CLAUDE_PLUGIN_ROOT:-$(cd "${script_dir}/.." && pwd)}"
bin_dir="${plugin_root}/bin"

# --- detect target triple ---------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
    Linux)
        case "$arch" in
            x86_64|amd64)  target="x86_64-unknown-linux-musl" ;;
            aarch64|arm64)
                echo "install-binary.sh: no prebuilt ARM64 Linux binary is published yet." >&2
                echo "  Build from source instead: cargo install --git https://github.com/${REPO}" >&2
                exit 1 ;;
            *) echo "install-binary.sh: unsupported Linux arch: $arch" >&2; exit 1 ;;
        esac ;;
    Darwin)
        case "$arch" in
            x86_64|amd64)  target="x86_64-apple-darwin" ;;
            arm64|aarch64) target="aarch64-apple-darwin" ;;
            *) echo "install-binary.sh: unsupported macOS arch: $arch" >&2; exit 1 ;;
        esac ;;
    *)
        echo "install-binary.sh: unsupported OS: $os (use install-binary.ps1 on Windows)" >&2
        exit 1 ;;
esac

# Versioned tags (v1.2.3 / 1.2.3) carry release.yml's versioned asset names;
# the rolling tag (and anything else) uses version-less names.
case "$TAG" in
    v[0-9]*|[0-9]*) asset="redactor-${TAG#v}-${target}.tar.gz" ;;
    *)              asset="redactor-${target}.tar.gz" ;;
esac
base="https://github.com/${REPO}/releases/download/${TAG}"

if [ -x "${bin_dir}/redactor" ] && [ "$FORCE" -ne 1 ]; then
    echo "redactor already present at ${bin_dir}/redactor (use --force to reinstall)"
    "${bin_dir}/redactor" --version || true
    exit 0
fi

# --- download ---------------------------------------------------------------
mkdir -p "${bin_dir}"
tmp="$(mktemp -d 2>/dev/null || mktemp -d -t redactor-install.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT

_fetch() { # url out
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --retry-delay 1 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        echo "install-binary.sh: need curl or wget" >&2; return 1
    fi
}

echo "redactor: downloading ${asset} from ${base}" >&2
_fetch "${base}/${asset}" "${tmp}/${asset}" \
    || { echo "install-binary.sh: download failed (${base}/${asset})" >&2; exit 1; }
_fetch "${base}/SHA256SUMS.txt" "${tmp}/SHA256SUMS.txt" \
    || { echo "install-binary.sh: SHA256SUMS.txt download failed" >&2; exit 1; }

# --- verify checksum --------------------------------------------------------
# Exact field match (handles GNU "HASH  file" and BSD "HASH *file"); no regex
# metacharacters from ${asset} (the dots in .tar.gz must not act as wildcards).
expected="$(awk -v a="$asset" '($2==a)||($2=="*"a){print $1; exit}' "${tmp}/SHA256SUMS.txt")"
if [ -z "$expected" ]; then
    echo "install-binary.sh: ${asset} not listed in SHA256SUMS.txt" >&2; exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${tmp}/${asset}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')"
else
    echo "install-binary.sh: no sha256 tool available" >&2; exit 1
fi
if [ "$expected" != "$actual" ]; then
    echo "install-binary.sh: SHA256 mismatch for ${asset}" >&2
    echo "  expected: ${expected}" >&2
    echo "  actual:   ${actual}" >&2
    exit 1
fi

# --- extract + install ------------------------------------------------------
tar -xzf "${tmp}/${asset}" -C "${tmp}" \
    || { echo "install-binary.sh: tar extract failed" >&2; exit 1; }
found="$(find "${tmp}" -type f -name redactor | head -n1)"
if [ -z "$found" ]; then
    echo "install-binary.sh: redactor binary not found inside ${asset}" >&2; exit 1
fi
install -m 0755 "$found" "${bin_dir}/redactor" 2>/dev/null \
    || { cp "$found" "${bin_dir}/redactor"; chmod 0755 "${bin_dir}/redactor"; }

echo "redactor installed -> ${bin_dir}/redactor"
"${bin_dir}/redactor" --version
