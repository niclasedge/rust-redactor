#!/usr/bin/env bash
# Idempotent self-bootstrap for the redactor binary.
#
# Behaviour:
#   1. If `redactor` is already on PATH -> return (no-op, ~1ms).
#   2. If a previously-bootstrapped binary exists in CACHE_DIR -> prepend PATH, return.
#   3. Otherwise download the prebuilt release tarball matching VERSION
#      from github.com/niclasedge/rust-redactor/releases, verify SHA256,
#      extract to CACHE_DIR/bin, and prepend PATH.
#
# Cache locations (in priority order):
#   $REDACTOR_CACHE_DIR        — explicit override
#   $RUNNER_TEMP/redactor      — GitHub Actions runners
#   $HOME/.cache/redactor      — local dev (Linux/macOS, Git-Bash on Windows)
#
# Sourced by wrap.sh; designed to be safe to source repeatedly. Errors during
# download fail-closed (return non-zero) so the calling hook can surface the
# problem rather than silently allow.

# Fast path: already on PATH.
if command -v redactor >/dev/null 2>&1; then
    return 0 2>/dev/null || exit 0
fi

set -e

_redactor_bootstrap_dir() {
    local d="${REDACTOR_CACHE_DIR:-}"
    if [[ -z "$d" ]]; then
        if [[ -n "${RUNNER_TEMP:-}" ]]; then
            d="${RUNNER_TEMP}/redactor"
        else
            d="${HOME}/.cache/redactor"
        fi
    fi
    printf '%s' "$d"
}

_redactor_bootstrap_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64)  printf 'x86_64-unknown-linux-musl' ;;
                aarch64|arm64) printf 'aarch64-unknown-linux-musl' ;;
                *) return 1 ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64|amd64)  printf 'x86_64-apple-darwin' ;;
                arm64|aarch64) printf 'aarch64-apple-darwin' ;;
                *) return 1 ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*)
            printf 'x86_64-pc-windows-msvc'
            ;;
        *) return 1 ;;
    esac
}

_redactor_bootstrap_main() {
    local cache_dir bin_dir version target tarball_name url tmp expected actual ext
    cache_dir="$(_redactor_bootstrap_dir)"
    bin_dir="${cache_dir}/bin"

    # Re-use a previously bootstrapped binary if present.
    if [[ -x "${bin_dir}/redactor" ]] || [[ -x "${bin_dir}/redactor.exe" ]]; then
        export PATH="${bin_dir}:${PATH}"
        return 0
    fi

    if ! target="$(_redactor_bootstrap_target)"; then
        echo "redactor bootstrap: unsupported platform $(uname -s)/$(uname -m)" >&2
        return 1
    fi

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -r "${script_dir}/VERSION" ]]; then
        version="$(tr -d '\n\r \t' < "${script_dir}/VERSION")"
    fi
    : "${version:=0.6.0}"

    case "$target" in
        *windows*) ext="zip"    ;;
        *)         ext="tar.gz" ;;
    esac

    tarball_name="redactor-${version}-${target}.${ext}"
    url="https://github.com/niclasedge/rust-redactor/releases/download/v${version}/${tarball_name}"

    mkdir -p "${bin_dir}"
    tmp="$(mktemp -d 2>/dev/null || mktemp -d -t redactor-bootstrap.XXXXXX)"
    trap 'rm -rf "$tmp"' RETURN

    echo "redactor bootstrap: fetching ${url}" >&2
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 2 --retry-delay 1 -o "${tmp}/${tarball_name}" "${url}" \
            || { echo "redactor bootstrap: download failed (${url})" >&2; return 1; }
        curl -fsSL --retry 2 --retry-delay 1 \
            -o "${tmp}/SHA256SUMS.txt" \
            "https://github.com/niclasedge/rust-redactor/releases/download/v${version}/SHA256SUMS.txt" \
            || { echo "redactor bootstrap: SHA256SUMS download failed" >&2; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "${tmp}/${tarball_name}" "${url}" \
            || { echo "redactor bootstrap: download failed (${url})" >&2; return 1; }
        wget -q -O "${tmp}/SHA256SUMS.txt" \
            "https://github.com/niclasedge/rust-redactor/releases/download/v${version}/SHA256SUMS.txt" \
            || { echo "redactor bootstrap: SHA256SUMS download failed" >&2; return 1; }
    else
        echo "redactor bootstrap: neither curl nor wget available" >&2
        return 1
    fi

    expected="$(grep -E " ${tarball_name}\$" "${tmp}/SHA256SUMS.txt" | awk '{print $1}')"
    if [[ -z "$expected" ]]; then
        echo "redactor bootstrap: ${tarball_name} not listed in SHA256SUMS.txt" >&2
        return 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "${tmp}/${tarball_name}" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "${tmp}/${tarball_name}" | awk '{print $1}')"
    else
        echo "redactor bootstrap: no sha256 tool available" >&2
        return 1
    fi
    if [[ "$expected" != "$actual" ]]; then
        echo "redactor bootstrap: SHA256 mismatch for ${tarball_name}" >&2
        echo "  expected: ${expected}" >&2
        echo "  actual:   ${actual}" >&2
        return 1
    fi

    case "$ext" in
        tar.gz)
            tar -xzf "${tmp}/${tarball_name}" -C "${tmp}" \
                || { echo "redactor bootstrap: tar extract failed" >&2; return 1; }
            ;;
        zip)
            if command -v unzip >/dev/null 2>&1; then
                unzip -q "${tmp}/${tarball_name}" -d "${tmp}" \
                    || { echo "redactor bootstrap: unzip failed" >&2; return 1; }
            else
                echo "redactor bootstrap: unzip not available for .zip extraction" >&2
                return 1
            fi
            ;;
    esac

    local found
    found="$(find "${tmp}" -type f \( -name redactor -o -name redactor.exe \) | head -n 1)"
    if [[ -z "$found" ]]; then
        echo "redactor bootstrap: binary not found inside ${tarball_name}" >&2
        return 1
    fi
    cp "$found" "${bin_dir}/$(basename "$found")"
    chmod +x "${bin_dir}/$(basename "$found")" 2>/dev/null || true

    export PATH="${bin_dir}:${PATH}"
    echo "redactor bootstrap: installed v${version} -> ${bin_dir}" >&2
    return 0
}

_redactor_bootstrap_main || {
    echo "redactor bootstrap: FAILED — install manually with 'cargo install --git https://github.com/niclasedge/rust-redactor' or download from https://github.com/niclasedge/rust-redactor/releases" >&2
    return 1 2>/dev/null || exit 1
}
