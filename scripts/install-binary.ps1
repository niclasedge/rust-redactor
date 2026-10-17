<#
.SYNOPSIS
    Fetch the prebuilt redactor.exe into the plugin's bin\ directory (Windows).
    Invoked by the /redactor:install slash command on Windows. The Unix/macOS
    equivalent is install-binary.sh.

.DESCRIPTION
    Resolves the plugin root (prefers $env:CLAUDE_PLUGIN_ROOT, else the parent
    of this script's folder), downloads redactor-<target>.zip + SHA256SUMS.txt
    from the rolling GitHub release, verifies the SHA256 checksum, extracts and
    installs redactor.exe into <plugin-root>\bin. Throws (non-zero exit) on any
    download or checksum failure so the caller surfaces the problem.

.PARAMETER Tag
    Release tag to pull. Default: rolling (or $env:REDACTOR_RELEASE_TAG).

.PARAMETER Force
    Reinstall even if redactor.exe is already present.

.EXAMPLE
    pwsh -File install-binary.ps1
    pwsh -File install-binary.ps1 -Tag v0.8.0 -Force
#>
[CmdletBinding()]
param(
    [string]$Tag = $(if ($env:REDACTOR_RELEASE_TAG) { $env:REDACTOR_RELEASE_TAG } else { 'rolling' }),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Windows PowerShell 5.1 (.NET Framework) defaults to TLS 1.0/1.1; GitHub's
# release CDN requires TLS 1.2+. Harmless on pwsh 7 (.NET 5+).
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

$repo = if ($env:REDACTOR_REPO) { $env:REDACTOR_REPO } else { 'niclasedge/rust-redactor' }

# --- resolve plugin root + bin dir -----------------------------------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pluginRoot = if ($env:CLAUDE_PLUGIN_ROOT) { $env:CLAUDE_PLUGIN_ROOT } else { (Resolve-Path (Join-Path $scriptDir '..')).Path }
$binDir = Join-Path $pluginRoot 'bin'

# --- detect target triple ---------------------------------------------------
# PROCESSOR_ARCHITEW6432 reflects the true OS arch when running in a 32-bit
# (WoW64) host process; PROCESSOR_ARCHITECTURE alone would misreport 'x86'.
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
    'AMD64' { $target = 'x86_64-pc-windows-msvc' }
    'X86'   { $target = 'x86_64-pc-windows-msvc' }  # 32-bit shell on x64 OS
    'ARM64' {
        # No native ARM64 build yet; the x64 binary runs under Windows-on-ARM emulation.
        $target = 'x86_64-pc-windows-msvc'
        Write-Host 'note: no native ARM64 build yet — using the x64 binary under emulation'
    }
    default { throw "install-binary.ps1: unsupported Windows arch: $arch" }
}

# Versioned tags (v1.2.3 / 1.2.3) carry release.yml's versioned asset names;
# the rolling tag (and anything else) uses version-less names.
$asset = if ($Tag -match '^v?\d') { "redactor-$($Tag -replace '^v','')-$target.zip" } else { "redactor-$target.zip" }
$base  = "https://github.com/$repo/releases/download/$Tag"
$exe   = Join-Path $binDir 'redactor.exe'

if ((Test-Path $exe) -and (-not $Force)) {
    Write-Host "redactor.exe already present at $exe (use -Force to reinstall)"
    & $exe --version
    exit 0
}

# --- download ---------------------------------------------------------------
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("redactor-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $assetPath = Join-Path $tmp $asset
    $sumsPath  = Join-Path $tmp 'SHA256SUMS.txt'

    Write-Host "redactor: downloading $asset from $base"
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $assetPath -UseBasicParsing
    Invoke-WebRequest -Uri "$base/SHA256SUMS.txt" -OutFile $sumsPath -UseBasicParsing

    # --- verify checksum ----------------------------------------------------
    # Anchor to end-of-line + leading space so the match is the filename field,
    # not an arbitrary substring (e.g. a future <asset>.sig line).
    $line = Select-String -Path $sumsPath -Pattern ("\s\*?" + [regex]::Escape($asset) + '$') | Select-Object -First 1
    if (-not $line) { throw "install-binary.ps1: $asset not listed in SHA256SUMS.txt" }
    $expected = ($line.Line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Path $assetPath -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        throw "install-binary.ps1: SHA256 mismatch for $asset`n  expected: $expected`n  actual:   $actual"
    }

    # --- extract + install --------------------------------------------------
    Expand-Archive -Path $assetPath -DestinationPath $tmp -Force
    $found = Get-ChildItem -Path $tmp -Recurse -Filter 'redactor.exe' | Select-Object -First 1
    if (-not $found) { throw "install-binary.ps1: redactor.exe not found inside $asset" }
    Copy-Item -Path $found.FullName -Destination $exe -Force

    Write-Host "redactor installed -> $exe"
    & $exe --version
    if ($LASTEXITCODE -ne 0) {
        throw "install-binary.ps1: installed redactor.exe failed to run (exit $LASTEXITCODE) — wrong arch or missing runtime?"
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
