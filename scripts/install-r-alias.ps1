# Idempotent: append a managed block to $PROFILE.CurrentUserAllHosts that
# removes PowerShell's built-in `r -> Invoke-History` alias, so the
# r.exe / r short-alias resolves via PATH.
$ErrorActionPreference = "Stop"
$marker = "# rust-redactor: r short-alias"
$snippet = @"
$marker (managed block)
Remove-Item Alias:r -Force -ErrorAction SilentlyContinue
# end rust-redactor
"@
$p = $PROFILE.CurrentUserAllHosts
$d = Split-Path -Parent $p
if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
if (-not (Test-Path $p)) { New-Item -ItemType File -Path $p -Force | Out-Null }
$c = Get-Content $p -Raw -ErrorAction SilentlyContinue
if ($null -eq $c -or $c -notmatch [regex]::Escape($marker)) {
    Add-Content -Path $p -Value "`n$snippet"
    Write-Host "patched PowerShell profile: $p"
} else {
    Write-Host "PowerShell profile already patched: $p"
}
