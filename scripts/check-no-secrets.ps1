# Verifies the repository never tracks secrets or runtime data.
# Usage:  pwsh -File scripts/check-no-secrets.ps1
#
# Exits non-zero when a sensitive path would be committed.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

try {
    if (-not (Test-Path (Join-Path $root '.git'))) {
        Write-Host 'No git repository found - nothing to check. Run: git init' -ForegroundColor Yellow
        exit 0
    }

    $forbidden = @(
        '\.env$',
        '\.env\.(local|development|production|staging)$',
        '/data/',
        '\.db$',
        '\.sqlite3?$',
        'node_modules/',
        '\.venv/',
        '\.pem$',
        '\.key$'
    )

    $staged = git add -A --dry-run 2>&1 | ForEach-Object { $_ -replace "^add '", '' -replace "'$", '' }
    $violations = @()

    foreach ($file in $staged) {
        $normalised = $file -replace '\\', '/'
        foreach ($pattern in $forbidden) {
            if ($normalised -match $pattern) {
                $violations += "$normalised  (matches $pattern)"
                break
            }
        }
    }

    Write-Host ("Files that would be committed: " + $staged.Count)

    if ($violations.Count -gt 0) {
        Write-Host 'FAIL: sensitive paths are not ignored:' -ForegroundColor Red
        $violations | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }

    # Independently scan tracked source for obvious live-looking credentials.
    $secretPatterns = @('sk-[A-Za-z0-9]{20,}', 'AKIA[0-9A-Z]{16}', '-----BEGIN [A-Z ]*PRIVATE KEY-----')
    $leaks = @()
    foreach ($file in $staged) {
        if ($file -match '\.(py|ts|tsx|js|json|ya?ml|md|toml)$') {
            $full = Join-Path $root $file
            if (Test-Path $full) {
                foreach ($pattern in $secretPatterns) {
                    if ((Get-Content -Raw -LiteralPath $full) -match $pattern) {
                        $leaks += "$file  (matches $pattern)"
                    }
                }
            }
        }
    }

    if ($leaks.Count -gt 0) {
        Write-Host 'FAIL: possible credential material found in source:' -ForegroundColor Red
        $leaks | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }

    Write-Host 'OK: no secrets or runtime data would be committed.' -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
