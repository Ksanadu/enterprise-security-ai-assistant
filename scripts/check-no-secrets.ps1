# Verifies the repository never tracks secrets or runtime data, and that the
# assets it *must* contain are actually committable.
#
# Usage:  pwsh -File scripts/check-no-secrets.ps1
#
# Exits non-zero when a sensitive path would be committed, or when a required
# asset is missing from the repository.
#
# The second half exists because of a real failure: a `.gitignore` rule of
# `data/` silently excluded `backend/tests/data/evaluation_questions.json`, so
# the 40-question evaluation set was never committed and a fresh clone failed
# the whole evaluation suite. Ignoring too much is as much a defect as ignoring
# too little, and only a positive check catches it.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

try {
    if (-not (Test-Path (Join-Path $root '.git'))) {
        Write-Host 'No git repository found - nothing to check. Run: git init' -ForegroundColor Yellow
        exit 0
    }

    # Anchored to the runtime location. A bare `/data/` also matched the test
    # fixtures under `backend/tests/data/`, which are source, not runtime state.
    $forbidden = @(
        '\.env$',
        '\.env\.(local|development|production|staging)$',
        '^backend/data/',
        '\.db$',
        '\.sqlite3?$',
        'node_modules/',
        '\.venv/',
        '\.pem$',
        '\.key$'
    )

    # Files that must be in the repository. Losing any of these is a defect that
    # no test run in a working copy would notice.
    $required = @(
        'README.md',
        '.env.example',
        '.gitignore',
        '.gitattributes',
        'PRODUCT_SPEC.md',
        'docker-compose.yml',
        'docs/ARCHITECTURE.md',
        'docs/DEMO.md',
        'backend/Dockerfile',
        'backend/knowledge_base/README.md',
        'backend/knowledge_base/KB-001-password-policy.md',
        'backend/scripts/demo.py',
        'backend/tests/data/evaluation_questions.json',
        'frontend/Dockerfile',
        'frontend/nginx.conf',
        'scripts/run-local.ps1'
    )

    $added = git add -A --dry-run 2>&1 | ForEach-Object { $_ -replace "^add '", '' -replace "'$", '' }
    $tracked = git ls-files
    # What the repository would contain after this commit: already tracked plus
    # anything new. `git add --dry-run` alone is empty on a clean tree, which
    # would make the required-asset check pass for the wrong reason.
    $effective = @($tracked) + @($added) | Sort-Object -Unique

    $violations = @()
    foreach ($file in $effective) {
        $normalised = $file -replace '\\', '/'
        foreach ($pattern in $forbidden) {
            if ($normalised -match $pattern) {
                $violations += "$normalised  (matches $pattern)"
                break
            }
        }
    }

    $missing = @()
    foreach ($asset in $required) {
        if ($effective -notcontains $asset) {
            $missing += $asset
        }
    }

    Write-Host ("Files that would be committed: " + $effective.Count)

    if ($violations.Count -gt 0) {
        Write-Host 'FAIL: sensitive paths are not ignored:' -ForegroundColor Red
        $violations | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }

    if ($missing.Count -gt 0) {
        Write-Host 'FAIL: required assets are not committable (check .gitignore):' -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }

    # Independently scan tracked source for obvious live-looking credentials.
    $secretPatterns = @('sk-[A-Za-z0-9]{20,}', 'AKIA[0-9A-Z]{16}', '-----BEGIN [A-Z ]*PRIVATE KEY-----')
    $leaks = @()
    foreach ($file in $effective) {
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

    Write-Host ("OK: " + $effective.Count + " files; no secrets or runtime data, all required assets present.") -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
