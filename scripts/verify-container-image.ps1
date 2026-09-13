# Verifies the backend container image without a container runtime.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-container-image.ps1
#
# Docker is not available on every machine this project is developed on, so the
# image is otherwise only checked by static analysis - which cannot tell you
# whether `requirements.txt` is actually complete, or whether the files the
# Dockerfile copies are enough for the app to start.
#
# This reproduces the image locally instead:
#
#   1. a fresh virtualenv built from backend/requirements.txt ALONE, so a
#      dependency that only exists in requirements-dev.txt is not available to
#      hide a missing entry;
#   2. a directory laid out exactly as the runtime stage builds it - /app/app,
#      /app/knowledge_base, /app/data - copied the same way the Dockerfile does;
#   3. the container's own environment (PYTHONDONTWRITEBYTECODE, PYTHONUNBUFFERED,
#      the container-side paths) and its exact CMD;
#   4. health, a real question, and a check that the database and vector index
#      were written to the mounted directory rather than into the image.
#
# It is not a substitute for `docker compose up`. It does prove the image's
# *contents* and *entrypoint* work, which is what static checks cannot.

[CmdletBinding()]
param(
    [int]$Port = 8123,
    [string]$Root = "$env:TEMP\esaa-image-check",
    [string]$Python,
    [switch]$Keep
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $repo 'backend'
$image = Join-Path $Root 'app'          # stands in for the container's /app
$venv = Join-Path $Root 'opt-venv'      # stands in for the container's /opt/venv
$failures = @()

# `python` on PATH is often the Microsoft Store alias on Windows, which is a
# stub rather than an interpreter. Resolve a real one, preferring the base
# interpreter this project's own virtualenv was built from.
function Resolve-Python {
    param([string]$Explicit)

    if ($Explicit) {
        if (Test-Path $Explicit) { return (Resolve-Path $Explicit).Path }
        throw "the interpreter given with -Python does not exist: $Explicit"
    }

    $candidates = @()
    $cfg = Join-Path $backend '.venv\pyvenv.cfg'
    if (Test-Path $cfg) {
        # Not $home: PowerShell reserves that for the user profile.
        $venvHome = (Select-String -Path $cfg -Pattern '^home\s*=\s*(.+)$').Matches.Groups[1].Value.Trim()
        if ($venvHome) { $candidates += (Join-Path $venvHome 'python.exe') }
    }
    $candidates += @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:ProgramFiles\Python312\python.exe"
    )

    foreach ($candidate in $candidates) {
        # A Store alias lives under WindowsApps and would fail on `--version`.
        if ($candidate -and (Test-Path $candidate) -and $candidate -notmatch 'WindowsApps') {
            return (Resolve-Path $candidate).Path
        }
    }
    throw 'no real Python interpreter found; pass one with -Python <path>'
}

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Ok($text) { Write-Host "  ok   $text" -ForegroundColor Green }
function Bad($text) { Write-Host "  FAIL $text" -ForegroundColor Red; $script:failures += $text }

try {
    $basePython = Resolve-Python -Explicit $Python
    Write-Host "Using $basePython" -ForegroundColor DarkGray

    if (Test-Path $Root) { Remove-Item -Recurse -Force $Root }
    New-Item -ItemType Directory -Path $Root | Out-Null

    Step '1. fresh virtualenv from requirements.txt alone'
    & $basePython -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'could not create the virtualenv' }
    $py = Join-Path $venv 'Scripts\python.exe'
    & $py -m pip install --quiet --disable-pip-version-check -r (Join-Path $backend 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { Bad 'pip install -r requirements.txt failed'; throw 'install failed' }
    Ok 'requirements.txt installs cleanly on its own'

    Step '2. lay out the runtime stage exactly as the Dockerfile does'
    # Mirrors: COPY --chown=appuser:appuser app ./app
    #          COPY --chown=appuser:appuser knowledge_base ./knowledge_base
    #          RUN mkdir -p /app/data
    New-Item -ItemType Directory -Path (Join-Path $image 'app') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $image 'knowledge_base') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $image 'data') | Out-Null
    Copy-Item -Recurse -Force (Join-Path $backend 'app\*') (Join-Path $image 'app')
    Copy-Item -Recurse -Force (Join-Path $backend 'knowledge_base\*') (Join-Path $image 'knowledge_base')

    # The image deliberately does NOT contain these; if the app needs any of them
    # it will fail here, which is the point.
    foreach ($absent in @('tests', 'scripts', 'requirements.txt', 'pytest.ini', '.env')) {
        if (Test-Path (Join-Path $image $absent)) { Bad "$absent leaked into the image layout" }
    }
    Ok 'only app/ and knowledge_base/ are present, plus the empty data/ mount point'

    Step '3. start with the container environment and the container CMD'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    $env:PYTHONUNBUFFERED = '1'
    # Container-side paths, as docker-compose.yml sets them.
    $env:DATABASE_URL = "sqlite:///$($image -replace '\\','/')/data/app.db"
    $env:VECTOR_STORE_PATH = "$image\data\vector_store"
    $env:KB_DIR = "$image\knowledge_base"
    $env:API_HOST = '0.0.0.0'
    $env:AUTH_SECRET_KEY = 'container-verification-key-not-a-real-secret-0123456789'
    $env:SEED_DEMO_USERS = 'true'

    $log = Join-Path $Root 'uvicorn.log'
    # The Dockerfile's CMD, verbatim apart from the port.
    $process = Start-Process -FilePath $py -PassThru -NoNewWindow `
        -WorkingDirectory $image `
        -RedirectStandardOutput $log -RedirectStandardError "$log.err" `
        -ArgumentList @(
            '-m', 'uvicorn', 'app.main:app',
            '--host', '0.0.0.0', '--port', "$Port", '--no-server-header'
        )

    $ready = $false
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/api/v1/health" -UseBasicParsing -TimeoutSec 3
            if ($r.StatusCode -eq 200) { $ready = $true; break }
        } catch { Start-Sleep -Milliseconds 700 }
    }

    if (-not $ready) {
        Bad 'the app did not become healthy with only the image contents'
        Get-Content $log, "$log.err" -ErrorAction SilentlyContinue | Select-Object -Last 25 |
            ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    } else {
        Ok "uvicorn started from the image layout and reported healthy"

        Step '4. exercise it: a real question over HTTP'
        $login = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/api/v1/auth/login" `
            -ContentType 'application/json' `
            -Body '{"email":"employee@example.com","password":"Demo@12345"}'
        $headers = @{ Authorization = "Bearer $($login.access_token)" }
        Ok "signed in as $($login.user.email)"

        $conv = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/api/v1/chat/conversations" `
            -Headers $headers -ContentType 'application/json' -Body '{}'
        $answer = Invoke-RestMethod -Method Post `
            -Uri "http://127.0.0.1:$Port/api/v1/chat/conversations/$($conv.id)/messages" `
            -Headers $headers -ContentType 'application/json' `
            -Body '{"content":"I entered my password on a phishing page."}'
        $payload = $answer.assistant_message.payload

        if ($payload.intent -and $payload.risk_level) {
            Ok "answered: intent=$($payload.intent) risk=$($payload.risk_level) ticket=$($payload.ticket_reference)"
        } else {
            Bad 'the pipeline did not produce a structured payload'
        }
        if ($payload.ticket_reference) {
            Ok "a ticket was raised, so the write path works in the image layout"
        } else {
            Bad 'a high-risk report did not raise a ticket'
        }

        Step '5. state landed on the mount point, not in the image'
        foreach ($expected in @('data\app.db', 'data\vector_store\fingerprint.txt')) {
            if (Test-Path (Join-Path $image $expected)) { Ok "$expected written under the mount point" }
            else { Bad "$expected was not written - the container would lose it on restart" }
        }
        if (Test-Path (Join-Path $image 'app\data')) {
            Bad 'the app wrote into its own source tree instead of the mount point'
        }
    }

    if ($process -and -not $process.HasExited) {
        & taskkill.exe /T /F /PID $process.Id 2>&1 | Out-Null
    }
}
finally {
    Get-Process -Name 'python' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -like "$venv*" } |
        ForEach-Object { & taskkill.exe /T /F /PID $_.Id 2>&1 | Out-Null }
    if (-not $Keep -and (Test-Path $Root)) { Remove-Item -Recurse -Force $Root -ErrorAction SilentlyContinue }
}

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host ("IMAGE CHECK FAILED: " + ($failures -join '; ')) -ForegroundColor Red
    exit 1
}
Write-Host 'IMAGE CHECK PASSED - the image contents and entrypoint work without a container runtime.' -ForegroundColor Green
exit 0
