<#
.SYNOPSIS
    One command to bring the whole Enterprise Security AI Assistant up in Docker.

.DESCRIPTION
    `docker compose up --build` already works from a fresh clone, because the
    compose file needs no configuration file. This script exists for the two
    things a bare `up` cannot do:

      1. It mints a stable AUTH_SECRET_KEY into `.env` on first use, so sessions
         survive `docker compose restart`. Without one the application generates
         a random key per process and every restart signs everyone out.
      2. It tells you the stack is actually answering, rather than that the
         containers started. `up -d` returns as soon as a service is *running*,
         which for the backend is before the knowledge base is loaded and the
         vector index is fitted. Readiness is confirmed by calling the API
         through nginx, which is the path the browser takes.

    It then prints the URL, the demo accounts and the ways to stop it.

.PARAMETER Down
    Stop the stack and keep the data volume (database + vector index).

.PARAMETER Logs
    Follow the stack's logs instead of starting anything.

.PARAMETER Rebuild
    Force a rebuild even if the images already exist.

.PARAMETER FrontendPort
    Host port for the application. Default 8080 (ESAA_HTTP_PORT).

.PARAMETER BackendPort
    Host port for the API on loopback. Default 8000 (ESAA_API_PORT).

.PARAMETER TimeoutSeconds
    How long to wait for readiness. Default 300.

.EXAMPLE
    pwsh -File scripts/docker-up.ps1
    pwsh -File scripts/docker-up.ps1 -FrontendPort 9090
    pwsh -File scripts/docker-up.ps1 -Down
    pwsh -File scripts/docker-up.ps1 -Logs

.NOTES
    Windows PowerShell 5.1 and PowerShell 7+ both run this. On the machine this
    project was developed on, `pwsh` is not installed; use
    `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\docker-up.ps1`.

    This starts the demo deployment: loopback-bound, demo accounts seeded,
    `LLM_PROVIDER=mock`, no TLS. Read the README's production checklist before
    exposing it to a network.
#>

[CmdletBinding()]
param(
    [switch]$Down,
    [switch]$Logs,
    [switch]$Rebuild,
    [int]$FrontendPort = 0,
    [int]$BackendPort = 0,
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot '.env'
$EnvTemplate = Join-Path $RepoRoot '.env.example'

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

$script:StepNumber = 0

function Write-Step {
    param([string]$Message)
    $script:StepNumber++
    Write-Host ''
    Write-Host ("[{0}] {1}" -f $script:StepNumber, $Message) -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host ("    ok    {0}" -f $Message) -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host ("          {0}" -f $Message) -ForegroundColor DarkGray
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("    warn  {0}" -f $Message) -ForegroundColor Yellow
}

function Fail {
    param([string]$Message, [string[]]$Remedy = @())
    Write-Host ''
    Write-Host ("FAILED: {0}" -f $Message) -ForegroundColor Red
    foreach ($line in $Remedy) {
        Write-Host ("        {0}" -f $line) -ForegroundColor Yellow
    }
    exit 1
}

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------

Write-Step 'Checking for a usable Docker Compose'

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $docker) {
    Fail 'the docker command is not on PATH.' @(
        'Install Docker Desktop (Windows/macOS) or Docker Engine (Linux), then reopen the terminal.',
        'Docker Desktop must be *running*: for a while after logon the CLI exists but the daemon does not.'
    )
}

# A docker binary is not the same thing as a usable Compose plugin, and a plugin
# is not the same thing as a running daemon. Probing the subcommand first turns
# three different environment problems into three different messages instead of
# one confusing failure after a two-minute build.
$composeVersion = (& docker compose version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    if ($composeVersion -match 'permission denied|docker daemon|pipe|not running|Cannot connect') {
        Fail 'Docker is installed but the daemon is not reachable.' @(
            'Start Docker Desktop and wait for it to report "Engine running", then re-run this script.'
        )
    }
    Fail 'the docker compose plugin is not available.' @(
        'Compose v2 ships with Docker Desktop; on Linux install the docker-compose-plugin package.',
        "docker said: $composeVersion"
    )
}
Write-Ok $composeVersion

# ---------------------------------------------------------------------------
# 2. Stop / logs modes
# ---------------------------------------------------------------------------

Push-Location $RepoRoot
try {
    if ($Down) {
        Write-Step 'Stopping the stack (the data volume is kept)'
        & docker compose down
        if ($LASTEXITCODE -ne 0) { Fail 'docker compose down failed.' }
        Write-Ok 'stopped; app.db and the vector index are still in the esaa_app-data volume'
        Write-Info 'docker compose down -v    also deletes the volume'
        exit 0
    }

    if ($Logs) {
        Write-Step 'Following stack logs (Ctrl+C to stop following)'
        & docker compose logs -f
        exit 0
    }

    # -----------------------------------------------------------------------
    # 3. Configuration file
    # -----------------------------------------------------------------------

    Write-Step 'Preparing .env'

    if (-not (Test-Path -LiteralPath $EnvTemplate)) {
        Fail "the environment template is missing: $EnvTemplate" @(
            'A fresh clone must contain .env.example; check that the checkout is complete.'
        )
    }

    if (Test-Path -LiteralPath $EnvFile) {
        Write-Ok '.env already exists (left untouched)'
    }
    else {
        # Byte-level copy, so the file's encoding is not reinterpreted on the way.
        Copy-Item -LiteralPath $EnvTemplate -Destination $EnvFile
        Write-Ok 'created .env from .env.example'
    }

    $envText = Get-Content -Raw -LiteralPath $EnvFile

    if ($envText -match '(?m)^\s*AUTH_SECRET_KEY\s*=\s*(\S*)\s*$') {
        $currentKey = $Matches[1]
        if ([string]::IsNullOrWhiteSpace($currentKey) -or
            $currentKey -eq 'dev-only-insecure-change-me' -or
            $currentKey.Length -lt 32) {

            # 48 bytes of CSPRNG, base64: 64 characters, URL-safe, and no '$'
            # character to interact with Compose's variable interpolation.
            $bytes = New-Object byte[] 48
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
            $newKey = [Convert]::ToBase64String($bytes)

            # Evaluated before use: a '$' in a -replace replacement is a backreference.
            $replacement = 'AUTH_SECRET_KEY=' + $newKey
            $envText = [regex]::Replace($envText, '(?m)^\s*AUTH_SECRET_KEY\s*=.*$', $replacement)
            [System.IO.File]::WriteAllText($EnvFile, $envText, (New-Object System.Text.UTF8Encoding($false)))
            Write-Ok 'generated a stable AUTH_SECRET_KEY (sessions now survive a restart)'
        }
        else {
            Write-Ok 'AUTH_SECRET_KEY is already set'
        }
    }
    else {
        Write-Warn 'no AUTH_SECRET_KEY line in .env; the app will generate one per process'
        Write-Info 'sessions will end whenever the backend restarts'
    }

    if ($envText -match '(?m)^\s*APP_ENV\s*=\s*production\s*$') {
        Fail 'APP_ENV=production is set in .env, which this script does not start.' @(
            'The demo stack seeds simulated users and refuses to do so in production.',
            'Point APP_ENV back at development for the demo, or deploy with the README production checklist.'
        )
    }

    # -----------------------------------------------------------------------
    # 3b. Which ports this run will use
    # -----------------------------------------------------------------------

    # Precedence: the command line, then the environment, then `.env`, then the
    # compose default. `.env` is in the list because Compose loads it
    # automatically, so a port set there is the port the stack really publishes -
    # and this script has to probe and report the same one. Reading it only from
    # the environment would print a URL nothing is listening on.
    $requestedHttp = if ($FrontendPort -gt 0) { "$FrontendPort" } else { '' }
    $requestedApi = if ($BackendPort -gt 0) { "$BackendPort" } else { '' }

    function Get-ConfiguredPort {
        param([string]$Requested, [string]$Name, [string]$Fallback, [string]$Text)
        if (-not [string]::IsNullOrWhiteSpace($Requested)) { return [int]$Requested }
        # `$env:$Name` is not valid PowerShell (the drive needs a literal name), so
        # the variable is read through the provider instead. Under StrictMode a
        # missing variable yields $null, and reading `.Value` off that throws, so
        # it is checked before it is used.
        $item = Get-Item -Path "Env:$Name" -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            $fromEnvironment = [string]$item.Value
            if (-not [string]::IsNullOrWhiteSpace($fromEnvironment)) {
                return [int]$fromEnvironment
            }
        }
        if ($Text -match "(?m)^\s*$([regex]::Escape($Name))\s*=\s*(\d+)\s*$") {
            return [int]$Matches[1]
        }
        return [int]$Fallback
    }

    $httpPort = Get-ConfiguredPort -Requested $requestedHttp -Name 'ESAA_HTTP_PORT' `
        -Fallback '8080' -Text $envText
    $apiPort = Get-ConfiguredPort -Requested $requestedApi -Name 'ESAA_API_PORT' `
        -Fallback '8000' -Text $envText

    # -----------------------------------------------------------------------
    # 4. Start
    # -----------------------------------------------------------------------

    Write-Step 'Starting the stack (the first build takes a few minutes)'

    # Passed to Compose as environment, so the published port this run uses is the
    # one that was just resolved rather than whatever `.env` alone would give.
    $env:ESAA_HTTP_PORT = "$httpPort"
    $env:ESAA_API_PORT = "$apiPort"

    $upArgs = @('compose', '--env-file', $EnvFile, 'up', '--detach')
    if ($Rebuild) { $upArgs += '--build' }

    Write-Info ("docker " + ($upArgs -join ' '))
    & docker @upArgs
    $upExit = $LASTEXITCODE

    if ($upExit -ne 0) {
        Fail 'docker compose up failed.' @(
            'The build or start-up output above names the cause.',
            'docker compose logs --tail 80 backend      # the application log',
            'docker compose logs --tail 80 frontend     # the nginx log'
        )
    }

    # -----------------------------------------------------------------------
    # 5. Wait for readiness
    # -----------------------------------------------------------------------

    Write-Step "Waiting for the stack to answer (up to $TimeoutSeconds s)"

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $ready = $false
    $lastReason = 'no probe has run yet'

    while ((Get-Date) -lt $deadline) {
        # Ask the *frontend* origin, because that is the path the browser takes:
        # it proves nginx is up, the SPA is served, and /api reaches the backend.
        #
        # `-NoProxy` matters on a machine with HTTP_PROXY set: without it the
        # request for 127.0.0.1 is sent to the corporate proxy, which cannot reach
        # this stack, and a perfectly healthy deployment is reported as never
        # becoming ready.
        try {
            $probe = Invoke-WebRequest -Uri "http://127.0.0.1:$httpPort/api/v1/health" `
                -UseBasicParsing -TimeoutSec 5 -NoProxy
            if ($probe.StatusCode -eq 200) {
                $ready = $true
                break
            }
            $lastReason = "HTTP $($probe.StatusCode) from the proxied health endpoint"
        }
        catch {
            $lastReason = $_.Exception.Message
        }

        # A container that has already exited will never become ready; stop
        # waiting for it and say which one it was.
        $states = @()
        try {
            $states = @(& docker compose ps --all --format '{{.Service}}={{.State}}')
        }
        catch {
            # `compose ps` failing is not itself fatal; the timeout still applies.
            $states = @()
        }
        foreach ($state in $states) {
            if ($state -match '^(?<name>[^=]+)=(?<value>exited|dead)') {
                Write-Host ''
                & docker compose ps --all
                Fail ("the {0} container {1} before the API became ready." -f $Matches['name'], $Matches['value']) @(
                    "docker compose logs --tail 120 $($Matches['name'])",
                    'The log says why it stopped; a configuration problem is the usual cause.'
                )
            }
        }

        Write-Host ("    ..    not ready yet ({0})" -f $lastReason) -ForegroundColor DarkGray
        Start-Sleep -Seconds 5
    }

    if (-not $ready) {
        Write-Host ''
        & docker compose ps --all
        Fail "the stack did not become ready within $TimeoutSeconds s." @(
            'docker compose logs --tail 120 backend',
            'A first run fits the knowledge base index; on a slow machine raise -TimeoutSeconds.'
        )
    }
    Write-Ok "the API answers through nginx on port $httpPort"

    # -----------------------------------------------------------------------
    # 6. Report
    # -----------------------------------------------------------------------

    Write-Step 'Checking the application actually loads'

    try {
        $page = Invoke-WebRequest -Uri "http://127.0.0.1:$httpPort/" -UseBasicParsing -TimeoutSec 10 -NoProxy
        if ($page.StatusCode -eq 200 -and $page.Content -match '<div id="root"') {
            Write-Ok 'the SPA document is served'
        }
        else {
            Write-Warn "unexpected document from / (HTTP $($page.StatusCode))"
        }
    }
    catch {
        Write-Warn "could not load the SPA document: $($_.Exception.Message)"
    }

    if ($envText -match '(?m)^\s*DEMO_USER_PASSWORD\s*=\s*(\S*)\s*$') {
        $demoPassword = $Matches[1]
        if ([string]::IsNullOrWhiteSpace($demoPassword)) { $demoPassword = 'Demo@12345' }
    }
    else {
        $demoPassword = 'Demo@12345'
    }

    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor Green
    Write-Host '   Enterprise Security AI Assistant is up' -ForegroundColor Green
    Write-Host '  ============================================================' -ForegroundColor Green
    Write-Host ''
    Write-Host ("   Application        http://localhost:{0}" -f $httpPort)
    Write-Host ("   API health         http://127.0.0.1:{0}/api/v1/health" -f $apiPort)
    Write-Host ("   API docs           http://127.0.0.1:{0}/docs" -f $apiPort)
    Write-Host ''
    Write-Host '   Demo accounts (all data is simulated)'
    Write-Host ("     password         {0}" -f $demoPassword)
    Write-Host '     employee@example.com   employee - public FAQ and employee policies (7 documents)'
    Write-Host '     it@example.com         IT       - + troubleshooting and IT SOPs (10 documents)'
    Write-Host '     security@example.com   security - everything, plus the dashboard (12 documents)'
    Write-Host ''
    Write-Host '   Try the RBAC boundary: ask "What is the malware response procedure?" as'
    Write-Host '   employee@example.com, then as security@example.com.'
    Write-Host ''
    Write-Host '   Stop               docker compose down          (keeps the data volume)'
    Write-Host '                      docker compose down -v       (deletes it)'
    Write-Host '   Logs               pwsh -File scripts/docker-up.ps1 -Logs'
    Write-Host '   Rebuild            pwsh -File scripts/docker-up.ps1 -Rebuild'
    Write-Host '   Other port         pwsh -File scripts/docker-up.ps1 -FrontendPort 9090'
    Write-Host ''
    Write-Host '   This is a demo deployment: loopback-bound, demo logins enabled,'
    Write-Host '   LLM_PROVIDER=mock. See the README production checklist before'
    Write-Host '   exposing it to a network.'
    Write-Host ''

    exit 0
}
finally {
    Pop-Location
}
