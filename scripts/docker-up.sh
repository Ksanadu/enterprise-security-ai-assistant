#!/usr/bin/env sh
# =============================================================================
# One command to bring the whole Enterprise Security AI Assistant up in Docker.
#
#     sh scripts/docker-up.sh              start (builds if needed), wait, report
#     sh scripts/docker-up.sh --rebuild    force a rebuild first
#     sh scripts/docker-up.sh --port 9090  publish the application on another port
#     sh scripts/docker-up.sh --logs       follow the logs
#     sh scripts/docker-up.sh --down       stop the stack, keep the data volume
#
# `docker compose up --build` already works from a fresh clone, because the
# compose file needs no configuration file. This script exists for the two things
# a bare `up` cannot do:
#
#   1. It mints a stable AUTH_SECRET_KEY into `.env` on first use, so sessions
#      survive `docker compose restart`. Without one the application generates a
#      random key per process and every restart signs everyone out.
#   2. It tells you the stack is actually answering, rather than that the
#      containers started. `up -d` returns once a service is *running*, which for
#      the backend is before the knowledge base is loaded and the vector index is
#      fitted. Readiness is confirmed by calling the API through nginx, which is
#      the path the browser takes.
#
# Windows users have the same tool as a PowerShell script: scripts/docker-up.ps1.
# Both do the same six steps, so the two cannot drift far without being noticed.
#
# This starts the demo deployment: loopback-bound, demo accounts seeded,
# LLM_PROVIDER=mock, no TLS. Read the README's production checklist before
# exposing it to a network.
# =============================================================================

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(dirname -- "$SCRIPT_DIR")
ENV_FILE="$REPO_ROOT/.env"
ENV_TEMPLATE="$REPO_ROOT/.env.example"

MODE=up
REBUILD=0
TIMEOUT=300
HTTP_PORT_OVERRIDE=
API_PORT_OVERRIDE=

while [ $# -gt 0 ]; do
    case "$1" in
        --down) MODE=down ;;
        --logs) MODE=logs ;;
        --rebuild) REBUILD=1 ;;
        --port)
            shift
            [ $# -gt 0 ] || { printf 'docker-up: --port needs a number\n' >&2; exit 2; }
            HTTP_PORT_OVERRIDE=$1
            ;;
        --api-port)
            shift
            [ $# -gt 0 ] || { printf 'docker-up: --api-port needs a number\n' >&2; exit 2; }
            API_PORT_OVERRIDE=$1
            ;;
        --timeout)
            shift
            [ $# -gt 0 ] || { printf 'docker-up: --timeout needs a number\n' >&2; exit 2; }
            TIMEOUT=$1
            ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) printf 'docker-up: unknown option %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

step_number=0

step() {
    step_number=$((step_number + 1))
    printf '\n[%s] %s\n' "$step_number" "$1"
}

ok() { printf '    ok    %s\n' "$1"; }
info() { printf '          %s\n' "$1"; }
warn() { printf '    warn  %s\n' "$1"; }

fail() {
    printf '\nFAILED: %s\n' "$1" >&2
    shift
    for remedy in "$@"; do
        printf '        %s\n' "$remedy" >&2
    done
    exit 1
}

# A portable "is this http URL answering with 200" check. curl is not guaranteed
# everywhere either, so wget is the fallback.
#
# The proxy variables are cleared for the request: on a machine with HTTP_PROXY
# set, asking a proxy to fetch http://127.0.0.1 answers 403/502, and a perfectly
# healthy stack would be reported as never becoming ready.
probe() {
    url=$1
    if command -v curl >/dev/null 2>&1; then
        HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= http_proxy= https_proxy= all_proxy= \
            curl -fsS -o /dev/null --max-time 5 --noproxy '*' "$url" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        HTTP_PROXY= HTTPS_PROXY= http_proxy= https_proxy= \
            wget -q -O /dev/null --timeout=5 --tries=1 --no-proxy "$url" 2>/dev/null
    else
        return 2
    fi
}

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------

step 'Checking for a usable Docker Compose'

command -v docker >/dev/null 2>&1 || fail 'the docker command is not on PATH.' \
    'Install Docker Engine (Linux) or Docker Desktop, then reopen the terminal.' \
    'Docker Desktop must be *running*: for a while after logon the CLI exists but the daemon does not.'

compose_version=$(docker compose version 2>&1) || {
    case "$compose_version" in
        *"Cannot connect"*|*"daemon"*|*"permission denied"*|*"pipe"*)
            fail 'Docker is installed but the daemon is not reachable.' \
                'Start Docker and wait for it to report that the engine is running, then re-run this script.' ;;
        *)
            fail 'the docker compose plugin is not available.' \
                'Compose v2 ships with Docker Desktop; on Linux install the docker-compose-plugin package.' \
                "docker said: $compose_version" ;;
    esac
}
ok "$compose_version"

cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# 2. Stop / logs modes
# ---------------------------------------------------------------------------

if [ "$MODE" = down ]; then
    step 'Stopping the stack (the data volume is kept)'
    docker compose down || fail 'docker compose down failed.'
    ok 'stopped; app.db and the vector index are still in the esaa_app-data volume'
    info 'docker compose down -v    also deletes the volume'
    exit 0
fi

if [ "$MODE" = logs ]; then
    step 'Following stack logs (Ctrl+C to stop following)'
    exec docker compose logs -f
fi

# ---------------------------------------------------------------------------
# 3. Configuration file
# ---------------------------------------------------------------------------

step 'Preparing .env'

[ -f "$ENV_TEMPLATE" ] || fail "the environment template is missing: $ENV_TEMPLATE" \
    'A fresh clone must contain .env.example; check that the checkout is complete.'

if [ -f "$ENV_FILE" ]; then
    ok '.env already exists (left untouched)'
else
    cp "$ENV_TEMPLATE" "$ENV_FILE"
    ok 'created .env from .env.example'
fi

current_key=$(sed -n 's/^[[:space:]]*AUTH_SECRET_KEY[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*$/\1/p' "$ENV_FILE" | head -n 1)

if [ -z "$current_key" ] || [ "$current_key" = 'dev-only-insecure-change-me' ] || [ "${#current_key}" -lt 32 ]; then
    # 48 bytes of CSPRNG, base64: 64 characters, URL-safe, and no '$' character
    # to interact with Compose's variable interpolation. openssl is not
    # guaranteed to be present, /dev/urandom and od are POSIX.
    new_key=$(od -An -N48 -tx1 /dev/urandom | tr -d ' \n')
    # Hex is 96 characters and still free of '$'; keep it simple and portable.
    tmp_file="$ENV_FILE.tmp.$$"
    sed "s|^[[:space:]]*AUTH_SECRET_KEY[[:space:]]*=.*$|AUTH_SECRET_KEY=$new_key|" "$ENV_FILE" > "$tmp_file"
    mv "$tmp_file" "$ENV_FILE"
    ok 'generated a stable AUTH_SECRET_KEY (sessions now survive a restart)'
else
    ok 'AUTH_SECRET_KEY is already set'
fi

if grep -q '^[[:space:]]*APP_ENV[[:space:]]*=[[:space:]]*production[[:space:]]*$' "$ENV_FILE"; then
    fail 'APP_ENV=production is set in .env, which this script does not start.' \
        'The demo stack seeds simulated users and refuses to do so in production.' \
        'Point APP_ENV back at development for the demo, or deploy with the README production checklist.'
fi

# ---------------------------------------------------------------------------
# 4. Start
# ---------------------------------------------------------------------------

step 'Starting the stack (the first build takes a few minutes)'

# Precedence: the command line, then the environment, then `.env`, then the
# compose default. `.env` is in the list because Compose loads it automatically,
# so a port set there is the port the stack really publishes - and this script has
# to probe and report the same one. Reading it only from the environment would
# print a URL nothing is listening on.
env_port() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*$/\1/p" "$ENV_FILE" | head -n 1
}

from_env_file=$(env_port ESAA_HTTP_PORT)
from_environment=${ESAA_HTTP_PORT:-}
HTTP_PORT=${HTTP_PORT_OVERRIDE:-${from_environment:-${from_env_file:-8080}}}

from_env_file=$(env_port ESAA_API_PORT)
from_environment=${ESAA_API_PORT:-}
API_PORT=${API_PORT_OVERRIDE:-${from_environment:-${from_env_file:-8000}}}

# Passed to Compose as environment, so the published port this run uses is the
# one that was just resolved rather than whatever `.env` alone would give.
ESAA_HTTP_PORT=$HTTP_PORT
ESAA_API_PORT=$API_PORT
export ESAA_HTTP_PORT
export ESAA_API_PORT

info "docker compose --env-file .env up --detach"

if [ "$REBUILD" = 1 ]; then
    docker compose --env-file "$ENV_FILE" up --detach --build || fail 'docker compose up --build failed.' \
        'The build output above names the cause.' \
        'docker compose logs --tail 80 backend'
else
    docker compose --env-file "$ENV_FILE" up --detach || fail 'docker compose up failed.' \
        'The build or start-up output above names the cause.' \
        'docker compose logs --tail 80 backend      # the application log' \
        'docker compose logs --tail 80 frontend     # the nginx log'
fi

# ---------------------------------------------------------------------------
# 5. Wait for readiness
# ---------------------------------------------------------------------------

step "Waiting for the stack to answer (up to ${TIMEOUT}s)"

elapsed=0
ready=0
last_reason='no probe has run yet'

while [ "$elapsed" -lt "$TIMEOUT" ]; do
    # `|| status=$?` rather than `set -e` reasoning: the probe *is* expected to
    # fail while the stack starts, and a function invoked in a `while` condition
    # is not exempt from `set -e` the way an `if` condition is on every shell.
    # Without this the script exits with curl's code (7, "couldn't connect")
    # instead of reaching its own message - which is exactly the confusing
    # failure the message exists to prevent.
    status=0
    probe "http://127.0.0.1:$HTTP_PORT/api/v1/health" || status=$?

    if [ "$status" -eq 0 ]; then
        ready=1
        break
    fi

    if [ "$status" -eq 2 ]; then
        fail 'neither curl nor wget is available, so readiness cannot be confirmed.' \
            'Install curl, or watch the stack yourself with: docker compose ps'
    fi

    # A container that has already exited will never become ready; stop waiting
    # for it and say which one it was.
    for service in $(docker compose ps --services 2>/dev/null || true); do
        state=$(docker compose ps --format '{{.State}}' "$service" 2>/dev/null | head -n 1 || true)
        case "$state" in
            exited|dead)
                docker compose ps --all || true
                fail "the $service container $state before the API became ready." \
                    "docker compose logs --tail 120 $service" \
                    'The log says why it stopped; a configuration problem is the usual cause.'
                ;;
        esac
    done

    last_reason='the proxied health endpoint has not returned 200 yet'
    printf '    ..    not ready yet (%s)\n' "$last_reason"
    sleep 5
    elapsed=$((elapsed + 5))
done

if [ "$ready" -ne 1 ]; then
    docker compose ps --all || true
    fail "the stack did not become ready within ${TIMEOUT}s." \
        'docker compose logs --tail 120 backend' \
        'A first run fits the knowledge base index; on a slow machine raise --timeout.'
fi
ok "the API answers through nginx on port $HTTP_PORT"

# ---------------------------------------------------------------------------
# 6. Report
# ---------------------------------------------------------------------------

step 'Checking the application actually loads'

if probe "http://127.0.0.1:$HTTP_PORT/"; then
    ok 'the SPA document is served'
else
    warn "could not load the SPA document from http://127.0.0.1:$HTTP_PORT/"
fi

demo_password=$(sed -n 's/^[[:space:]]*DEMO_USER_PASSWORD[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*$/\1/p' "$ENV_FILE" | head -n 1)
[ -n "$demo_password" ] || demo_password='Demo@12345'

printf '\n'
printf '  ============================================================\n'
printf '   Enterprise Security AI Assistant is up\n'
printf '  ============================================================\n'
printf '\n'
printf '   Application        http://localhost:%s\n' "$HTTP_PORT"
printf '   API health         http://127.0.0.1:%s/api/v1/health\n' "$API_PORT"
printf '   API docs           http://127.0.0.1:%s/docs\n' "$API_PORT"
printf '\n'
printf '   Demo accounts (all data is simulated)\n'
printf '     password         %s\n' "$demo_password"
printf '     employee@example.com   employee - public FAQ and employee policies (7 documents)\n'
printf '     it@example.com         IT       - + troubleshooting and IT SOPs (10 documents)\n'
printf '     security@example.com   security - everything, plus the dashboard (12 documents)\n'
printf '\n'
printf '   Try the RBAC boundary: ask "What is the malware response procedure?" as\n'
printf '   employee@example.com, then as security@example.com.\n'
printf '\n'
printf '   Stop               docker compose down          (keeps the data volume)\n'
printf '                      docker compose down -v       (deletes it)\n'
printf '   Logs               sh scripts/docker-up.sh --logs\n'
printf '   Rebuild            sh scripts/docker-up.sh --rebuild\n'
printf '   Other port         sh scripts/docker-up.sh --port 9090\n'
printf '\n'
printf '   This is a demo deployment: loopback-bound, demo logins enabled,\n'
printf '   LLM_PROVIDER=mock. See the README production checklist before\n'
printf '   exposing it to a network.\n'
printf '\n'

exit 0
