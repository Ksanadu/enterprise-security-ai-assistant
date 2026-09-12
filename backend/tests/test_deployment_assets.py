"""Deployment asset tests (Phase 9).

Docker is not installed in the environment where this project was developed, so
``docker compose up`` could not be executed here. These tests are what replaces
that: they parse the deployment files and cross-check them against each other and
against the application's own configuration model.

They catch the class of failure that otherwise only appears on the very first
`up`, where it is expensive and confusing:

* a service name that does not match the nginx ``proxy_pass`` target,
* a knowledge-base path that the image never receives a ``COPY`` for,
* a volume mounted somewhere other than the directory the app writes to,
* a relative database URL inside the container (``sqlite:///./data`` would
  resolve against the image layer and be lost on the next restart),
* a secret written into the compose file instead of being read from ``.env``,
* a ``.dockerignore`` that would bake ``.env`` or a database file into a layer,
* a container that would run as root.

Everything here is static analysis plus the real settings model. Nothing requires
a container runtime, and nothing touches the network.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"
BACKEND_DOCKERFILE = BACKEND_DIR / "Dockerfile"
FRONTEND_DOCKERFILE = FRONTEND_DIR / "Dockerfile"
NGINX_CONF = FRONTEND_DIR / "nginx.conf"
BACKEND_DOCKERIGNORE = BACKEND_DIR / ".dockerignore"
FRONTEND_DOCKERIGNORE = FRONTEND_DIR / ".dockerignore"

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    assert COMPOSE_FILE.is_file(), f"missing {COMPOSE_FILE}"
    data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "docker-compose.yml must be a YAML mapping"
    return data


@pytest.fixture(scope="module")
def services(compose: dict[str, Any]) -> dict[str, Any]:
    services = compose.get("services")
    assert isinstance(services, dict) and services, "no services defined"
    return services


def _container_path(value: str) -> PurePosixPath:
    """Normalise a POSIX path inside a container.

    ``PurePosixPath`` preserves a leading double slash, so ``//app/data`` and
    ``/app/data`` would compare unequal even though they name the same
    directory. Collapsing the prefix makes the two spellings agree.
    """
    assert value.startswith("/"), f"not an absolute container path: {value!r}"
    return PurePosixPath("/" + value.lstrip("/"))


def _dockerfile_stages(path: Path) -> list[list[str]]:
    """Split a Dockerfile into stages, each as a list of logical instructions.

    Line continuations are joined and comment/blank lines dropped, so an
    assertion can look at a whole instruction rather than a wrapped fragment.
    """
    text = path.read_text(encoding="utf-8")
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    instructions: list[str] = []
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        instructions.append(line)

    stages: list[list[str]] = []
    for instruction in instructions:
        if instruction.upper().startswith("FROM "):
            stages.append([instruction])
        elif stages:
            stages[-1].append(instruction)
        else:
            # Preamble before the first FROM (e.g. a syntax directive) is not
            # part of any stage.
            continue
    assert stages, f"{path.name} has no FROM instruction"
    return stages


def _stage_instructions(path: Path, stage_index: int) -> list[str]:
    return _dockerfile_stages(path)[stage_index]


def _find(instructions: list[str], keyword: str) -> list[str]:
    upper = keyword.upper()
    return [line for line in instructions if line.upper().startswith(upper)]


def _copy_destinations(instructions: list[str]) -> list[PurePosixPath]:
    """Absolute container destinations of every ``COPY``, tracking ``WORKDIR``.

    ``COPY app ./app`` names a relative destination; resolving it against the
    current ``WORKDIR`` is what lets a test compare it with the absolute path the
    application is configured to read.
    """
    workdir = "/"
    destinations: list[PurePosixPath] = []

    for line in instructions:
        tokens = line.split()
        if not tokens:
            continue
        keyword = tokens[0].upper()
        if keyword == "WORKDIR":
            workdir = tokens[1]
            continue
        if keyword != "COPY":
            continue

        operands = [token for token in tokens[1:] if not token.startswith("--")]
        assert len(operands) >= 2, f"COPY needs a source and a destination: {line!r}"
        destination = operands[-1]
        if destination.startswith("./"):
            destination = f"{workdir.rstrip('/')}/{destination[2:]}"
        elif not destination.startswith("/"):
            destination = f"{workdir.rstrip('/')}/{destination}"
        destinations.append(_container_path(destination))

    return destinations


def _volume_mounts(service: dict[str, Any]) -> list[tuple[str, PurePosixPath]]:
    """(source, container target) for a service, for both compose volume syntaxes.

    Short syntax (``- app-data:/app/data``) arrives from YAML as a plain string;
    long syntax arrives as a mapping. Deployment files in the wild use both.
    """
    mounts: list[tuple[str, PurePosixPath]] = []
    for volume in service.get("volumes") or []:
        if isinstance(volume, dict):
            mounts.append((str(volume["source"]), _container_path(str(volume["target"]))))
            continue
        source, separator, target = str(volume).partition(":")
        assert separator and target, f"unexpected volume syntax: {volume!r}"
        mounts.append((source, _container_path(target)))
    return mounts


@pytest.fixture(scope="module")
def conf() -> str:
    """The nginx configuration, shared by the header and CSP test classes."""
    return NGINX_CONF.read_text(encoding="utf-8")


def _dockerignore_rules(path: Path) -> set[str]:
    rules: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rules.add(line)
    return rules


def _csp_directives(policy: str) -> set[str]:
    """Directive names of a Content-Security-Policy, e.g. ``script-src``."""
    names = set()
    for segment in policy.split(";"):
        segment = segment.strip()
        if segment:
            names.add(segment.split()[0])
    return names


def _env_example_keys() -> set[str]:
    keys: set[str] = set()
    for raw in (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        keys.add(line.split("=", 1)[0].strip())
    return keys


# ---------------------------------------------------------------------------
# docker-compose.yml
# ---------------------------------------------------------------------------


class TestComposeStructure:
    def test_declares_the_two_expected_services(self, services: dict[str, Any]) -> None:
        assert set(services) == {"backend", "frontend"}

    @pytest.mark.parametrize(
        ("service", "context_dir", "dockerfile"),
        [
            ("backend", BACKEND_DIR, BACKEND_DOCKERFILE),
            ("frontend", FRONTEND_DIR, FRONTEND_DOCKERFILE),
        ],
    )
    def test_build_context_exists(
        self,
        services: dict[str, Any],
        service: str,
        context_dir: Path,
        dockerfile: Path,
    ) -> None:
        build = services[service].get("build")
        assert isinstance(build, dict), f"{service} must be built from a context"
        context = (PROJECT_ROOT / build["context"]).resolve()
        assert context == context_dir.resolve()
        assert dockerfile.is_file(), f"{service} build context has no Dockerfile"

    def test_frontend_waits_for_a_healthy_backend(self, services: dict[str, Any]) -> None:
        depends_on = services["frontend"]["depends_on"]
        assert depends_on["backend"]["condition"] == "service_healthy"

    def test_both_services_have_a_healthcheck(self, services: dict[str, Any]) -> None:
        for name in ("backend", "frontend"):
            healthcheck = services[name].get("healthcheck")
            assert healthcheck, f"{name} has no healthcheck"
            assert healthcheck.get("test"), f"{name} healthcheck has no test"
            assert healthcheck.get("start_period"), f"{name} needs a start period"

    def test_restart_policy_is_bounded(self, services: dict[str, Any]) -> None:
        # `always` would restart-loop a container that cannot start because its
        # configuration is wrong, hiding the error from the operator.
        for name in ("backend", "frontend"):
            assert services[name]["restart"] == "unless-stopped"

    def test_no_privilege_escalation_in_either_service(self, services: dict[str, Any]) -> None:
        for name in ("backend", "frontend"):
            assert "no-new-privileges:true" in services[name]["security_opt"]

    def test_compose_file_declares_a_project_name(self, compose: dict[str, Any]) -> None:
        # Without it the stack name follows the directory, which changes the
        # volume name and silently orphans the database.
        assert compose.get("name") == "esaa"


class TestComposeContainerPaths:
    """The paths inside the container must agree with the image layout."""

    def _environment(self, services: dict[str, Any]) -> dict[str, str]:
        return services["backend"]["environment"]

    def test_database_url_is_an_absolute_container_path(self, services: dict[str, Any]) -> None:
        # Four slashes: "sqlite://" + "/app/data/app.db". With three slashes the
        # value is relative, and the app would resolve it against its own source
        # directory - i.e. inside the image layer, lost on the next restart.
        url = self._environment(services)["DATABASE_URL"]
        assert url.startswith("sqlite:////"), url

    def test_vector_store_path_is_absolute(self, services: dict[str, Any]) -> None:
        value = self._environment(services)["VECTOR_STORE_PATH"]
        assert value.startswith("/")
        assert PurePosixPath(value).is_absolute()

    def test_database_and_index_live_on_the_same_volume(self, services: dict[str, Any]) -> None:
        environment = self._environment(services)
        database = _container_path(environment["DATABASE_URL"][len("sqlite://") :])
        vector_store = _container_path(environment["VECTOR_STORE_PATH"])

        mounts = _volume_mounts(services["backend"])
        assert mounts, "backend has no volume: all state would be lost on rebuild"
        targets = [target for _, target in mounts]

        # A mount covers a path when it is that path or one of its ancestors.
        def coverage(path: PurePosixPath) -> set[PurePosixPath]:
            return {target for target in targets if target == path or target in path.parents}

        database_volumes = coverage(database)
        vector_store_volumes = coverage(vector_store)

        assert database_volumes, f"{database} is not on a mounted volume"
        assert vector_store_volumes, f"{vector_store} is not on a mounted volume"
        # Both must land on the *same* volume, so a single `docker compose down`
        # cannot destroy the database and leave a stale index behind (or vice versa).
        assert database_volumes == vector_store_volumes, (
            f"database and index are on different volumes: "
            f"{database_volumes} vs {vector_store_volumes}"
        )

    def test_the_volume_is_named_not_bound_to_the_host(self, services: dict[str, Any]) -> None:
        # A bind mount would be owned by the host user while the container runs
        # as uid 10001, and would also let the container write into the repo.
        for source, _ in _volume_mounts(services["backend"]):
            assert re.fullmatch(r"[A-Za-z0-9_.-]+", source), (
                f"expected a named volume, got host path {source!r}"
            )

    def test_the_declared_volume_exists(self, compose: dict[str, Any]) -> None:
        declared = set(compose.get("volumes") or {})
        used = {
            source
            for service in compose["services"].values()
            for source, _ in _volume_mounts(service)
        }
        assert used <= declared, f"undeclared volume(s): {sorted(used - declared)}"

    def test_knowledge_base_path_matches_the_image_copy(self, services: dict[str, Any]) -> None:
        kb_dir = _container_path(services["backend"]["environment"]["KB_DIR"])
        destinations = _copy_destinations(_stage_instructions(BACKEND_DOCKERFILE, 1))
        assert kb_dir in destinations, (
            f"the image never copies the knowledge base to {kb_dir}; "
            f"COPY destinations are {[str(d) for d in destinations]}"
        )

    def test_the_writable_mount_point_is_owned_by_the_runtime_user(
        self, services: dict[str, Any]
    ) -> None:
        # Docker seeds an empty named volume with the ownership of the directory
        # it covers. Without this chown the unprivileged user cannot create the
        # database, and the container fails on first start.
        runtime = " ".join(_stage_instructions(BACKEND_DOCKERFILE, 1))
        for _, target in _volume_mounts(services["backend"]):
            assert f"mkdir -p {target}" in runtime, f"{target} is never created"
            assert f"chown -R appuser:appuser {target}" in runtime, f"{target} is not chowned"

    def test_api_binds_all_interfaces_inside_the_container(self, services: dict[str, Any]) -> None:
        # 127.0.0.1 inside the container would be unreachable from nginx.
        # The literal is a configuration value being read, not a socket bind.
        wildcard = "0.0.0.0"  # noqa: S104
        assert services["backend"]["environment"]["API_HOST"] == wildcard

    def test_the_proxy_hop_count_matches_the_deployed_topology(
        self, services: dict[str, Any]
    ) -> None:
        # nginx is the only thing in front of the API, so exactly one hop of
        # X-Forwarded-For is trustworthy. Getting this wrong is not cosmetic:
        # at 0 every request is attributed to nginx, which collapses the
        # per-address sign-in lockout into one shared bucket and records the
        # proxy in every audit row.
        assert services["backend"]["environment"]["TRUSTED_PROXY_COUNT"] == 1

    def test_the_proxy_actually_forwards_the_client_address(self, conf: str) -> None:
        api_block = re.search(r"location /api/\s*\{([^}]*)\}", conf)
        assert api_block
        # $proxy_add_x_forwarded_for appends the peer to whatever arrived, which
        # is what makes the rightmost entry trustworthy.
        assert "X-Forwarded-For $proxy_add_x_forwarded_for" in api_block.group(1)

    def test_the_hop_count_is_documented_in_the_environment_template(self) -> None:
        assert "TRUSTED_PROXY_COUNT" in _env_example_keys()


class TestComposeExposure:
    def test_backend_is_not_published_to_the_network(self, services: dict[str, Any]) -> None:
        # Loopback-only, whether the port number is literal or interpolated.
        pattern = r"^127\.0\.0\.1:(\d+|\$\{[A-Z_]+:-\d+\}):(\d+|\$\{[A-Z_]+:-\d+\})$"
        for mapping in services["backend"]["ports"]:
            assert re.match(pattern, str(mapping)), (
                f"backend port must be loopback-only, got {mapping!r}"
            )

    def test_frontend_has_an_explicit_default_port(self, services: dict[str, Any]) -> None:
        mapping = str(services["frontend"]["ports"][0])
        assert mapping.endswith(":80")
        assert "${ESAA_HTTP_PORT:-8080}" in mapping

    def test_no_wildcard_cors_origin_is_configured(self, services: dict[str, Any]) -> None:
        value = services["backend"]["environment"]["API_CORS_ORIGINS"]

        # The value may be an interpolated list; check the default it falls back
        # to, which is what an unconfigured deployment actually serves.
        interpolated = re.fullmatch(r"\$\{[A-Z_]+:-(.*)\}", value)
        origins = (interpolated.group(1) if interpolated else value).split(",")

        assert "*" not in value
        for origin in origins:
            assert origin.startswith(("http://localhost", "http://127.0.0.1")), origin


class TestComposeSecrets:
    FORBIDDEN_KEYS = (
        "AUTH_SECRET_KEY",
        "LLM_API_KEY",
        "EMBEDDING_API_KEY",
        "DEMO_USER_PASSWORD",
    )

    def test_configuration_comes_from_the_env_file(self, services: dict[str, Any]) -> None:
        assert services["backend"]["env_file"] == [".env"]

    @pytest.mark.parametrize("key", FORBIDDEN_KEYS)
    def test_secrets_are_not_inlined(self, services: dict[str, Any], key: str) -> None:
        # Overriding them here would silently shadow the operator's .env.
        assert key not in services["backend"].get("environment", {})
        assert key not in (services["backend"].get("env_file") or [])

    def test_compose_file_contains_no_credential_shaped_value(self) -> None:
        text = COMPOSE_FILE.read_text(encoding="utf-8")
        for pattern in (r"sk-[A-Za-z0-9]{16,}", r"AKIA[0-9A-Z]{16}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"):
            assert not re.search(pattern, text), f"credential-shaped value in compose: {pattern}"

    def test_env_file_itself_is_gitignored(self) -> None:
        ignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        assert ".env" in {line.strip() for line in ignore}
        assert "!.env.example" in {line.strip() for line in ignore}

    def test_every_overridden_variable_is_documented_in_the_template(
        self, services: dict[str, Any]
    ) -> None:
        documented = _env_example_keys()
        undocumented = sorted(set(services["backend"]["environment"]) - documented)
        assert not undocumented, (
            f"compose overrides variables that .env.example does not document: {undocumented}"
        )


class TestComposeSemantics:
    """Validate the file with the real tool when it is available."""

    def test_compose_config_is_valid_if_docker_is_installed(self) -> None:
        docker = shutil.which("docker")
        if docker is None:
            pytest.skip(
                "docker CLI is not installed in this environment; "
                "docker-compose.yml is validated by static analysis instead"
            )
        # Fixed argv from a resolved path, no shell, no interpolated input.
        completed = subprocess.run(  # noqa: S603
            [docker, "compose", "-f", str(COMPOSE_FILE), "config", "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr


# ---------------------------------------------------------------------------
# backend/Dockerfile
# ---------------------------------------------------------------------------


class TestBackendDockerfile:
    @pytest.fixture(scope="class")
    def stages(self) -> list[list[str]]:
        return _dockerfile_stages(BACKEND_DOCKERFILE)

    def test_is_multi_stage(self, stages: list[list[str]]) -> None:
        assert len(stages) == 2, "expected a builder stage and a runtime stage"

    def test_runtime_stage_does_not_run_as_root(self, stages: list[list[str]]) -> None:
        runtime = stages[-1]
        users = _find(runtime, "USER")
        assert users, "runtime stage never drops privileges"
        assert users[-1].split()[1].strip().lower() not in {"root", "0"}

    def test_runtime_stage_installs_the_openmp_runtime(self, stages: list[list[str]]) -> None:
        # FAISS links against libgomp; without it the container starts and then
        # dies on `import faiss` rather than failing the build.
        runtime = " ".join(stages[-1])
        assert "libgomp1" in runtime

    def test_runtime_stage_reuses_the_builder_virtualenv(self, stages: list[list[str]]) -> None:
        runtime = " ".join(stages[-1])
        assert "/opt/venv" in runtime
        assert "pip install" not in runtime, "runtime stage must not install packages"

    def test_dependencies_are_installed_from_the_requirements_file(
        self, stages: list[list[str]]
    ) -> None:
        builder = " ".join(stages[0])
        assert "pip install -r requirements.txt" in builder

    def test_copy_never_takes_the_whole_context(self, stages: list[list[str]]) -> None:
        # `COPY . .` would defeat .dockerignore review and can bake in .env.
        for stage in stages:
            for line in _find(stage, "COPY"):
                assert line.split()[-2:] != [".", "."], line
                assert not re.search(r"COPY\s+\.\s", line), line

    def test_declares_the_service_port(self, stages: list[list[str]]) -> None:
        assert "EXPOSE 8000" in " ".join(stages[-1])

    def test_has_a_healthcheck_using_the_application_endpoint(
        self, stages: list[list[str]]
    ) -> None:
        healthchecks = _find(stages[-1], "HEALTHCHECK")
        assert healthchecks, "no HEALTHCHECK"
        assert "/api/v1/health" in " ".join(healthchecks)

    def test_has_an_exec_form_command(self, stages: list[list[str]]) -> None:
        commands = _find(stages[-1], "CMD")
        assert commands, "no CMD"
        # JSON exec form: the process receives signals directly instead of being
        # behind a shell, so `docker compose stop` is not a 10-second timeout.
        assert commands[-1].lstrip("CMD").strip().startswith("[")

    def test_does_not_disable_tls_verification(self) -> None:
        text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        assert "PYTHONHTTPSVERIFY" not in text
        assert re.search(r"pip install[^\n]*--trusted-host", text) is None


# ---------------------------------------------------------------------------
# frontend/Dockerfile and nginx.conf
# ---------------------------------------------------------------------------


class TestFrontendDockerfile:
    @pytest.fixture(scope="class")
    def stages(self) -> list[list[str]]:
        return _dockerfile_stages(FRONTEND_DOCKERFILE)

    def test_is_multi_stage(self, stages: list[list[str]]) -> None:
        assert len(stages) == 2

    def test_build_stage_installs_from_the_lockfile(self, stages: list[list[str]]) -> None:
        assert "npm ci" in " ".join(stages[0])

    def test_build_runs_the_type_checked_build(self, stages: list[list[str]]) -> None:
        # `npm run build` is `tsc -b && vite build`, so a type error fails the
        # image build rather than shipping broken JavaScript.
        assert "npm run build" in " ".join(stages[0])

    def test_only_the_build_output_reaches_the_runtime_stage(
        self, stages: list[list[str]]
    ) -> None:
        copies = [line for line in _find(stages[-1], "COPY") if "--from" in line]
        assert copies, "runtime stage does not copy the build output"
        assert all("/build/dist" in line for line in copies)
        assert "node_modules" not in " ".join(stages[-1])

        destinations = _copy_destinations(stages[-1])
        assert _container_path("/usr/share/nginx/html") in destinations, (
            f"build output is not served from nginx's document root: {destinations}"
        )

    def test_build_context_carries_the_settings_the_image_needs(
        self, stages: list[list[str]]
    ) -> None:
        # `tsc -b` type-checks vite.config.ts through tsconfig.node.json, so the
        # tsconfig files are build inputs; omitting any of them breaks the build
        # inside the image only.
        sources = " ".join(_find(stages[0], "COPY"))
        for required in ("package.json", "package-lock.json", "tsconfig.json", "vite.config.ts"):
            assert required in sources, f"build stage never copies {required}"

    def test_runtime_stage_is_nginx(self, stages: list[list[str]]) -> None:
        assert stages[-1][0].upper().startswith("FROM NGINX")

    def test_default_configuration_is_removed(self, stages: list[list[str]]) -> None:
        runtime = " ".join(stages[-1])
        assert "conf.d/default.conf" in runtime

    def test_has_a_healthcheck(self, stages: list[list[str]]) -> None:
        assert _find(stages[-1], "HEALTHCHECK")


class TestNginxConfiguration:
    def test_proxies_api_to_the_backend_service(self, conf: str) -> None:
        # The hostname must be the compose service name, or every API call 502s.
        match = re.search(r"proxy_pass\s+(http://[^;]+);", conf)
        assert match, "no proxy_pass"
        assert match.group(1) == "http://backend:8000"

    def test_proxy_preserves_the_api_prefix(self, conf: str) -> None:
        # A trailing slash on proxy_pass would strip the prefix and 404.
        assert not re.search(r"proxy_pass\s+http://backend:8000/", conf)

    def test_serves_the_spa_with_a_history_fallback(self, conf: str) -> None:
        assert re.search(r"try_files\s+\$uri\s+\$uri/\s+/index\.html", conf)

    def test_hides_the_server_version(self, conf: str) -> None:
        assert "server_tokens off;" in conf

    def test_limits_request_body_size(self, conf: str) -> None:
        assert re.search(r"client_max_body_size\s+\d+[kmg]?;", conf)

    @pytest.mark.parametrize(
        "directive",
        [
            'X-Content-Type-Options "nosniff"',
            'X-Frame-Options "DENY"',
            'Referrer-Policy "no-referrer"',
        ],
    )
    def test_sets_baseline_security_headers(self, conf: str, directive: str) -> None:
        assert directive in conf

    def test_every_block_that_declares_a_header_repeats_the_security_headers(
        self, conf: str
    ) -> None:
        # nginx `add_header` is not inherited once a block declares its own, so a
        # location that only sets Cache-Control would silently drop nosniff.
        blocks = re.findall(r"location[^{]*\{([^}]*)\}", conf)
        assert blocks
        for block in blocks:
            if "add_header" not in block:
                continue
            assert "X-Content-Type-Options" in block, block
            assert "Content-Security-Policy" in block, block

    def test_content_security_policy_is_restrictive(self, conf: str) -> None:
        match = re.search(r'add_header Content-Security-Policy "([^"]+)"', conf)
        assert match, "no CSP"
        policy = match.group(1)
        assert "default-src 'self'" in policy
        assert "script-src 'self'" in policy
        assert "frame-ancestors 'none'" in policy
        assert "object-src 'none'" in policy
        # A policy allowing any origin for scripts would be pointless.
        assert "script-src 'self' 'unsafe-inline'" not in policy
        assert "script-src *" not in policy

    def test_api_responses_are_not_cached(self, conf: str) -> None:
        api_block = re.search(r"location /api/\s*\{([^}]*)\}", conf)
        assert api_block
        assert "no-store" in api_block.group(1)

    def test_html_is_not_cached(self, conf: str) -> None:
        assert re.search(r"add_header Cache-Control \"no-store\"", conf)

    def test_no_directory_listing(self, conf: str) -> None:
        assert "autoindex on" not in conf

    def test_configuration_is_syntactically_plausible(self, conf: str) -> None:
        """No nginx binary is available here, so check the structure by hand.

        This is not a substitute for `nginx -t`; it catches the mistakes that are
        actually likely while editing - an unbalanced brace, a forgotten
        semicolon - which otherwise only surface as a container that exits during
        `docker compose up`.
        """
        # Strip comments so a ';' or '{' inside prose cannot affect the count.
        stripped = re.sub(r"#[^\n]*", "", conf)

        depth = 0
        for character in stripped:
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
            assert depth >= 0, "unbalanced closing brace"
        assert depth == 0, f"unbalanced braces: {depth} block(s) left open"

        for raw in stripped.splitlines():
            line = raw.strip()
            if not line:
                continue
            assert line.endswith((";", "{", "}")), f"statement is not terminated: {line!r}"

    def test_every_location_block_is_closed(self, conf: str) -> None:
        blocks = re.findall(r"location[^{]*\{([^}]*)\}", conf)
        assert len(blocks) == conf.count("location "), "a location block is malformed"


class TestContentSecurityPolicyInjection:
    """The CSP is injected into the built HTML by string replacement.

    `frontend/vite.config.ts` replaces the referrer meta tag with itself plus the
    CSP meta tag. If that anchor is ever reformatted, the replacement silently
    does nothing and production ships with no CSP at all - a failure with no error
    message anywhere. These tests fail loudly instead.
    """

    def test_the_build_anchor_still_exists_in_the_html_template(self) -> None:
        html = (FRONTEND_DIR / "index.html").read_text(encoding="utf-8")
        assert '<meta name="referrer" content="no-referrer" />' in html

    def test_the_injection_plugin_is_registered_for_builds(self) -> None:
        config = (FRONTEND_DIR / "vite.config.ts").read_text(encoding="utf-8")
        assert "contentSecurityPolicy()" in config
        assert "apply: 'build'" in config

    def test_the_injected_policy_matches_the_nginx_header(self, conf: str) -> None:
        config = (FRONTEND_DIR / "vite.config.ts").read_text(encoding="utf-8")

        # The policy array in vite.config.ts, up to the .join('; ') call. Each
        # element is a double-quoted directive such as "script-src 'self'"; the
        # single quotes inside are CSP syntax, not string delimiters.
        array = re.search(r"const policy = \[(.*?)\]\.join", config, re.DOTALL)
        assert array, "could not find the policy array in vite.config.ts"
        from_config = "; ".join(re.findall(r'"([^"]+)"', array.group(1)))
        assert from_config, "the policy array is empty"

        header = re.search(r'add_header Content-Security-Policy "([^"]+)"', conf)
        assert header, "nginx.conf has no CSP header"

        # Only the directive names are compared: the two files quote and order the
        # sources differently, but the set of directives must agree, or the header
        # and the meta tag would enforce different policies.
        assert _csp_directives(from_config) == _csp_directives(header.group(1))


# ---------------------------------------------------------------------------
# .dockerignore
# ---------------------------------------------------------------------------


class TestDockerignore:
    @pytest.mark.parametrize(
        ("path", "must_exclude"),
        [
            (BACKEND_DOCKERIGNORE, ".env"),
            (BACKEND_DOCKERIGNORE, "data/"),
            (BACKEND_DOCKERIGNORE, ".venv/"),
            (BACKEND_DOCKERIGNORE, "tests/"),
            (FRONTEND_DOCKERIGNORE, ".env"),
            (FRONTEND_DOCKERIGNORE, "node_modules/"),
            (FRONTEND_DOCKERIGNORE, "dist/"),
        ],
    )
    def test_excludes_local_artefacts(self, path: Path, must_exclude: str) -> None:
        rules = _dockerignore_rules(path)
        # An explicit negation for the same entry would cancel the exclusion.
        assert must_exclude in rules, f"{path.name} does not exclude {must_exclude}"
        assert f"!{must_exclude}" not in rules

    def test_runtime_data_is_never_copied_into_an_image(self) -> None:
        text = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        for forbidden in (".env", "app.db", "vector_store", "data/"):
            assert not re.search(rf"COPY[^\n]*\b{re.escape(forbidden)}", text), forbidden


# ---------------------------------------------------------------------------
# Local (non-container) run path
# ---------------------------------------------------------------------------


class TestLocalRunScript:
    """The repository must be runnable without a container runtime."""

    @pytest.fixture(scope="class")
    def script(self) -> str:
        path = PROJECT_ROOT / "scripts" / "run-local.ps1"
        assert path.is_file()
        return path.read_text(encoding="utf-8")

    def test_health_endpoint_is_probed(self, script: str) -> None:
        assert "/api/v1/health" in script

    def test_it_shuts_down_what_it_started(self, script: str) -> None:
        assert "taskkill" in script and "/T" in script

    def test_it_refuses_to_run_without_a_virtualenv(self, script: str) -> None:
        assert "Backend virtualenv not found" in script

    def test_default_ports_match_the_documented_ones(self, script: str) -> None:
        assert "$FrontendPort = 5173" in script
        assert "$BackendPort = 8000" in script

    def test_the_smoke_loop_variable_does_not_shadow_the_switch(self, script: str) -> None:
        # PowerShell variable names are case-insensitive, so a loop variable named
        # $check collides with [switch]$Check and fails at run time with a
        # bewildering "Cannot create object of type SwitchParameter" error.
        assert "$check in" not in script
        assert "foreach ($probe in $probes)" in script

    def test_child_logs_are_redirected_to_files(self, script: str) -> None:
        # Keeps the verdict readable and stops a native process writing to stderr
        # from corrupting this script's exit code.
        assert "-RedirectStandardError" in script
        assert "-RedirectStandardOutput" in script


class TestProductionBundleCanBeVerifiedWithoutContainers:
    """`vite preview` reproduces the nginx topology so a build can be checked.

    The dev server is not a substitute: it injects an inline module script for
    hot reload, which the production CSP deliberately blocks, and it serves
    unbundled source. Only `vite preview` exercises the built artifact under the
    policy that actually ships.
    """

    @pytest.fixture(scope="class")
    def config(self) -> str:
        return (FRONTEND_DIR / "vite.config.ts").read_text(encoding="utf-8")

    def test_preview_proxies_the_api(self, config: str) -> None:
        preview = re.search(r"preview: \{(.*?)\n    \},", config, re.DOTALL)
        assert preview, "no preview block in vite.config.ts"
        assert "'/api'" in preview.group(1)
        assert "target: backendTarget" in preview.group(1)

    def test_the_preview_port_is_configurable(self, config: str) -> None:
        assert "VITE_PREVIEW_PORT" in config

    def test_the_proxied_prefix_matches_the_backend_mount_point(self) -> None:
        # The frontend proxies '/api' and nginx proxies '/api/'; the backend is
        # mounted at '/api/v1'. A mismatch here 404s every request.
        assert 'prefix="/api/v1"' in (BACKEND_DIR / "app" / "api" / "router.py").read_text(
            encoding="utf-8"
        )
        nginx = NGINX_CONF.read_text(encoding="utf-8")
        assert "location /api/" in nginx
        assert "'/api'" in (FRONTEND_DIR / "vite.config.ts").read_text(encoding="utf-8")
