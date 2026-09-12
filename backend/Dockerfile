# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Backend image: FastAPI + SQLite + FAISS.
#
# Two stages so the compiler toolchain never reaches the runtime image. The
# runtime stage installs `libgomp1` explicitly: FAISS is built against OpenMP
# and the slim base image does not include it, which shows up as an opaque
# import error at start-up rather than a build failure.
# ---------------------------------------------------------------------------

FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Only needed if a wheel is unavailable for this platform; discarded afterwards.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependencies first: this layer is cached until requirements.txt changes.
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user. The application never needs to write outside /app/data,
# which is a mounted volume owned by this user.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser knowledge_base ./knowledge_base

# Mount point for the SQLite database and the vector index.
#
# The chown is load-bearing, not cosmetic. When Docker mounts a *named volume*
# onto a path that already exists in the image, it seeds the empty volume with
# that directory's contents **and ownership**. Because /app/data is owned by
# appuser here, the volume comes up writable by uid 10001. Remove this line and
# the container starts as an unprivileged user that cannot create its own
# database.
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data

USER appuser

EXPOSE 8000

# Uses the interpreter rather than curl: curl is not in the slim image, and the
# health endpoint is the application's own readiness signal.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).getcode() == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
