# Two stages: dependencies are compiled in the first and only the results are
# copied into the second. The build stage needs a C compiler for argon2-cffi and
# asyncpg; the runtime image must not ship one, because a compiler in a
# production container is a tool an attacker who lands there gets to use.

FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Dependencies are their own layer, keyed on the requirements file alone, so a
# source change does not reinstall the world.
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt


FROM python:3.12-slim AS runtime

# LOG_FORMAT/DEBUG default to the deployed choice here -- JSON logs for a
# shipper, and no SQL statement echo -- rather than to the local-development
# values in Settings. Compose or the orchestrator can still override them.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    LOG_FORMAT=json \
    DEBUG=false

WORKDIR /app

# curl is kept deliberately -- the healthcheck below uses it. Nothing else from
# the build toolchain comes across.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser . .

# Non-root, and the application directory is not writable by the user running
# it: this service never writes to its own filesystem.
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/v1/health || exit 1

# No --reload, no --workers here: process count is a deployment decision, set
# through the compose command or the orchestrator.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
