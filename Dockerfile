# syntax=docker/dockerfile:1.12@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25
ARG PYTHON_IMAGE=python:3.14.6-slim-bookworm@sha256:4c92ffcde4dd6f1ff72a24518f49fd4990b27134987dfa31a733badde66df9f8

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# uv is a build tool only. Runtime dependencies and the application itself are
# resolved exclusively from the reviewed lock file.
RUN python -m pip install "uv==0.12.5"
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable \
    && rm -rf /tmp/uv-cache

FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="soffortbackend" \
      org.opencontainers.image.description="Authenticated stateless MCP resource server" \
      org.opencontainers.image.source="https://github.com/AlphonseKurian1618/soffortmcp" \
      org.opencontainers.image.licenses="MIT"

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 soffort \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin soffort

COPY --from=builder --chown=10001:10001 /opt/venv /opt/venv

WORKDIR /app
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/livez', timeout=2)"]

ENTRYPOINT ["python", "-m", "soffortbackend"]
