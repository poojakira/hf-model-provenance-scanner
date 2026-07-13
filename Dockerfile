# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Build stage: install the package into an isolated virtualenv. Any pip/build
# work happens here, so it never runs in (or leaves cached layers owned by
# root in) the runtime image.
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Create a self-contained venv we can copy into the runtime image.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY scanner/ /build/scanner/
COPY pyproject.toml /build/

RUN pip install --no-cache-dir .

# ---------------------------------------------------------------------------
# Runtime stage: minimal, non-root, no build tooling or pip in the final image.
# (For an even smaller attack surface this can be swapped for a distroless
# python base; slim keeps a shell for the HEALTHCHECK below.)
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="HF Model Provenance Scanner"
LABEL org.opencontainers.image.description="Zero-dependency ML supply chain security scanner"
LABEL org.opencontainers.image.source="https://github.com/poojakira/hf-model-provenance-scanner"
LABEL org.opencontainers.image.authors="Pooja Kiran <poojakira>"

# Create an unprivileged user before copying anything.
RUN useradd -m -s /bin/bash -u 10001 scanner

# Copy the pre-built virtualenv from the builder stage.
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

USER scanner
WORKDIR /workspace

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["hf-scanner", "--version"]

ENTRYPOINT ["hf-scanner"]
CMD ["--help"]
