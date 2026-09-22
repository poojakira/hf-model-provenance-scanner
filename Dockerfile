FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build
COPY pyproject.toml ./
COPY scanner ./scanner

RUN python -m pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /wheels

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="HF Model Provenance Scanner"
LABEL org.opencontainers.image.description="ML model supply-chain admission scanner"
LABEL org.opencontainers.image.source="https://github.com/poojakira/hf-model-provenance-scanner"
LABEL org.opencontainers.image.authors="Pooja Kiran <poojakira>"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system scanner \
    && useradd --system --gid scanner --create-home --home-dir /home/scanner scanner

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels \
    && hf-scanner --version

USER scanner
WORKDIR /workspace

ENTRYPOINT ["hf-scanner"]
CMD ["--help"]
