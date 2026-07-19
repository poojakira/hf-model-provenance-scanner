FROM python:3.14-slim

LABEL org.opencontainers.image.title="HF Model Provenance Scanner"
LABEL org.opencontainers.image.description="Zero-dependency ML supply chain security scanner"
LABEL org.opencontainers.image.source="https://github.com/poojakira/hf-model-provenance-scanner"
LABEL org.opencontainers.image.authors="Pooja Kiran <poojakira>"

WORKDIR /scanner

# Copy scanner source (zero dependencies, no pip install needed)
COPY scanner/ /scanner/scanner/
COPY pyproject.toml /scanner/

# Install for entry point
RUN pip install --no-cache-dir -e . && \
    # Verify installation
    hf-scanner --version

# Non-root user for security
RUN useradd -m -s /bin/bash scanner
USER scanner

WORKDIR /workspace

ENTRYPOINT ["hf-scanner"]
CMD ["--help"]
