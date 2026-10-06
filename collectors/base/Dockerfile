# Pinned by digest (multi-arch index observed 2026-10-06). Re-verify in CI on bump.
FROM python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

RUN apk add --no-cache tcpdump libpcap

WORKDIR /opt/ambercell/collector-base

# Build context: repository root (see collectors/README.md).
COPY collectors/base/pyproject.toml ./
COPY collectors/base/ambercell ./ambercell
COPY docs/schemas /opt/ambercell/schemas

ENV PYTHONUNBUFFERED=1
ENV AMBER_EVIDENCE_ROOT=/var/ambercell
ENV AMBER_SCHEMA_DIR=/opt/ambercell/schemas

RUN pip install --no-cache-dir ".[validate]"
