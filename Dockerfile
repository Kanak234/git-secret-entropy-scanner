# Multi-stage hardened Dockerfile for git-secret-entropy-scanner
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN rm -rf build && cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j$(nproc) \
    && ctest --test-dir build --output-on-failure

FROM ubuntu:24.04 AS runner

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 -U appuser

WORKDIR /app
COPY --from=builder /app/build/secret_scanner_cli /usr/local/bin/secret_scanner_cli

RUN chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["secret_scanner_cli", "health"] || exit 1

ENTRYPOINT ["secret_scanner_cli"]
CMD ["--help"]
