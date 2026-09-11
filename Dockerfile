# Multi-stage Dockerfile for git-secret-entropy-scanner
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

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build -j$(nproc)
RUN ctest --test-dir build --output-on-failure

FROM ubuntu:24.04 AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/secret_scanner_cli /usr/local/bin/secret_scanner_cli

ENTRYPOINT ["secret_scanner_cli"]
CMD ["--help"]
