# Implementation Plan: `git-secret-entropy-scanner`

## Project: `git-secret-entropy-scanner`
**Language:** C++20  
**Build System:** CMake 3.22+  
**Target Delivery:** High-throughput Git history auditor and secret scanner with Shannon entropy analysis and false-positive suppression.

---

## 1. Task Breakdown & Phases

### Phase 1: Environment & Core Detection Primitives
- [x] Configure `CMakeLists.txt` with C++20 standard, strict compiler warnings (`-Wall -Wextra -Wpedantic`), `-O3` optimization, and CTest integration.
- [x] Implement `EntropyCalculator`:
  - 256-bin character frequency counting without heap allocation.
  - Shannon entropy computation $H = -\sum p_i \log_2(p_i)$.
  - Base64 ($H > 4.5$) and Hexadecimal ($H > 3.0$) character set classification and thresholding.
- [x] Implement `RuleEngine`:
  - Precompiled regex catalog (AWS, GitHub, Slack, Stripe, GCP, PEM, JWT).
  - Secret masking utility (`AKIA****...****1234`).
- [x] Implement `FalsePositiveFilter`:
  - UUID pattern detection.
  - Commit SHA suppression.
  - Test/placeholder keyword heuristics.

### Phase 2: Scanner Engine & Thread Pool
- [x] Implement `SecretFinding` and `ScanStats` data models.
- [x] Implement `ThreadPool`: lightweight modern C++20 worker thread queue.
- [x] Implement `Scanner`:
  - Line-by-line and token-by-token evaluation.
  - Assignment context extractor (`key = "..."`).
  - Thread-safe result aggregation.

### Phase 3: Git History & Filesystem Walkers
- [x] Implement `GitLogParser`:
  - Subprocess pipe reader for `git log -p --full-history`.
  - Incremental parsing of commit metadata, diff boundaries, and added lines (`+`).
- [x] Implement `DirectoryWalker`:
  - Recursive directory scanner with `.git` and binary file skip filters.
- [x] Implement Stdin / single-file scanner.

### Phase 4: Reporting & Verification Suite
- [x] Implement `ConsoleReporter` with color-coded masked findings and summary statistics.
- [x] Implement `JsonReporter` for machine-readable CI/CD ingestion.
- [x] Write unit tests:
  - `tests/TestEntropy.cpp`: Shannon entropy precision.
  - `tests/TestRules.cpp`: Signature regex accuracy and masking.
  - `tests/TestFalsePositives.cpp`: Suppression heuristics.
  - `tests/TestGitScan.cpp`: In-memory / synthetic Git repo history audit.

### Phase 5: CLI, Benchmarking & Packaging
- [x] Implement `secret_scanner_cli` supporting `scan-git`, `scan-dir`, `scan-file`, and `bench`.
- [x] Run benchmark measuring lines/second (> 300,000 lines/sec).
- [x] Write `docs/EXPLAIN.md` (6 sections), `README.md` (with actual benchmark results), `CHANGELOG.md`, `Dockerfile`, `.github/workflows/ci.yml`.
- [x] Verify formatting with `clang-format`.
- [x] Git commit, tag `v1.0.0`, publish to GitHub.
- [x] Update portfolio tracking documents (`PROGRESS.md`, `PUBLISH_LOG.md`, `REPORT.md`).
