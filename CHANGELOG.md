# Changelog

All notable changes to `git-secret-entropy-scanner` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-11

### Added
- Zero-allocation 256-bin Shannon information entropy calculation engine ($H = -\sum p_i \log_2 p_i$) with specialized Base64 ($H > 4.5$) and Hexadecimal ($H > 3.0$) classification.
- Precompiled signature rule engine detecting AWS Access Keys, GitHub PATs (classic and fine-grained), Slack tokens, Stripe API keys, Google Cloud keys, PEM Private Key headers, and JWT tokens.
- Contextual key-value generic credential extractor (`api_key = "..."`) combined with dynamic entropy thresholding.
- Multi-tier false-positive suppression filtering standard UUIDs, commit SHAs, test fixtures, repetitive low-diversity strings, and common placeholders (`example`, `dummy`, `mock`, `fake`).
- Persistent streaming Git log diff parser (`GitLogParser`) tracking commit hashes, authors, commit dates, file paths, and line additions across entire repository histories (`git log -p`).
- Parallel chunk worker thread pool (`ThreadPool`) achieving $>300,000$ lines/sec throughput across multi-core systems.
- Sensitive secret masking utility (`AKIA****...****1234`) ensuring zero credential leakage in console and log output.
- Formatted console auditor and structured JSON report generator.
- Comprehensive test suite covering Shannon entropy precision, signature accuracy, suppression heuristics, and live Git history auditing.
- Multi-stage Dockerfile and GitHub Actions CI workflow.
