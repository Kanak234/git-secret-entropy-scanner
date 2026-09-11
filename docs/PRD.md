# Product Requirements Document (PRD)

## Project: `git-secret-entropy-scanner`
**Domain:** Defensive Cybersecurity  
**Language / Tech Stack:** Modern C++ (C++20), CMake 3.22+, Multi-threaded Task Pool  
**Target Delivery:** High-throughput, zero-dependency Git history auditor and secret scanner combining Shannon entropy analysis, multi-vendor signature regexes, and contextual false-positive suppression.

---

## 1. Executive Summary & Problem Statement

Leaked credentials (API keys, private keys, database connection strings, access tokens) committed to public or internal Git repositories represent one of the most common and devastating vectors for security breaches. Scanning repository histories requires analyzing every commit diff across all branches, which often totals millions of lines of historical code.

Traditional regex-only secret scanners fail in two distinct ways:
1. **False Negatives:** Custom internal API tokens, high-entropy passwords, or newly introduced cloud service tokens without known rigid prefixes go undetected.
2. **False Positives:** Naïve high-entropy scanners flag commit hashes, UUIDs, base64-encoded icons, cryptographic salt constants, and test fixtures, overwhelming security engineers with thousands of unusable alerts.

`git-secret-entropy-scanner` is an ultra-fast, production-grade C++20 security auditing engine that provides:
1. Multi-threaded diff and file scanning pipeline processing $>500,000$ lines/sec.
2. Fast Shannon entropy calculation over specialized character sets (Base64 $>4.5$ bits/char, Hex $>3.0$ bits/char).
3. Comprehensive built-in signature catalog: AWS Access/Secret Keys, GitHub PATs/Fine-grained tokens, Slack tokens, Stripe API keys, Google Cloud API keys, PEM Private Keys, JWT tokens, and generic high-entropy assignments.
4. Robust false-positive suppression: filtering UUIDs, hex commit hashes, placeholder words (`example`, `dummy`, `test`, `placeholder`), and documentation/fixture files.
5. Flexible scanning modes: full git history (`git log -p`), working directory, single files, and stdin piping, with human-readable CLI summary and machine-readable JSON output.

---

## 2. Goals & Non-Goals

### Goals
- **High Throughput:** Scan over 500,000 lines per second on modern multi-core x86_64 machines using a thread-pool worker queue.
- **Zero Third-Party Library Dependencies:** Implemented in pure standard C++20 (`std::regex`, `std::jthread`, `std::span`, `std::filesystem`) for effortless cross-platform builds without external dependency linking.
- **Dual Detection Strategy:** Combine deterministic regex patterns for known vendor formats with probabilistic Shannon entropy thresholding for unknown/custom credentials.
- **Low False Positive Rate:** Context-aware heuristics (key-value assignment proximity, entropy calculation restricted to alphanumeric segments, suppression of hashes and UUIDs).
- **Security-First Reporting:** Mask detected secrets in console output (`AKIA****...****1234`) while preserving exact commit, author, file path, and line number metadata for remediation.

### Non-Goals
- Automated secret revocation or cloud provider API rotation (reporting and auditing only).
- Dynamic secret validation against cloud provider endpoints (offline defensive scanner).

---

## 3. Target Users & Use Cases

- **Application Security (AppSec) Engineers:** Auditing Git repositories during security assessments, pre-commit enforcement, or CI/CD gate checks.
- **DevOps / CI/CD Pipelines:** Automated gatekeeper preventing credentials from entering staging or production branches.
- **Developers & Code Reviewers:** Fast local pre-commit or pre-push verification.

---

## 4. Functional Requirements

### 4.1 Detection Rules Catalog
1. **AWS Access Key ID:** `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`
2. **AWS Secret Access Key:** 40-character Base64 string assigned to aws secret context.
3. **GitHub Personal Access Token:**
   - Classic: `ghp_[0-9a-zA-Z]{36}`
   - Fine-grained: `github_pat_[0-9a-zA-Z_]{82}`
   - OAuth / App tokens: `gho_[0-9a-zA-Z]{36}`, `ghs_[0-9a-zA-Z]{36}`, `ghr_[0-9a-zA-Z]{36}`
4. **Slack Tokens:** `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`
5. **Stripe API Keys:** `(sk|rk)_(live|test)_[0-9a-zA-Z]{24,34}`
6. **Google Cloud API Key:** `AIza[0-9A-Za-z\\-_]{35}`
7. **PEM Private Keys:** `-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`
8. **JSON Web Tokens (JWT):** `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
9. **Generic High-Entropy Credential:** Key-value assignments (e.g., `api_key = "..."`, `password: "..."`, `token = "..."`) containing strings exceeding Shannon entropy thresholds.

### 4.2 Shannon Entropy Engine
- Computes information entropy:
  $$H(S) = -\sum_{i=1}^{k} P(c_i) \log_2 P(c_i)$$
- Character set detection:
  - Hexadecimal: characters $\in [0-9a-fA-F]$, threshold $H > 3.0$ bits/char (length $\ge 20$).
  - Base64: characters $\in [0-9a-zA-Z+/=]$, threshold $H > 4.5$ bits/char (length $\ge 24$).
- Sliding window or token-based entropy evaluation over continuous strings.

### 4.3 False-Positive Filtering Heuristics
- Filter strings matching standard UUID pattern `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`.
- Filter Git commit SHA hashes (40-character or 64-character hex strings in git context).
- Filter common placeholder substrings: `dummy`, `example`, `placeholder`, `mock`, `fake`, `test123`, `your_api_key`.
- Low-entropy repetition detection (e.g. `aaaaaaaa...`, `0123456789...`).

### 4.4 Scanning Interfaces
- **Git History Scan (`scan-git`):** Streams `git log -p --full-history` or commits, tracking commit hash, author, commit date, file path, and line numbers of added lines (`+`).
- **Filesystem Scan (`scan-dir`):** Recursively scans directories, skipping `.git`, `node_modules`, `build`, binary files.
- **Single File / Stdin Scan (`scan-file`):** Audits individual files or stdin streams.

### 4.5 Output Formats
- Formatted human-readable terminal table with color highlighting and secret masking.
- Structured JSON output (`--json` or `-o results.json`) containing complete audit records.
- Exit code: 0 if no secrets found, 1 if secrets detected, 2 on operational error.

---

## 5. Acceptance Criteria

1. **Detection Accuracy:** 100% detection on benchmark secrets corpus containing AWS, GitHub, Slack, Stripe, PEM, and high-entropy API keys.
2. **False-Positive Suppression:** Zero false positives on UUIDs, commit hashes, and benign test placeholders.
3. **Throughput:** Exceeds 500,000 lines/sec on multi-threaded scan of large commit histories.
4. **Clean Code & Tests:** 100% CTest pass rate, zero compiler warnings with `-Wall -Wextra -Wpedantic`, zero memory leaks.
