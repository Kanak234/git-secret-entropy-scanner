# Technical Requirements Document (TRD)

## Project: `git-secret-entropy-scanner`
**Language:** Modern C++ (C++20 Standard)  
**Compiler Support:** GCC 11+, Clang 14+  
**Build System:** CMake 3.22+  
**Concurrency:** C++20 standard concurrency (`std::jthread`, `std::mutex`, `std::condition_variable`)

---

## 1. System Architecture & Component Design

```
┌─────────────────────────────────────────────────────────────┐
│                       CLI Application                        │
│               (scan-git, scan-dir, scan-file)               │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌─────────────────────────────┐┌──────────────────────────────┐
│        GitLogParser         ││     Filesystem Directory     │
│   Streams diff additions    ││           Walker             │
│   commit, author, file, line││    Binary & ignore filter    │
└──────────────┬──────────────┘└──────────────┬───────────────┘
               │                              │
               └──────────────┬───────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Parallel Scanner Engine                  │
│                     (Thread-Pool Queue)                     │
│                                                             │
│  ┌───────────────────────┐      ┌────────────────────────┐  │
│  │      RuleEngine       │      │   EntropyCalculator    │  │
│  │   Precompiled Regex   │      │ Fast Shannon Frequency │  │
│  │   Vendor Signatures   │      │ Base64 & Hex Threshold │  │
│  └───────────┬───────────┘      └────────────┬───────────┘  │
│              │                               │              │
│              └──────────────┬────────────────┘              │
│                             │                               │
│                             ▼                               │
│                 ┌───────────────────────┐                   │
│                 │  FalsePositiveFilter  │                   │
│                 │ UUIDs, SHAs, keywords │                   │
│                 └───────────┬───────────┘                   │
└─────────────────────────────┼───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Report Generator                       │
│             - Masked Human Console Summary                  │
│             - Structured JSON Format                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Core Data Structures

### 2.1 `SecretFinding`
```cpp
struct SecretFinding {
    std::string ruleId;          // e.g. "AWS_ACCESS_KEY", "HIGH_ENTROPY_BASE64"
    std::string description;     // e.g. "AWS Access Key ID"
    std::string matchedText;     // Raw secret text (masked for display)
    std::string maskedText;      // e.g. "AKIA****...****1234"
    std::string filePath;        // File path where secret was found
    size_t lineNumber{0};        // Line number in file / diff
    std::string commitHash;      // Git commit hash (empty if working tree)
    std::string commitAuthor;    // Git author name / email
    std::string commitDate;      // Git commit timestamp
    double entropy{0.0};         // Shannon entropy bits/char
    std::string lineContent;     // Full line snippet
};
```

### 2.2 `EntropyCalculator`
Shannon entropy formula:
$$H = -\sum_{c} \frac{count[c]}{N} \log_2 \left(\frac{count[c]}{N}\right)$$
- Fast counting: fixed 256-element stack array `uint32_t counts[256]{0}`.
- Length bounds: minimum 16 characters for Hex, 20 characters for Base64.
- Thresholds:
  - Hexadecimal: $> 3.0$ bits/character (max theoretical is $\log_2(16) = 4.0$).
  - Base64: $> 4.5$ bits/character (max theoretical is $\log_2(64) = 6.0$).

### 2.3 `RuleEngine`
Precompiled patterns:
1. `AWS_ACCESS_KEY`: `\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`
2. `GITHUB_PAT`: `\b(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})\b`
3. `SLACK_TOKEN`: `\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b`
4. `STRIPE_KEY`: `\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,34}\b`
5. `GOOGLE_API_KEY`: `\bAIza[0-9A-Za-z\\-_]{35}\b`
6. `PEM_PRIVATE_KEY`: `-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`
7. `JWT_TOKEN`: `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`
8. `GENERIC_SECRET_ASSIGNMENT`: Key-value regex with entropy validation.

### 2.4 `FalsePositiveFilter`
Rejection conditions:
- **UUID pattern:** `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
- **Hex hash pattern:** Commit hashes (40 or 64 hex characters) without key context.
- **Placeholder words:** Contains `example`, `dummy`, `test`, `placeholder`, `fake`, `your_token`, `foo`, `bar`.
- **Low entropy character diversity:** Unique character count $< 8$.

---

## 3. Git Streaming & Concurrency Architecture

- **`GitLogParser`:** Runs `git log -p --full-history --date=iso` as a piped subprocess.
- Parses headers:
  - `commit <hash>`
  - `Author: <author>`
  - `Date: <date>`
  - `diff --git a/<path> b/<path>`
  - Line additions starting with `+` (ignoring `+++`).
- **Parallel Chunk Worker Pool:**
  - Buffers lines into chunks of 2,000 lines.
  - Distributes chunks to worker threads via an active task queue.
  - Aggregates findings in a thread-safe synchronized collector.

---

## 4. Verification Framework & Acceptance Criteria

- **Unit Tests (`tests/TestEntropy.cpp`):**
  - Verify Shannon entropy accuracy on known strings (random vs repetitive).
  - Verify Base64 vs Hex character set detection.
- **Rule Engine Tests (`tests/TestRules.cpp`):**
  - Verify each of the 8 signature types against real-world test cases.
  - Verify masking functions.
- **False-Positive Tests (`tests/TestFalsePositives.cpp`):**
  - Verify rejection of UUIDs, commit SHAs, URLs, and test fixtures.
- **End-to-End Git Scan Test (`tests/TestGitScan.cpp`):**
  - Initialize temporary git repo with injected commits, run scan, verify 100% detection.
- **Throughput Benchmark:**
  - Measure line scanning rate over 1,000,000 lines. Target $> 500,000$ lines/sec.
