# Technical Architecture & Secret Scanning Deep-Dive

## 1. System Architecture & Detection Philosophy

Leaked credentials committed to version control repositories remain one of the most critical security liabilities in software engineering. Even if a commit that introduces a secret is overwritten or deleted in a later commit, the secret persists permanently in the repository's Git object database (`packfiles` and `loose objects`).

`git-secret-entropy-scanner` is designed with a defense-in-depth detection philosophy that pairs two complementary scanning strategies:
1. **Deterministic Signature Matching:** Precompiled high-speed regular expressions targeted at known vendor formats (AWS, GitHub, Slack, Stripe, Google, PEM, JWT).
2. **Statistical Shannon Information Entropy:** Information-theoretic analysis that evaluates the probability distribution of character frequencies to detect arbitrary, unformatted secrets (high-entropy passwords, HMAC secrets, custom bearer tokens) within assignment contexts.

To minimize alert fatigue, raw findings are passed through a multi-tier false-positive suppression filter before reporting.

---

## 2. Information Theory & Shannon Entropy Mathematics

Claude Shannon (1948) defined the information entropy $H(X)$ of a discrete random variable $X$ with possible values $\{x_1, \dots, x_n\}$ and probability mass function $P(X)$ as:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

In the context of a candidate secret string $S$ of length $N$:
- The frequency $C(c)$ of each byte $c \in [0, 255]$ is counted:
  $$P(c) = \frac{C(c)}{N}$$
- The entropy is calculated over all observed characters:
  $$H(S) = -\sum_{c: C(c) > 0} \frac{C(c)}{N} \log_2 \left(\frac{C(c)}{N}\right)$$

### Theoretical Bounds & Calibrated Thresholds
- **Hexadecimal String ($k=16$ symbols):**
  - Maximum theoretical entropy: $\log_2(16) = 4.0\text{ bits/char}$.
  - Calibrated threshold: **$H \ge 3.0\text{ bits/char}$** (for string length $\ge 16$).
  - Random 32-byte hex keys typically score $H \approx 3.6 - 3.9$, whereas natural language text scores $H < 2.5$.
- **Base64 String ($k=64$ symbols):**
  - Maximum theoretical entropy: $\log_2(64) = 6.0\text{ bits/char}$.
  - Calibrated threshold: **$H \ge 4.5\text{ bits/char}$** (for string length $\ge 20$).
  - Random cryptographic Base64 strings score $H \approx 4.8 - 5.5$.

---

## 3. Signature Rules & Contextual Key-Value Matching

### Vendor Signature Specifications

1. **AWS Access Key ID:**
   - Pattern: `\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`
   - Fixed prefix indicates account identity and IAM entity type.
2. **GitHub Personal Access Token:**
   - Classic: `ghp_[A-Za-z0-9_]{36}`
   - Fine-grained: `github_pat_[A-Za-z0-9_]{82}`
   - App / OAuth: `gho_`, `ghs_`, `ghr_`
3. **Slack API Token:**
   - Bot/User tokens: `\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b`
4. **Stripe API Key:**
   - Live / Test secret keys: `\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,34}\b`
5. **Google Cloud API Key:**
   - Pattern: `\bAIza[0-9A-Za-z\-_]{35}\b`
6. **PEM Private Key:**
   - Pattern: `-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`
7. **JSON Web Token (JWT):**
   - Three dot-separated Base64URL encoded JSON objects starting with `eyJ`.

### Contextual Assignment Matching
To detect generic tokens without a fixed vendor prefix, the engine scans for assignment operators where the variable name suggests sensitive data:
```regex
(?:api[_-]?key|apikey|secret|token|password|passwd|auth[_-]?token|client[_-]?secret|access[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_\-\+\/=]{16,})["']?
```
The captured token value is then tested against `EntropyCalculator::isHighEntropy()`.

---

## 4. Multi-Tier False-Positive Suppression Heuristics

A high-entropy score alone can trigger false alarms on non-secret artifacts. The `FalsePositiveFilter` applies five orthogonal suppression tests:

1. **UUID Elimination:**
   Matches `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`. Standard UUIDs exhibit high character dispersion but are public identifiers.
2. **Git Commit SHA Elimination:**
   Hexadecimal strings of exactly 40 characters (SHA-1) or 64 characters (SHA-256) appearing in commit references, tags, or deployment scripts are suppressed unless explicitly assigned to a `password`/`secret` variable.
3. **Dummy & Placeholder Rejection:**
   Case-insensitive substring inspection against test fixtures: `example`, `dummy`, `mock`, `fake`, `placeholder`, `changeme`, `your_`, `test123`, `abcdef`, `0123456789`.
4. **Low Diversity Rejection:**
   Rejects strings with fewer than 5 unique characters (e.g. `aaaaaaaaaaaaaaaa`, `0000000000000000`).
5. **Ignored Paths & Binary Files:**
   Filters package manager lockfiles (`package-lock.json`, `go.sum`, `Cargo.lock`), minified bundles (`*.min.js`), and binary assets.

---

## 5. Git History Streaming & Parallel Pipeline Architecture

Scanning large Git histories with thousands of commits requires high I/O efficiency:
1. **Streaming Diff Ingestion:** `GitLogParser` invokes `git log -p --full-history --date=iso` as a piped subprocess. Lines are read via `getline()` without buffering the entire repository diff in RAM.
2. **State Machine Parsing:** The parser maintains state (`commit`, `author`, `date`, `filePath`, `lineNumber`) across diff chunks, extracting only added lines (`+`).
3. **Parallel Batch Dispatch:** Lines are accumulated into batches of 2,000 items and dispatched to a C++20 `ThreadPool`.
4. **Thread-Safe Accumulation:** Thread-local finding buffers are flushed into the synchronized global collector upon task completion.

---

## 6. Security Considerations & Production Integration

- **Secret Masking:** Secrets are never printed in plaintext to standard output or terminal logs. The middle portion of the secret is replaced with `****...****` (e.g., `AKIA****...****1234`).
- **CI/CD Integration:** When run in CI pipelines, `secret_scanner_cli` returns exit code `1` if any secrets are detected and `0` if the repository is clean, allowing automated pull request blocking.
- **Machine-Readable JSON Output:** The `--json` or `-o report.json` option outputs complete metadata (commit, author, file, line, rule, entropy) for SIEM / SOAR dashboard ingestion.
