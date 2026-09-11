#pragma once

#include <cstdint>
#include <string>

namespace scanner {

enum class Severity { Low, Medium, High, Critical };

struct SecretFinding {
  std::string ruleId;
  std::string description;
  std::string matchedText;
  std::string maskedText;
  std::string filePath;
  size_t lineNumber{0};
  std::string commitHash;
  std::string commitAuthor;
  std::string commitDate;
  double entropy{0.0};
  std::string lineContent;
  Severity severity{Severity::High};
};

struct ScanStats {
  size_t totalLines{0};
  size_t totalCommits{0};
  size_t totalFiles{0};
  size_t totalFindings{0};
  double scanDurationMs{0.0};
};

} // namespace scanner
