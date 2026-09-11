#pragma once

#include "scanner/SecretFinding.hpp"
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace scanner {

struct SecretRule {
  std::string ruleId;
  std::string description;
  std::regex regexPattern;
  Severity severity;
  bool requireHighEntropy{false};
};

class RuleEngine {
public:
  RuleEngine();

  /**
   * Scans a single line of text for secrets against compiled rules and entropy
   * checks.
   */
  void scanLine(std::string_view line, std::string_view filePath,
                size_t lineNumber, const std::string &commitHash,
                const std::string &author, const std::string &date,
                std::vector<SecretFinding> &findingsOut) const;

  /**
   * Masks sensitive secret values for safe terminal / log display.
   * e.g., "AKIAIOSFODNN7EXAMPLE" -> "AKIA****...****MPLE"
   */
  [[nodiscard]] static std::string maskSecret(std::string_view secret) noexcept;

  [[nodiscard]] const std::vector<SecretRule> &rules() const noexcept {
    return rules_;
  }

private:
  void initRules();
  std::vector<SecretRule> rules_;
  std::regex genericAssignmentPattern_;
};

} // namespace scanner
