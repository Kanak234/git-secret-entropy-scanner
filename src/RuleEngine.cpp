#include "scanner/RuleEngine.hpp"

#include <sstream>

#include "scanner/EntropyCalculator.hpp"
#include "scanner/FalsePositiveFilter.hpp"

namespace scanner {

RuleEngine::RuleEngine() { initRules(); }

void RuleEngine::initRules() {
  rules_.push_back({"AWS_ACCESS_KEY", "AWS Access Key ID",
                    std::regex(R"(\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b)"),
                    Severity::Critical, false});

  rules_.push_back(
      {"GITHUB_PAT", "GitHub Personal Access Token",
       std::regex(
           R"(\b(ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82}|gho_[A-Za-z0-9_]{36}|ghs_[A-Za-z0-9_]{36})\b)"),
       Severity::Critical, false});

  rules_.push_back({"SLACK_TOKEN", "Slack API Token",
                    std::regex(R"(\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b)"),
                    Severity::High, false});

  rules_.push_back({"STRIPE_KEY", "Stripe API Secret Key",
                    std::regex(R"(\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,34}\b)"), Severity::Critical,
                    false});

  rules_.push_back({"GOOGLE_API_KEY", "Google Cloud API Key",
                    std::regex(R"(\bAIza[0-9A-Za-z\-_]{35}\b)"), Severity::High, false});

  rules_.push_back({"PEM_PRIVATE_KEY", "Unencrypted PEM Private Key Header",
                    std::regex(R"(-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----)"),
                    Severity::Critical, false});

  rules_.push_back(
      {"JWT_TOKEN", "JSON Web Token (JWT)",
       std::regex(R"(\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)"),
       Severity::Medium, false});

  // Generic key-value assignment regex: api_key = "..."
  genericAssignmentPattern_ = std::regex(
      R"((?:api[_-]?key|apikey|secret|token|password|passwd|auth[_-]?token|client[_-]?secret|access[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_\-\+\/=]{16,})["']?)",
      std::regex_constants::icase);
}

std::string RuleEngine::maskSecret(std::string_view secret) noexcept {
  if (secret.size() <= 6) {
    return "******";
  }
  if (secret.size() <= 12) {
    std::string s;
    s += secret.front();
    s += "****";
    s += secret.back();
    return s;
  }

  std::string masked;
  masked += secret.substr(0, 4);
  masked += "****...****";
  masked += secret.substr(secret.size() - 4);
  return masked;
}

void RuleEngine::scanLine(std::string_view line, std::string_view filePath, size_t lineNumber,
                          const std::string& commitHash, const std::string& author,
                          const std::string& date, std::vector<SecretFinding>& findingsOut) const {
  if (line.empty()) return;
  std::string lineStr(line);

  // 1. Signature Regex Rules
  for (const auto& rule : rules_) {
    std::smatch match;
    std::string::const_iterator searchStart(lineStr.cbegin());

    while (std::regex_search(searchStart, lineStr.cend(), match, rule.regexPattern)) {
      std::string matchedStr = match.str(0);

      if (!FalsePositiveFilter::isFalsePositive(matchedStr, filePath, line)) {
        SecretFinding finding;
        finding.ruleId = rule.ruleId;
        finding.description = rule.description;
        finding.matchedText = matchedStr;
        finding.maskedText = maskSecret(matchedStr);
        finding.filePath = std::string(filePath);
        finding.lineNumber = lineNumber;
        finding.commitHash = commitHash;
        finding.commitAuthor = author;
        finding.commitDate = date;
        finding.entropy = EntropyCalculator::calculateShannonEntropy(matchedStr);
        finding.lineContent = lineStr;
        finding.severity = rule.severity;

        findingsOut.push_back(std::move(finding));
      }

      searchStart = match.suffix().first;
    }
  }

  // 2. Generic High-Entropy Assignment Detection
  std::smatch genericMatch;
  std::string::const_iterator start(lineStr.cbegin());

  while (std::regex_search(start, lineStr.cend(), genericMatch, genericAssignmentPattern_)) {
    if (genericMatch.size() > 1) {
      std::string candidate = genericMatch.str(1);

      if (!FalsePositiveFilter::isFalsePositive(candidate, filePath, line)) {
        double ent = EntropyCalculator::calculateShannonEntropy(candidate);
        if (EntropyCalculator::isHighEntropy(candidate)) {
          SecretFinding finding;
          finding.ruleId = "HIGH_ENTROPY_CREDENTIAL";
          finding.description = "High-Entropy Credential Assignment";
          finding.matchedText = candidate;
          finding.maskedText = maskSecret(candidate);
          finding.filePath = std::string(filePath);
          finding.lineNumber = lineNumber;
          finding.commitHash = commitHash;
          finding.commitAuthor = author;
          finding.commitDate = date;
          finding.entropy = ent;
          finding.lineContent = lineStr;
          finding.severity = Severity::High;

          findingsOut.push_back(std::move(finding));
        }
      }
    }
    start = genericMatch.suffix().first;
  }
}

}  // namespace scanner
