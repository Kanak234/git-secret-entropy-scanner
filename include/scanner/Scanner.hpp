#pragma once

#include "scanner/RuleEngine.hpp"
#include "scanner/SecretFinding.hpp"
#include "scanner/ThreadPool.hpp"
#include <filesystem>
#include <mutex>
#include <span>
#include <vector>

namespace scanner {

class Scanner {
public:
  explicit Scanner(size_t threadCount = 0);

  ScanStats scanGitRepository(const std::filesystem::path &repoPath,
                              const std::string &revisionRange = "HEAD");

  ScanStats scanDirectory(const std::filesystem::path &dirPath);

  ScanStats scanFile(const std::filesystem::path &filePath);

  ScanStats scanStream(std::istream &is,
                       const std::string &streamName = "stdin");

  [[nodiscard]] const std::vector<SecretFinding> &findings() const noexcept {
    return findings_;
  }
  void clearFindings() noexcept { findings_.clear(); }

private:
  void addFindings(std::vector<SecretFinding> &&newFindings);

  RuleEngine ruleEngine_;
  ThreadPool threadPool_;
  std::vector<SecretFinding> findings_;
  std::mutex findingsMutex_;
};

} // namespace scanner
