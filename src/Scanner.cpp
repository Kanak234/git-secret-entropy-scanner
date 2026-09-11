#include "scanner/Scanner.hpp"

#include <chrono>
#include <iostream>
#include <unordered_set>

#include "scanner/DirectoryWalker.hpp"
#include "scanner/GitLogParser.hpp"

namespace scanner {

Scanner::Scanner(size_t threadCount)
    : threadPool_(threadCount == 0 ? std::thread::hardware_concurrency() : threadCount) {}

void Scanner::addFindings(std::vector<SecretFinding>&& newFindings) {
  if (newFindings.empty()) return;
  std::lock_guard<std::mutex> lock(findingsMutex_);
  for (auto& f : newFindings) {
    findings_.push_back(std::move(f));
  }
}

ScanStats Scanner::scanGitRepository(const std::filesystem::path& repoPath,
                                     const std::string& revisionRange) {
  clearFindings();
  ScanStats stats;
  auto startTime = std::chrono::steady_clock::now();

  std::unordered_set<std::string> uniqueCommits;
  std::unordered_set<std::string> uniqueFiles;

  struct LineItem {
    std::string line;
    std::string file;
    size_t lineNum;
    std::string commit;
    std::string author;
    std::string date;
  };

  std::vector<LineItem> batch;
  batch.reserve(2000);

  auto dispatchBatch = [this, &batch]() {
    if (batch.empty()) return;
    auto currentBatch = std::move(batch);
    batch.clear();
    batch.reserve(2000);

    threadPool_.enqueue([this, items = std::move(currentBatch)]() {
      std::vector<SecretFinding> localFindings;
      localFindings.reserve(16);
      for (const auto& item : items) {
        ruleEngine_.scanLine(item.line, item.file, item.lineNum, item.commit, item.author,
                             item.date, localFindings);
      }
      if (!localFindings.empty()) {
        addFindings(std::move(localFindings));
      }
    });
  };

  GitLogParser::parseRepository(
      repoPath,
      [&](const DiffLine& dl) {
        stats.totalLines++;
        if (!dl.commitHash.empty()) uniqueCommits.insert(dl.commitHash);
        if (!dl.filePath.empty()) uniqueFiles.insert(dl.filePath);

        batch.push_back({dl.line, dl.filePath, dl.lineNumber, dl.commitHash, dl.author, dl.date});
        if (batch.size() >= 2000) {
          dispatchBatch();
        }
      },
      revisionRange);

  dispatchBatch();
  threadPool_.waitAll();

  auto endTime = std::chrono::steady_clock::now();
  stats.scanDurationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
  stats.totalCommits = uniqueCommits.size();
  stats.totalFiles = uniqueFiles.size();
  stats.totalFindings = findings_.size();

  return stats;
}

ScanStats Scanner::scanDirectory(const std::filesystem::path& dirPath) {
  clearFindings();
  ScanStats stats;
  auto startTime = std::chrono::steady_clock::now();

  std::unordered_set<std::string> uniqueFiles;

  struct LineItem {
    std::string line;
    std::string file;
    size_t lineNum;
  };

  std::vector<LineItem> batch;
  batch.reserve(2000);

  auto dispatchBatch = [this, &batch]() {
    if (batch.empty()) return;
    auto currentBatch = std::move(batch);
    batch.clear();
    batch.reserve(2000);

    threadPool_.enqueue([this, items = std::move(currentBatch)]() {
      std::vector<SecretFinding> localFindings;
      localFindings.reserve(16);
      for (const auto& item : items) {
        ruleEngine_.scanLine(item.line, item.file, item.lineNum, "", "", "", localFindings);
      }
      if (!localFindings.empty()) {
        addFindings(std::move(localFindings));
      }
    });
  };

  DirectoryWalker::walkDirectory(dirPath, [&](const FileLine& fl) {
    stats.totalLines++;
    uniqueFiles.insert(fl.filePath);

    batch.push_back({fl.line, fl.filePath, fl.lineNumber});
    if (batch.size() >= 2000) {
      dispatchBatch();
    }
  });

  dispatchBatch();
  threadPool_.waitAll();

  auto endTime = std::chrono::steady_clock::now();
  stats.scanDurationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
  stats.totalFiles = uniqueFiles.size();
  stats.totalFindings = findings_.size();

  return stats;
}

ScanStats Scanner::scanFile(const std::filesystem::path& filePath) {
  clearFindings();
  ScanStats stats;
  auto startTime = std::chrono::steady_clock::now();

  std::vector<SecretFinding> localFindings;
  DirectoryWalker::walkFile(filePath, [&](const FileLine& fl) {
    stats.totalLines++;
    ruleEngine_.scanLine(fl.line, fl.filePath, fl.lineNumber, "", "", "", localFindings);
  });

  addFindings(std::move(localFindings));

  auto endTime = std::chrono::steady_clock::now();
  stats.scanDurationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
  stats.totalFiles = 1;
  stats.totalFindings = findings_.size();

  return stats;
}

ScanStats Scanner::scanStream(std::istream& is, const std::string& streamName) {
  clearFindings();
  ScanStats stats;
  auto startTime = std::chrono::steady_clock::now();

  std::string line;
  size_t lineNum = 1;
  std::vector<SecretFinding> localFindings;

  while (std::getline(is, line)) {
    stats.totalLines++;
    ruleEngine_.scanLine(line, streamName, lineNum++, "", "", "", localFindings);
  }

  addFindings(std::move(localFindings));

  auto endTime = std::chrono::steady_clock::now();
  stats.scanDurationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
  stats.totalFiles = 1;
  stats.totalFindings = findings_.size();

  return stats;
}

}  // namespace scanner
