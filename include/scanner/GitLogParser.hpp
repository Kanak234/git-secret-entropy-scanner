#pragma once

#include "scanner/SecretFinding.hpp"
#include <filesystem>
#include <functional>
#include <istream>
#include <string>
#include <string_view>

namespace scanner {

struct DiffLine {
  std::string line;
  std::string filePath;
  size_t lineNumber{0};
  std::string commitHash;
  std::string author;
  std::string date;
};

class GitLogParser {
public:
  using LineCallback = std::function<void(const DiffLine &)>;

  GitLogParser() = default;

  /**
   * Parses a single line from a git log -p stream, updating internal parser
   * state.
   */
  void parseLine(std::string_view line, const LineCallback &callback);

  /**
   * Parses a full stream from an istream.
   */
  void parseStream(std::istream &is, const LineCallback &callback);

  /**
   * Runs git log -p on a repository directory and parses diff output.
   */
  static void parseRepository(const std::filesystem::path &repoPath,
                              const LineCallback &callback,
                              const std::string &revisionRange = "HEAD");

private:
  std::string currentCommit_;
  std::string currentAuthor_;
  std::string currentDate_;
  std::string currentFile_;
  size_t currentLineNum_{0};
};

} // namespace scanner
