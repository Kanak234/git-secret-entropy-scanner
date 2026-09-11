#include "scanner/GitLogParser.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace scanner {

namespace {
struct PipeDeleter {
  void operator()(FILE *fp) const noexcept {
    if (fp) {
      pclose(fp);
    }
  }
};
} // namespace

void GitLogParser::parseLine(std::string_view line,
                             const LineCallback &callback) {
  if (line.starts_with("commit ")) {
    std::string_view rest = line.substr(7);
    size_t spacePos = rest.find(' ');
    if (spacePos != std::string_view::npos) {
      currentCommit_ = std::string(rest.substr(0, spacePos));
    } else {
      currentCommit_ = std::string(rest);
    }
    return;
  }

  if (line.starts_with("Author: ")) {
    currentAuthor_ = std::string(line.substr(8));
    return;
  }

  if (line.starts_with("Date: ")) {
    std::string_view d = line.substr(6);
    while (!d.empty() && d.front() == ' ')
      d.remove_prefix(1);
    currentDate_ = std::string(d);
    return;
  }

  if (line.starts_with("diff --git a/")) {
    size_t bPos = line.find(" b/");
    if (bPos != std::string_view::npos) {
      currentFile_ = std::string(line.substr(bPos + 3));
    }
    currentLineNum_ = 0;
    return;
  }

  if (line.starts_with("+++ b/")) {
    currentFile_ = std::string(line.substr(6));
    return;
  }

  // Hunk header: @@ -a,b +start,count @@
  if (line.starts_with("@@ ")) {
    size_t plusPos = line.find('+');
    if (plusPos != std::string_view::npos) {
      try {
        currentLineNum_ = std::stoul(std::string(line.substr(plusPos + 1)));
      } catch (...) {
        currentLineNum_ = 1;
      }
    }
    return;
  }

  // Added lines in diff: start with '+' but not '+++'
  if (line.starts_with("+") && !line.starts_with("+++")) {
    DiffLine dl;
    dl.line = std::string(line.substr(1));
    dl.filePath = currentFile_;
    dl.lineNumber = currentLineNum_++;
    dl.commitHash = currentCommit_;
    dl.author = currentAuthor_;
    dl.date = currentDate_;

    callback(dl);
    return;
  }

  // Unmodified context lines increment target line number
  if (!line.starts_with("-")) {
    currentLineNum_++;
  }
}

void GitLogParser::parseStream(std::istream &is, const LineCallback &callback) {
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    parseLine(line, callback);
  }
}

void GitLogParser::parseRepository(const std::filesystem::path &repoPath,
                                   const LineCallback &callback,
                                   const std::string &revisionRange) {
  std::string cmd = "git -C \"" + repoPath.string() +
                    "\" log -p --full-history --date=iso " + revisionRange +
                    " 2>/dev/null";

  std::unique_ptr<FILE, PipeDeleter> pipe(popen(cmd.c_str(), "r"));
  if (!pipe) {
    throw std::runtime_error("Failed to execute git log command on: " +
                             repoPath.string());
  }

  GitLogParser parser;
  char *linebuf = nullptr;
  size_t linecap = 0;
  ssize_t linelen = 0;

  while ((linelen = getline(&linebuf, &linecap, pipe.get())) != -1) {
    if (linelen > 0 && linebuf[linelen - 1] == '\n') {
      linebuf[linelen - 1] = '\0';
      linelen--;
    }
    if (linelen > 0 && linebuf[linelen - 1] == '\r') {
      linebuf[linelen - 1] = '\0';
      linelen--;
    }
    parser.parseLine(std::string_view(linebuf, static_cast<size_t>(linelen)),
                     callback);
  }

  if (linebuf) {
    std::free(linebuf);
  }
}

} // namespace scanner
