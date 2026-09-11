#include "scanner/GitLogParser.hpp"

#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>

extern "C" char** environ;

namespace scanner {

void GitLogParser::parseLine(std::string_view line, const LineCallback& callback) {
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
    while (!d.empty() && d.front() == ' ') d.remove_prefix(1);
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

void GitLogParser::parseStream(std::istream& is, const LineCallback& callback) {
  std::string line;
  while (std::getline(is, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    parseLine(line, callback);
  }
}

void GitLogParser::parseRepository(const std::filesystem::path& repoPath,
                                   const LineCallback& callback, const std::string& revisionRange) {
  std::string repoStr = repoPath.string();
  if (repoStr.empty() || repoStr.find_first_of(";&|`$\"'\n\r") != std::string::npos) {
    throw std::invalid_argument("Invalid repository path for git inspection");
  }
  if (!std::filesystem::exists(repoPath) || !std::filesystem::is_directory(repoPath)) {
    throw std::invalid_argument("Repository path does not exist or is not a directory: " + repoStr);
  }

  if (!revisionRange.empty()) {
    for (char c : revisionRange) {
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-' && c != '.' &&
          c != '^' && c != '~' && c != '@' && c != '/' && c != ':' && c != ' ') {
        throw std::invalid_argument("Invalid characters in revision range: " + revisionRange);
      }
    }
  }

  int pipefd[2];
  if (pipe(pipefd) != 0) {
    throw std::runtime_error("Failed to create pipe for git execution");
  }

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_addclose(&actions, pipefd[0]);
  posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
  posix_spawn_file_actions_addclose(&actions, pipefd[1]);
  posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

  std::vector<std::string> args = {"git",       "-C", repoStr, "log", "-p", "--full-history",
                                   "--date=iso"};
  if (!revisionRange.empty()) {
    args.push_back(revisionRange);
  }

  std::vector<char*> c_args;
  c_args.reserve(args.size() + 1);
  for (auto& s : args) {
    c_args.push_back(s.data());
  }
  c_args.push_back(nullptr);

  pid_t pid;
  int spawnStatus = posix_spawnp(&pid, "git", &actions, nullptr, c_args.data(), ::environ);
  posix_spawn_file_actions_destroy(&actions);
  close(pipefd[1]);

  if (spawnStatus != 0) {
    close(pipefd[0]);
    throw std::runtime_error("Failed to spawn git process for: " + repoStr);
  }

  FILE* fp = fdopen(pipefd[0], "r");
  if (!fp) {
    close(pipefd[0]);
    waitpid(pid, nullptr, 0);
    throw std::runtime_error("Failed to read git process output for: " + repoStr);
  }

  GitLogParser parser;
  char* linebuf = nullptr;
  size_t linecap = 0;
  ssize_t linelen = 0;

  while ((linelen = getline(&linebuf, &linecap, fp)) != -1) {
    if (linelen > 0 && linebuf[linelen - 1] == '\n') {
      linebuf[linelen - 1] = '\0';
      linelen--;
    }
    if (linelen > 0 && linebuf[linelen - 1] == '\r') {
      linebuf[linelen - 1] = '\0';
      linelen--;
    }
    parser.parseLine(std::string_view(linebuf, static_cast<size_t>(linelen)), callback);
  }

  if (linebuf) {
    std::free(linebuf);
  }

  fclose(fp);
  waitpid(pid, nullptr, 0);
}

}  // namespace scanner
