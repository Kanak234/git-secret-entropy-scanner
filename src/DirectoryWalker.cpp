#include "scanner/DirectoryWalker.hpp"

#include <fstream>
#include <vector>

namespace scanner {

bool DirectoryWalker::isBinaryFile(const std::filesystem::path& path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) return true;

  char buf[1024];
  ifs.read(buf, sizeof(buf));
  std::streamsize bytesRead = ifs.gcount();

  for (std::streamsize i = 0; i < bytesRead; ++i) {
    if (buf[i] == '\0') {
      return true;
    }
  }
  return false;
}

void DirectoryWalker::walkFile(const std::filesystem::path& filePath,
                               const LineCallback& callback) {
  if (isBinaryFile(filePath)) return;

  std::ifstream ifs(filePath);
  if (!ifs) return;

  std::string line;
  size_t lineNum = 1;
  std::string pathStr = filePath.string();

  while (std::getline(ifs, line)) {
    FileLine fl;
    fl.line = line;
    fl.filePath = pathStr;
    fl.lineNumber = lineNum++;
    callback(fl);
  }
}

void DirectoryWalker::walkDirectory(const std::filesystem::path& rootPath,
                                    const LineCallback& callback) {
  if (!std::filesystem::exists(rootPath)) return;

  if (!std::filesystem::is_directory(rootPath)) {
    walkFile(rootPath, callback);
    return;
  }

  static constexpr std::string_view ignoredDirs[] = {
      ".git", "node_modules", "build", "dist", "bin", ".idea", ".vscode", "target", "__pycache__"};

  for (const auto& entry : std::filesystem::recursive_directory_iterator(
           rootPath, std::filesystem::directory_options::skip_permission_denied)) {
    if (entry.is_directory()) {
      std::string dirName = entry.path().filename().string();
      for (std::string_view ign : ignoredDirs) {
        if (dirName == ign) {
          // Skip directory
          break;
        }
      }
      continue;
    }

    if (entry.is_regular_file()) {
      std::string pathStr = entry.path().string();
      bool shouldSkip = false;
      for (std::string_view ign : ignoredDirs) {
        if (pathStr.find("/" + std::string(ign) + "/") != std::string::npos) {
          shouldSkip = true;
          break;
        }
      }
      if (!shouldSkip) {
        walkFile(entry.path(), callback);
      }
    }
  }
}

}  // namespace scanner
