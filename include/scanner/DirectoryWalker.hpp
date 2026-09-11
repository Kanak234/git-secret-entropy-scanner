#pragma once

#include <filesystem>
#include <functional>
#include <string>

namespace scanner {

struct FileLine {
  std::string line;
  std::string filePath;
  size_t lineNumber{0};
};

class DirectoryWalker {
 public:
  using LineCallback = std::function<void(const FileLine&)>;

  static void walkDirectory(const std::filesystem::path& rootPath, const LineCallback& callback);

  static void walkFile(const std::filesystem::path& filePath, const LineCallback& callback);

  [[nodiscard]] static bool isBinaryFile(const std::filesystem::path& path);
};

}  // namespace scanner
