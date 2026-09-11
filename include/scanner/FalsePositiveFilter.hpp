#pragma once

#include <string_view>

namespace scanner {

class FalsePositiveFilter {
 public:
  [[nodiscard]] static bool isFalsePositive(std::string_view candidate, std::string_view filePath,
                                            std::string_view fullLine) noexcept;

  [[nodiscard]] static bool isUUID(std::string_view text) noexcept;
  [[nodiscard]] static bool isCommitHash(std::string_view text) noexcept;
  [[nodiscard]] static bool isPlaceholder(std::string_view text) noexcept;
  [[nodiscard]] static bool isLowDiversity(std::string_view text) noexcept;
  [[nodiscard]] static bool isIgnoredPath(std::string_view filePath) noexcept;
};

}  // namespace scanner
