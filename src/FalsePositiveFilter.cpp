#include "scanner/FalsePositiveFilter.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <string>

namespace scanner {

bool FalsePositiveFilter::isUUID(std::string_view text) noexcept {
  // 8-4-4-4-12 format: 36 characters
  if (text.size() != 36)
    return false;

  for (size_t i = 0; i < 36; ++i) {
    char c = text[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-')
        return false;
    } else {
      if (!std::isxdigit(static_cast<unsigned char>(c)))
        return false;
    }
  }
  return true;
}

bool FalsePositiveFilter::isCommitHash(std::string_view text) noexcept {
  // 40 chars (SHA-1) or 64 chars (SHA-256)
  if (text.size() != 40 && text.size() != 64)
    return false;

  for (char c : text) {
    if (!std::isxdigit(static_cast<unsigned char>(c)))
      return false;
  }
  return true;
}

bool FalsePositiveFilter::isPlaceholder(std::string_view text) noexcept {
  std::string lower;
  lower.reserve(text.size());
  for (char c : text) {
    lower.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }

  static constexpr std::string_view placeholders[] = {
      "example",    "dummy",   "placeholder", "mock",        "fake", "your_",
      "changeme",   "test123", "secret123",   "password123", "foo",  "bar",
      "0123456789", "abcdef",  "xxxxxx",      "mysecret"};

  for (std::string_view ph : placeholders) {
    if (lower.find(ph) != std::string::npos) {
      return true;
    }
  }

  return false;
}

bool FalsePositiveFilter::isLowDiversity(std::string_view text) noexcept {
  if (text.empty())
    return true;

  std::array<bool, 256> seen{};
  size_t uniqueCount = 0;

  for (char c : text) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (!seen[uc]) {
      seen[uc] = true;
      uniqueCount++;
    }
  }

  // A real cryptographic secret or token has high character variety
  return uniqueCount < 5;
}

bool FalsePositiveFilter::isIgnoredPath(std::string_view filePath) noexcept {
  static constexpr std::string_view ignoredExtensions[] = {
      ".min.js",   ".min.css",   ".map",   ".lock",         "package-lock.json",
      "yarn.lock", "Cargo.lock", "go.sum", "composer.lock", ".png",
      ".jpg",      ".jpeg",      ".gif",   ".ico",          ".svg",
      ".pdf",      ".bin",       ".dat",   ".so",           ".a",
      ".o",        ".pyc"};

  for (std::string_view ext : ignoredExtensions) {
    if (filePath.ends_with(ext)) {
      return true;
    }
  }

  return false;
}

bool FalsePositiveFilter::isFalsePositive(std::string_view candidate,
                                          std::string_view filePath,
                                          std::string_view fullLine) noexcept {
  (void)fullLine;

  if (isIgnoredPath(filePath))
    return true;
  if (isUUID(candidate))
    return true;
  if (isCommitHash(candidate))
    return true;
  if (isPlaceholder(candidate))
    return true;
  if (isLowDiversity(candidate))
    return true;

  return false;
}

} // namespace scanner
