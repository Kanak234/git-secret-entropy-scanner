#include "scanner/EntropyCalculator.hpp"

#include <array>
#include <cctype>

namespace scanner {

double EntropyCalculator::calculateShannonEntropy(std::string_view text) noexcept {
  if (text.empty()) return 0.0;

  std::array<uint32_t, 256> counts{};
  for (char c : text) {
    counts[static_cast<unsigned char>(c)]++;
  }

  const double n = static_cast<double>(text.size());
  double entropy = 0.0;

  for (uint32_t count : counts) {
    if (count > 0) {
      double p = static_cast<double>(count) / n;
      entropy -= p * std::log2(p);
    }
  }

  return entropy;
}

CharSetType EntropyCalculator::detectCharSet(std::string_view text) noexcept {
  if (text.empty()) return CharSetType::Generic;

  bool allHex = true;
  bool allBase64 = true;

  for (char c : text) {
    bool isHexChar = std::isxdigit(static_cast<unsigned char>(c));
    bool isBase64Char = std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' ||
                        c == '=' || c == '_' || c == '-';

    if (!isHexChar) allHex = false;
    if (!isBase64Char) allBase64 = false;

    if (!allBase64) return CharSetType::Generic;
  }

  if (allHex) return CharSetType::Hex;
  if (allBase64) return CharSetType::Base64;
  return CharSetType::Generic;
}

bool EntropyCalculator::isHighEntropy(std::string_view text, double hexThreshold,
                                      double base64Threshold) noexcept {
  if (text.size() < 16) return false;

  CharSetType type = detectCharSet(text);
  double h = calculateShannonEntropy(text);

  if (type == CharSetType::Hex) {
    return (text.size() >= 16 && h >= hexThreshold);
  } else if (type == CharSetType::Base64) {
    return (text.size() >= 20 && h >= base64Threshold);
  } else {
    // Generic printable alphanumeric
    return (text.size() >= 16 && h >= 4.0);
  }
}

}  // namespace scanner
