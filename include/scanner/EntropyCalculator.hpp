#pragma once

#include <cmath>
#include <cstdint>
#include <string_view>

namespace scanner {

enum class CharSetType {
  Hex,     // [0-9a-fA-F]
  Base64,  // [0-9a-zA-Z+/=_-]
  Generic  // Any printable ASCII
};

class EntropyCalculator {
 public:
  /**
   * Computes the Shannon entropy in bits per character:
   * H = - \sum (count_i / N) * log2(count_i / N)
   */
  [[nodiscard]] static double calculateShannonEntropy(std::string_view text) noexcept;

  /**
   * Identifies character set type (Hex, Base64, Generic).
   */
  [[nodiscard]] static CharSetType detectCharSet(std::string_view text) noexcept;

  /**
   * Checks if a token exceeds entropy thresholds based on its character set.
   * Default thresholds: Hex > 3.0 bits/char (min len 16), Base64 > 4.5
   * bits/char (min len 20).
   */
  [[nodiscard]] static bool isHighEntropy(std::string_view text, double hexThreshold = 3.0,
                                          double base64Threshold = 4.5) noexcept;
};

}  // namespace scanner
