#include "scanner/EntropyCalculator.hpp"
#include <cassert>
#include <cmath>
#include <iostream>

void testShannonEntropy() {
  // 1. Single repeated character must have zero entropy
  double hZero =
      scanner::EntropyCalculator::calculateShannonEntropy("aaaaaaaaaaaaaaaa");
  assert(std::abs(hZero - 0.0) < 1e-9);
  (void)hZero;

  // 2. 16 distinct characters with uniform distribution: H = log2(16) = 4.0
  double hUniform16 =
      scanner::EntropyCalculator::calculateShannonEntropy("0123456789abcdef");
  assert(std::abs(hUniform16 - 4.0) < 1e-9);
  (void)hUniform16;

  // 3. Two equally distributed characters: H = 1.0
  double hBinary =
      scanner::EntropyCalculator::calculateShannonEntropy("abababababababab");
  assert(std::abs(hBinary - 1.0) < 1e-9);
  (void)hBinary;

  std::cout << "testShannonEntropy: PASSED\n";
}

void testCharSetDetection() {
  using scanner::CharSetType;

  assert(scanner::EntropyCalculator::detectCharSet("0123456789abcdefABCDEF") ==
         CharSetType::Hex);
  assert(scanner::EntropyCalculator::detectCharSet("a1B2+c3/d4==") ==
         CharSetType::Base64);
  assert(scanner::EntropyCalculator::detectCharSet("hello world! @#$") ==
         CharSetType::Generic);

  std::cout << "testCharSetDetection: PASSED\n";
}

void testHighEntropyThresholds() {
  // High-entropy random Base64 string
  std::string highEntropyB64 =
      "dGhpcyBpcyBhIHJhbmRvbSBzZWNyZXQga2V5IDEyMzQ1Njc4OTA=";
  assert(scanner::EntropyCalculator::isHighEntropy(highEntropyB64));

  // Low-entropy repeated Base64
  std::string lowEntropyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  assert(!scanner::EntropyCalculator::isHighEntropy(lowEntropyB64));

  // High-entropy Hex string (e.g. 32-byte random hex)
  std::string highEntropyHex = "4a8b2f9c1e7d0a3b5c6e8f1a2b3c4d5e";
  assert(scanner::EntropyCalculator::isHighEntropy(highEntropyHex));

  std::cout << "testHighEntropyThresholds: PASSED\n";
}

int main() {
  testShannonEntropy();
  testCharSetDetection();
  testHighEntropyThresholds();
  std::cout << "All entropy tests passed successfully.\n";
  return 0;
}
