#pragma once

#include "scanner/SecretFinding.hpp"
#include <filesystem>
#include <iostream>
#include <span>

namespace scanner {

class Reporter {
public:
  static void printConsoleReport(std::span<const SecretFinding> findings,
                                 const ScanStats &stats,
                                 std::ostream &os = std::cout);

  static void exportJsonReport(std::span<const SecretFinding> findings,
                               const ScanStats &stats,
                               std::ostream &os = std::cout);

  static void exportJsonFile(std::span<const SecretFinding> findings,
                             const ScanStats &stats,
                             const std::filesystem::path &outPath);
};

} // namespace scanner
