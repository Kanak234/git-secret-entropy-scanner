#include "scanner/Reporter.hpp"
#include <fstream>
#include <iomanip>

namespace scanner {

void Reporter::printConsoleReport(std::span<const SecretFinding> findings,
                                  const ScanStats &stats, std::ostream &os) {
  os << "======================================================================"
        "==\n";
  os << " Git Secret Entropy Scanner Audit Report\n";
  os << "======================================================================"
        "==\n";

  if (findings.empty()) {
    os << "\n  [✓] ZERO SECRETS DETECTED. Repository audit clean.\n\n";
  } else {
    os << "\n  [!] " << findings.size() << " POTENTIAL SECRET(S) DETECTED:\n\n";

    for (size_t i = 0; i < findings.size(); ++i) {
      const auto &f = findings[i];
      os << "  #" << (i + 1) << " [" << f.ruleId << "] " << f.description
         << "\n";
      os << "     File:     " << f.filePath << ":" << f.lineNumber << "\n";
      if (!f.commitHash.empty()) {
        os << "     Commit:   " << f.commitHash.substr(0, 8);
        if (!f.commitAuthor.empty())
          os << " (by " << f.commitAuthor << ")";
        if (!f.commitDate.empty())
          os << " on " << f.commitDate;
        os << "\n";
      }
      os << "     Secret:   " << f.maskedText << "\n";
      os << "     Entropy:  " << std::fixed << std::setprecision(2) << f.entropy
         << " bits/char\n";
      os << "     Line:     " << f.lineContent << "\n\n";
    }
  }

  os << "----------------------------------------------------------------------"
        "--\n";
  os << " Scan Summary:\n";
  os << "  Total Lines Scanned:    " << stats.totalLines << "\n";
  if (stats.totalCommits > 0) {
    os << "  Total Commits Scanned:  " << stats.totalCommits << "\n";
  }
  os << "  Total Files Audited:    " << stats.totalFiles << "\n";
  os << "  Secrets Detected:       " << stats.totalFindings << "\n";
  os << "  Scan Duration:          " << std::fixed << std::setprecision(2)
     << stats.scanDurationMs << " ms\n";

  if (stats.scanDurationMs > 0.0) {
    double linesPerSec = (static_cast<double>(stats.totalLines) /
                          (stats.scanDurationMs / 1000.0));
    os << "  Scanning Throughput:    " << std::fixed << std::setprecision(0)
       << linesPerSec << " lines/sec\n";
  }
  os << "======================================================================"
        "==\n";
}

void Reporter::exportJsonReport(std::span<const SecretFinding> findings,
                                const ScanStats &stats, std::ostream &os) {
  auto escapeJson = [](std::string_view s) {
    std::string res;
    for (char c : s) {
      if (c == '"')
        res += "\\\"";
      else if (c == '\\')
        res += "\\\\";
      else if (c == '\b')
        res += "\\b";
      else if (c == '\f')
        res += "\\f";
      else if (c == '\n')
        res += "\\n";
      else if (c == '\r')
        res += "\\r";
      else if (c == '\t')
        res += "\\t";
      else
        res += c;
    }
    return res;
  };

  os << "{\n";
  os << "  \"stats\": {\n";
  os << "    \"totalLines\": " << stats.totalLines << ",\n";
  os << "    \"totalCommits\": " << stats.totalCommits << ",\n";
  os << "    \"totalFiles\": " << stats.totalFiles << ",\n";
  os << "    \"totalFindings\": " << stats.totalFindings << ",\n";
  os << "    \"scanDurationMs\": " << stats.scanDurationMs << "\n";
  os << "  },\n";

  os << "  \"findings\": [\n";
  for (size_t i = 0; i < findings.size(); ++i) {
    const auto &f = findings[i];
    os << "    {\n";
    os << "      \"ruleId\": \"" << escapeJson(f.ruleId) << "\",\n";
    os << "      \"description\": \"" << escapeJson(f.description) << "\",\n";
    os << "      \"maskedSecret\": \"" << escapeJson(f.maskedText) << "\",\n";
    os << "      \"filePath\": \"" << escapeJson(f.filePath) << "\",\n";
    os << "      \"lineNumber\": " << f.lineNumber << ",\n";
    os << "      \"commitHash\": \"" << escapeJson(f.commitHash) << "\",\n";
    os << "      \"commitAuthor\": \"" << escapeJson(f.commitAuthor) << "\",\n";
    os << "      \"commitDate\": \"" << escapeJson(f.commitDate) << "\",\n";
    os << "      \"entropy\": " << f.entropy << ",\n";
    os << "      \"lineContent\": \"" << escapeJson(f.lineContent) << "\"\n";
    os << "    }" << (i + 1 < findings.size() ? "," : "") << "\n";
  }
  os << "  ]\n";
  os << "}\n";
}

void Reporter::exportJsonFile(std::span<const SecretFinding> findings,
                              const ScanStats &stats,
                              const std::filesystem::path &outPath) {
  std::ofstream ofs(outPath);
  if (ofs) {
    exportJsonReport(findings, stats, ofs);
  }
}

} // namespace scanner
