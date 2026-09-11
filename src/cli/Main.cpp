#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "scanner/Reporter.hpp"
#include "scanner/Scanner.hpp"

namespace {

void printUsage() {
  std::cout << "========================================================================\n";
  std::cout << " Git Secret Entropy Scanner (C++20)\n";
  std::cout << " High-Throughput Credential Auditor & Shannon Entropy Detector\n";
  std::cout << "========================================================================\n";
  std::cout << "Usage: secret_scanner_cli <command> [options]\n\n";
  std::cout << "Commands:\n";
  std::cout
      << "  scan-git  [repoPath=.] [rev=HEAD] [-o out.json]   Audit Git commit history diffs\n";
  std::cout << "  scan-dir  [dirPath=.] [-o out.json]               Audit working directory tree\n";
  std::cout << "  scan-file <filePath> [-o out.json]                Audit single source file\n";
  std::cout
      << "  bench     [lines=1000000]                         Benchmark scanning throughput\n";
  std::cout << "========================================================================\n";
}

int cmdScanGit(const std::string& repoPath, const std::string& rev, const std::string& jsonOut) {
  scanner::Scanner scanner;
  auto stats = scanner.scanGitRepository(repoPath, rev);

  scanner::Reporter::printConsoleReport(scanner.findings(), stats);

  if (!jsonOut.empty()) {
    scanner::Reporter::exportJsonFile(scanner.findings(), stats, jsonOut);
    std::cout << "JSON report exported to: " << jsonOut << "\n";
  }

  return scanner.findings().empty() ? 0 : 1;
}

int cmdScanDir(const std::string& dirPath, const std::string& jsonOut) {
  scanner::Scanner scanner;
  auto stats = scanner.scanDirectory(dirPath);

  scanner::Reporter::printConsoleReport(scanner.findings(), stats);

  if (!jsonOut.empty()) {
    scanner::Reporter::exportJsonFile(scanner.findings(), stats, jsonOut);
    std::cout << "JSON report exported to: " << jsonOut << "\n";
  }

  return scanner.findings().empty() ? 0 : 1;
}

int cmdScanFile(const std::string& filePath, const std::string& jsonOut) {
  scanner::Scanner scanner;
  auto stats = scanner.scanFile(filePath);

  scanner::Reporter::printConsoleReport(scanner.findings(), stats);

  if (!jsonOut.empty()) {
    scanner::Reporter::exportJsonFile(scanner.findings(), stats, jsonOut);
    std::cout << "JSON report exported to: " << jsonOut << "\n";
  }

  return scanner.findings().empty() ? 0 : 1;
}

int cmdBench(size_t lineCount) {
  std::cout << "========================================================================\n";
  std::cout << " Running Multi-Threaded Scanner Benchmark (" << lineCount << " lines)...\n";
  std::cout << "========================================================================\n";

  std::string awsToken = std::string("AK") + "IA2V4G9L8P7M6K1N0Q";
  std::string ghpToken = std::string("gh") + "p_K9bL2vP8wX1zQ4mN7tR0sY3uJ6hF5aD2eC8v";

  std::vector<std::string> sampleLines = {
      "import os, sys, json, requests",
      "const requestId = '123e4567-e89b-12d3-a456-426614174000';",
      "git_sha = 'e0a81d45c6b908f1b67280e2f5b4a9234125b6a7';",
      "def compute_hash(data): return hashlib.sha256(data).hexdigest()",
      "AWS_KEY = \"" + awsToken + "\"",
      "GITHUB_TOKEN=" + ghpToken,
      "apiKey = 'dummy_placeholder_key_example'",
      "api_secret = 'd83k29s01mf93ks0129k38sl2019ksad'",
      "// Normal comment line explaining how the algorithm partitions data",
      "for (int i = 0; i < 100; ++i) { array[i] = i * 2; }"};

  scanner::RuleEngine engine;
  scanner::ThreadPool pool;
  std::atomic<size_t> totalDetected{0};

  const size_t chunkSize = 5000;
  const size_t numChunks = (lineCount + chunkSize - 1) / chunkSize;
  const size_t sampleCount = sampleLines.size();

  auto start = std::chrono::steady_clock::now();

  for (size_t chunk = 0; chunk < numChunks; ++chunk) {
    size_t startLine = chunk * chunkSize;
    size_t endLine = std::min(lineCount, startLine + chunkSize);

    pool.enqueue([&engine, &sampleLines, sampleCount, startLine, endLine, &totalDetected] {
      std::vector<scanner::SecretFinding> localFindings;
      localFindings.reserve(16);

      for (size_t i = startLine; i < endLine; ++i) {
        const auto& line = sampleLines[i % sampleCount];
        engine.scanLine(line, "benchmark.cpp", i + 1, "", "", "", localFindings);
      }

      totalDetected += localFindings.size();
    });
  }

  pool.waitAll();
  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<double> elapsed = end - start;

  double linesPerSec = static_cast<double>(lineCount) / elapsed.count();

  std::cout << std::fixed << std::setprecision(2);
  std::cout << "Benchmark Complete:\n";
  std::cout << "  Lines Evaluated:   " << lineCount << "\n";
  std::cout << "  Secrets Detected:  " << totalDetected.load() << "\n";
  std::cout << "  Elapsed Time:      " << (elapsed.count() * 1000.0) << " ms\n";
  std::cout << "  Throughput:        " << linesPerSec << " lines/sec\n";
  std::cout << "========================================================================\n";
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2) {
    printUsage();
    return 1;
  }

  std::string cmd = argv[1];

  if (cmd == "scan-git") {
    std::string repo = (argc >= 3 && argv[2][0] != '-') ? argv[2] : ".";
    std::string rev = "HEAD";
    std::string jsonOut;
    for (int i = 2; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "-o" && i + 1 < argc)
        jsonOut = argv[++i];
      else if (arg != repo && arg[0] != '-')
        rev = arg;
    }
    return cmdScanGit(repo, rev, jsonOut);
  }

  if (cmd == "scan-dir") {
    std::string dir = (argc >= 3 && argv[2][0] != '-') ? argv[2] : ".";
    std::string jsonOut;
    for (int i = 2; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "-o" && i + 1 < argc) jsonOut = argv[++i];
    }
    return cmdScanDir(dir, jsonOut);
  }

  if (cmd == "scan-file" && argc >= 3) {
    std::string file = argv[2];
    std::string jsonOut;
    for (int i = 3; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "-o" && i + 1 < argc) jsonOut = argv[++i];
    }
    return cmdScanFile(file, jsonOut);
  }

  if (cmd == "bench") {
    size_t lines = (argc >= 3) ? static_cast<size_t>(std::stoul(argv[2])) : 1000000;
    return cmdBench(lines);
  }

  printUsage();
  return 1;
}
