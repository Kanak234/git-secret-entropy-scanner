#include <cassert>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "scanner/DirectoryWalker.hpp"
#include "scanner/EntropyCalculator.hpp"
#include "scanner/FalsePositiveFilter.hpp"
#include "scanner/GitLogParser.hpp"
#include "scanner/Reporter.hpp"
#include "scanner/RuleEngine.hpp"
#include "scanner/Scanner.hpp"
#include "scanner/ThreadPool.hpp"

namespace {

void testEntropyCalculatorEdgeCases() {
  using scanner::CharSetType;
  using scanner::EntropyCalculator;

  assert(std::abs(EntropyCalculator::calculateShannonEntropy("") - 0.0) < 1e-9);
  assert(std::abs(EntropyCalculator::calculateShannonEntropy("z") - 0.0) < 1e-9);

  assert(EntropyCalculator::detectCharSet("abcdef0123456789") == CharSetType::Hex);
  assert(EntropyCalculator::detectCharSet("ABCDEF0123456789") == CharSetType::Hex);
  assert(EntropyCalculator::detectCharSet("ABCDEF0123456789+/==") == CharSetType::Base64);
  assert(EntropyCalculator::detectCharSet("Hello World! Special characters @#$%") ==
         CharSetType::Generic);
  assert(EntropyCalculator::detectCharSet("") == CharSetType::Generic);

  assert(EntropyCalculator::isHighEntropy("0123456789abcdef0123456789abcdef", 3.0, 4.5));
  assert(!EntropyCalculator::isHighEntropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 3.0, 4.5));
  assert(!EntropyCalculator::isHighEntropy("short", 3.0, 4.5));

  std::cout << "testEntropyCalculatorEdgeCases: PASSED\n";
}

void testFalsePositiveFilterEdgeCases() {
  using scanner::FalsePositiveFilter;

  assert(FalsePositiveFilter::isUUID("c56a4180-65aa-42ec-a945-5fd21dec0538"));
  assert(FalsePositiveFilter::isUUID("C56A4180-65AA-42EC-A945-5FD21DEC0538"));
  assert(!FalsePositiveFilter::isUUID(""));
  assert(!FalsePositiveFilter::isUUID("c56a418065aaa9455fd21dec0538"));
  assert(!FalsePositiveFilter::isUUID("c56a4180-65aa-42ec-a945-5fd21dec053g"));

  assert(FalsePositiveFilter::isCommitHash("0123456789abcdef0123456789abcdef01234567"));
  assert(FalsePositiveFilter::isCommitHash(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
  assert(!FalsePositiveFilter::isCommitHash(""));
  assert(!FalsePositiveFilter::isCommitHash("0123456789abcdef"));
  assert(!FalsePositiveFilter::isCommitHash("0123456789abcdef0123456789abcdef0123456g"));

  assert(FalsePositiveFilter::isPlaceholder("YOUR_API_KEY_HERE"));
  assert(FalsePositiveFilter::isPlaceholder("my_fake_secret_token"));
  assert(FalsePositiveFilter::isPlaceholder("placeholder_password"));
  assert(FalsePositiveFilter::isPlaceholder("sample_test123_value"));
  assert(!FalsePositiveFilter::isPlaceholder("prod_real_token_1938491823"));

  assert(FalsePositiveFilter::isLowDiversity(""));
  assert(FalsePositiveFilter::isLowDiversity("abc"));
  assert(FalsePositiveFilter::isLowDiversity("aaaaabbbbb"));
  assert(!FalsePositiveFilter::isLowDiversity("abcdefghij1234567890"));

  assert(FalsePositiveFilter::isIgnoredPath("bundle.min.js"));
  assert(FalsePositiveFilter::isIgnoredPath("styles.min.css"));
  assert(FalsePositiveFilter::isIgnoredPath("app.js.map"));
  assert(FalsePositiveFilter::isIgnoredPath("app.lock"));
  assert(FalsePositiveFilter::isIgnoredPath("package-lock.json"));
  assert(FalsePositiveFilter::isIgnoredPath("yarn.lock"));
  assert(FalsePositiveFilter::isIgnoredPath("Cargo.lock"));
  assert(FalsePositiveFilter::isIgnoredPath("go.sum"));
  assert(FalsePositiveFilter::isIgnoredPath("composer.lock"));
  assert(FalsePositiveFilter::isIgnoredPath("test.png"));
  assert(FalsePositiveFilter::isIgnoredPath("photo.jpg"));
  assert(FalsePositiveFilter::isIgnoredPath("libfoo.so"));
  assert(FalsePositiveFilter::isIgnoredPath("object.o"));
  assert(FalsePositiveFilter::isIgnoredPath("binary.dat"));
  assert(!FalsePositiveFilter::isIgnoredPath("src/backend/auth.cpp"));

  std::cout << "testFalsePositiveFilterEdgeCases: PASSED\n";
}

void testRuleEngineEdgeCases() {
  using scanner::RuleEngine;
  using scanner::SecretFinding;

  assert(RuleEngine::maskSecret("") == "******");
  assert(RuleEngine::maskSecret("a") == "******");
  assert(RuleEngine::maskSecret("123456") == "******");
  assert(RuleEngine::maskSecret("12345678") == "1****8");
  assert(RuleEngine::maskSecret("1234567890123456") == "1234****...****3456");

  RuleEngine engine;
  std::vector<SecretFinding> findings;

  std::string slackToken = std::string("xo") + "xb-234567890123-345678901234-fedcba654321";
  engine.scanLine("token: " + slackToken, "slack.conf", 10, "c1", "author", "date", findings);
  assert(!findings.empty());
  assert(findings.back().ruleId == "SLACK_TOKEN");

  std::string stripeKey = std::string("sk") + "_live_9876543210fedcba98765432";
  engine.scanLine("stripe = '" + stripeKey + "'", "billing.py", 20, "c2", "author", "date",
                  findings);
  assert(!findings.empty());
  assert(findings.back().ruleId == "STRIPE_KEY");

  engine.scanLine("-----BEGIN RSA PRIVATE KEY-----", "id_rsa", 1, "c3", "author", "date", findings);
  assert(!findings.empty());
  assert(findings.back().ruleId == "PEM_PRIVATE_KEY");

  size_t beforeCount = findings.size();
  std::string awsKey = std::string("AK") + "IA1111111111111111";
  engine.scanLine("key = " + awsKey, "tests/test_mock.py", 5, "", "", "", findings);
  assert(findings.size() == beforeCount);
  (void)beforeCount;

  std::cout << "testRuleEngineEdgeCases: PASSED\n";
}

void testDirectoryWalkerEdgeCases() {
  using scanner::DirectoryWalker;
  using scanner::FileLine;

  auto tempDir = std::filesystem::temp_directory_path() / "test_dir_walker_edge";
  std::filesystem::remove_all(tempDir);
  std::filesystem::create_directories(tempDir);

  auto binFile = tempDir / "binary.dat";
  {
    std::ofstream ofs(binFile, std::ios::binary);
    char buf[16] = {'H', 'e', 'l', 'l', 'o', '\0', 'W', 'o', 'r', 'l', 'd', '\0'};
    ofs.write(buf, sizeof(buf));
  }
  assert(DirectoryWalker::isBinaryFile(binFile));
  assert(DirectoryWalker::isBinaryFile(tempDir / "does_not_exist.bin"));

  auto txtFile = tempDir / "text.txt";
  {
    std::ofstream ofs(txtFile);
    ofs << "Line 1\nLine 2\nLine 3\n";
  }
  assert(!DirectoryWalker::isBinaryFile(txtFile));

  std::vector<FileLine> lines;
  DirectoryWalker::walkFile(txtFile, [&](const FileLine& fl) { lines.push_back(fl); });
  assert(lines.size() == 3);
  assert(lines[0].line == "Line 1");
  assert(lines[1].line == "Line 2");
  assert(lines[2].line == "Line 3");

  lines.clear();
  DirectoryWalker::walkFile(binFile, [&](const FileLine& fl) { lines.push_back(fl); });
  assert(lines.empty());

  lines.clear();
  DirectoryWalker::walkFile(tempDir / "missing.txt",
                            [&](const FileLine& fl) { lines.push_back(fl); });
  assert(lines.empty());

  auto gitSubdir = tempDir / ".git";
  std::filesystem::create_directories(gitSubdir);
  {
    std::ofstream ofs(gitSubdir / "config");
    ofs << "git config\n";
  }

  lines.clear();
  DirectoryWalker::walkDirectory(tempDir, [&](const FileLine& fl) { lines.push_back(fl); });
  assert(lines.size() == 3);

  lines.clear();
  DirectoryWalker::walkDirectory(tempDir / "non_existent_dir",
                                 [&](const FileLine& fl) { lines.push_back(fl); });
  assert(lines.empty());

  std::filesystem::remove_all(tempDir);
  std::cout << "testDirectoryWalkerEdgeCases: PASSED\n";
}

void testReporterEdgeCases() {
  using scanner::Reporter;
  using scanner::ScanStats;
  using scanner::SecretFinding;

  ScanStats emptyStats;
  emptyStats.totalLines = 100;
  emptyStats.totalFiles = 2;
  emptyStats.scanDurationMs = 12.5;
  std::ostringstream ssEmpty;
  Reporter::printConsoleReport({}, emptyStats, ssEmpty);
  assert(ssEmpty.str().find("ZERO SECRETS DETECTED") != std::string::npos);

  SecretFinding f1;
  f1.ruleId = "AWS_ACCESS_KEY";
  f1.description = "AWS Access Key ID";
  f1.filePath = "config/creds.py";
  f1.lineNumber = 42;
  f1.commitHash = "abcdef0123456789";
  f1.commitAuthor = "Dev Person";
  f1.commitDate = "2026-09-11 12:00:00";
  f1.matchedText = "AKIA1111111111111111";
  f1.maskedText = "AKIA****...****1111";
  f1.entropy = 3.5;
  f1.lineContent = "aws_secret = 'AKIA1111111111111111'";

  SecretFinding f2;
  f2.ruleId = "GENERIC_SECRET";
  f2.description = "Generic High Entropy String";
  f2.filePath = "app.py";
  f2.lineNumber = 5;
  f2.matchedText = "a1b2c3d4e5f6g7h8";
  f2.maskedText = "a1b2****...****g7h8";
  f2.entropy = 3.8;
  f2.lineContent = "token = 'a1b2c3d4e5f6g7h8'";

  std::vector<SecretFinding> findings = {f1, f2};
  ScanStats stats;
  stats.totalLines = 500;
  stats.totalFiles = 10;
  stats.totalCommits = 3;
  stats.totalFindings = 2;
  stats.scanDurationMs = 45.0;

  std::ostringstream ssReport;
  Reporter::printConsoleReport(findings, stats, ssReport);
  std::string reportOut = ssReport.str();
  assert(reportOut.find("POTENTIAL SECRET(S) DETECTED") != std::string::npos);
  assert(reportOut.find("AWS_ACCESS_KEY") != std::string::npos);
  assert(reportOut.find("Dev Person") != std::string::npos);

  auto tempJson = std::filesystem::temp_directory_path() / "test_reporter_export.json";
  Reporter::exportJsonFile(findings, stats, tempJson);
  assert(std::filesystem::exists(tempJson));

  std::ifstream jf(tempJson);
  std::stringstream jsb;
  jsb << jf.rdbuf();
  std::string jsonStr = jsb.str();
  assert(jsonStr.find("\"findings\": [") != std::string::npos);
  assert(jsonStr.find("\"AWS_ACCESS_KEY\"") != std::string::npos);
  assert(jsonStr.find("\"stats\": {") != std::string::npos);

  std::filesystem::remove(tempJson);
  std::cout << "testReporterEdgeCases: PASSED\n";
}

void testScannerAndStreamEdgeCases() {
  using scanner::Scanner;

  Scanner sc(2);
  assert(sc.findings().empty());

  std::string testAws = std::string("AK") + "IA9876543210ZYXWVU";
  std::string sample = "header line\naws_key = " + testAws + "\nfooter line\n";
  std::istringstream iss(sample);
  auto stats = sc.scanStream(iss, "stream_test.txt");
  assert(stats.totalLines == 3);
  assert(stats.totalFindings >= 1);
  assert(sc.findings().size() >= 1);

  // Scan Directory
  auto tempDir = std::filesystem::temp_directory_path() / "test_scanner_dir_scan";
  std::filesystem::remove_all(tempDir);
  std::filesystem::create_directories(tempDir);
  {
    std::ofstream ofs(tempDir / "sample.py");
    ofs << "header line\naws_key = " << testAws << "\nfooter line\n";
  }
  auto dirStats = sc.scanDirectory(tempDir);
  assert(dirStats.totalFiles == 1);
  assert(dirStats.totalFindings >= 1);
  std::filesystem::remove_all(tempDir);

  // Scan single valid file
  auto tempFile = std::filesystem::temp_directory_path() / "test_scanner_single_file.py";
  {
    std::ofstream ofs(tempFile);
    ofs << "key = " << testAws << "\n";
  }
  auto fileStats = sc.scanFile(tempFile);
  assert(fileStats.totalFiles == 1);
  assert(fileStats.totalFindings >= 1);
  std::filesystem::remove(tempFile);

  auto missingStats = sc.scanFile("/non_existent_file_path_12345.py");
  assert(missingStats.totalLines == 0);
  assert(missingStats.totalFindings == 0);

  bool caught = false;
  try {
    sc.scanGitRepository("/path/with;injection/attempt");
  } catch (const std::invalid_argument&) {
    caught = true;
  }
  assert(caught);
  (void)stats;
  (void)dirStats;
  (void)fileStats;
  (void)missingStats;
  (void)caught;

  std::cout << "testScannerAndStreamEdgeCases: PASSED\n";
}

void testGitLogParserEdgeCases() {
  using scanner::DiffLine;
  using scanner::GitLogParser;

  GitLogParser parser;
  std::vector<DiffLine> diffs;

  std::string diffStream =
      "commit 1234567890abcdef (HEAD -> main)\n"
      "Author: Alice <alice@example.com>\n"
      "Date:   2026-09-11 10:00:00 +0000\n"
      "\n"
      "diff --git a/test.py b/test.py\n"
      "--- a/test.py\n"
      "+++ b/test.py\n"
      "@@ -1,3 +1,4 @@\n"
      " unmodified context line\n"
      "+added line 1\n"
      "-deleted line\n"
      "+added line 2\n\r\n";

  std::istringstream iss(diffStream);
  parser.parseStream(iss, [&](const DiffLine& dl) { diffs.push_back(dl); });

  assert(diffs.size() == 2);
  assert(diffs[0].line == "added line 1");
  assert(diffs[0].commitHash == "1234567890abcdef");
  assert(diffs[0].author == "Alice <alice@example.com>");
  assert(diffs[1].line == "added line 2");

  bool caught = false;
  try {
    std::filesystem::path cur = std::filesystem::current_path();
    GitLogParser::parseRepository(cur, [](const DiffLine&) {}, "HEAD; rm -rf /");
  } catch (const std::invalid_argument&) {
    caught = true;
  }
  assert(caught);
  (void)caught;

  std::cout << "testGitLogParserEdgeCases: PASSED\n";
}

void testThreadPoolEdgeCases() {
  using scanner::ThreadPool;

  ThreadPool pool(4);
  std::atomic<int> counter{0};

  for (int i = 0; i < 100; ++i) {
    pool.enqueue([&counter]() { counter.fetch_add(1); });
  }

  pool.waitAll();
  assert(counter.load() == 100);

  std::cout << "testThreadPoolEdgeCases: PASSED\n";
}

}  // namespace

int main() {
  testEntropyCalculatorEdgeCases();
  testFalsePositiveFilterEdgeCases();
  testRuleEngineEdgeCases();
  testDirectoryWalkerEdgeCases();
  testReporterEdgeCases();
  testScannerAndStreamEdgeCases();
  testGitLogParserEdgeCases();
  testThreadPoolEdgeCases();

  std::cout << "\n>>> ALL COVERAGE EDGE-CASE TESTS PASSED SUCCESSFULLY! <<<\n";
  return 0;
}
