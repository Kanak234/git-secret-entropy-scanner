#include "scanner/Scanner.hpp"
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>

void testGitHistoryScanning() {
  std::filesystem::path testRepo =
      std::filesystem::temp_directory_path() / "test_git_secret_audit_repo";
  std::filesystem::remove_all(testRepo);
  std::filesystem::create_directories(testRepo);

  // Initialize test git repository
  std::string initCmd = "git -C \"" + testRepo.string() + "\" init >/dev/null 2>&1";
  std::string configCmd = "git -C \"" + testRepo.string() + "\" config user.name \"AuditTest\" && " +
                          "git -C \"" + testRepo.string() + "\" config user.email \"audit@example.com\"";
  int ret1 = std::system(initCmd.c_str());
  int ret2 = std::system(configCmd.c_str());
  (void)ret1;
  (void)ret2;

  // Commit 1: Clean file
  {
    std::ofstream f(testRepo / "app.py");
    f << "def hello():\n    return 'Hello, World!'\n";
  }
  int ret3 = std::system(("git -C \"" + testRepo.string() +
                          "\" add app.py && git -C \"" + testRepo.string() +
                          "\" commit -m \"Initial commit\" >/dev/null 2>&1")
                             .c_str());
  (void)ret3;

  // Commit 2: Leaked AWS Access Key (assembled dynamically)
  std::string testAwsKey = std::string("AK") + "IA9876543210ZYXWVU";
  {
    std::ofstream f(testRepo / "config.py");
    f << "# Leaked credentials\nAWS_KEY = \"" << testAwsKey << "\"\n";
  }
  int ret4 = std::system(("git -C \"" + testRepo.string() +
                          "\" add config.py && git -C \"" + testRepo.string() +
                          "\" commit -m \"Add aws config\" >/dev/null 2>&1")
                             .c_str());
  (void)ret4;

  // Commit 3: Leaked GitHub PAT (assembled dynamically)
  std::string testGhpKey = std::string("gh") + "p_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
  {
    std::ofstream f(testRepo / ".env");
    f << "GITHUB_TOKEN=" << testGhpKey << "\n";
  }
  int ret5 = std::system(("git -C \"" + testRepo.string() +
                          "\" add .env && git -C \"" + testRepo.string() +
                          "\" commit -m \"Add github token\" >/dev/null 2>&1")
                             .c_str());
  (void)ret5;

  // Commit 4: "Fix" - delete .env and remove AWS_KEY from config.py
  {
    std::ofstream f(testRepo / "config.py");
    f << "# Fixed credentials\nAWS_KEY = os.getenv('AWS_KEY')\n";
  }
  int ret6 = std::system(
      ("git -C \"" + testRepo.string() +
       "\" rm .env >/dev/null 2>&1 && git -C \"" + testRepo.string() +
       "\" add config.py && git -C \"" + testRepo.string() +
       "\" commit -m \"Remove secrets from tree\" >/dev/null 2>&1")
          .c_str());
  (void)ret6;

  // Now run Scanner on git history!
  scanner::Scanner scanner(4);
  auto stats = scanner.scanGitRepository(testRepo);

  std::cout << "Git History Scan Results:\n";
  std::cout << "  Commits Scanned:  " << stats.totalCommits << "\n";
  std::cout << "  Lines Scanned:    " << stats.totalLines << "\n";
  std::cout << "  Secrets Detected: " << stats.totalFindings << "\n";

  bool foundAws = false;
  bool foundGhp = false;

  for (const auto& finding : scanner.findings()) {
    std::cout << "  -> Found: [" << finding.ruleId << "] in "
              << finding.filePath
              << " (Commit " << finding.commitHash.substr(0, 8)
              << "): " << finding.maskedText << "\n";
    if (finding.ruleId == "AWS_ACCESS_KEY" && finding.matchedText == testAwsKey) {
      foundAws = true;
    }
    if (finding.ruleId == "GITHUB_PAT" && finding.matchedText == testGhpKey) {
      foundGhp = true;
    }
  }

  assert(foundAws);
  assert(foundGhp);
  assert(stats.totalFindings >= 2);
  (void)foundAws;
  (void)foundGhp;

  // Clean up
  std::filesystem::remove_all(testRepo);
  std::cout << "testGitHistoryScanning: PASSED\n";
}

int main() {
  testGitHistoryScanning();
  return 0;
}
