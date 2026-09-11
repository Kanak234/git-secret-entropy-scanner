#include <cassert>
#include <iostream>
#include <vector>

#include "scanner/FalsePositiveFilter.hpp"
#include "scanner/RuleEngine.hpp"

void testSuppressionFilters() {
  using scanner::FalsePositiveFilter;

  // 1. UUID suppression
  assert(FalsePositiveFilter::isUUID("123e4567-e89b-12d3-a456-426614174000"));
  assert(!FalsePositiveFilter::isUUID("NOT_A_UUID_IDENTIFIER_STRING_1234"));

  // 2. Commit Hash suppression
  assert(FalsePositiveFilter::isCommitHash("e0a81d45c6b908f1b67280e2f5b4a9234125b6a7"));
  assert(FalsePositiveFilter::isCommitHash(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
  assert(!FalsePositiveFilter::isCommitHash("not_a_hex_hash_at_all_12345"));

  // 3. Placeholder keywords
  assert(FalsePositiveFilter::isPlaceholder("my_dummy_secret_token_12345"));
  assert(FalsePositiveFilter::isPlaceholder("EXAMPLE_API_KEY_VALUE_HERE"));
  assert(!FalsePositiveFilter::isPlaceholder("real_secret_token_q8w9e0r1t2"));

  // 4. Low diversity
  assert(FalsePositiveFilter::isLowDiversity("aaaaaaaaaaaaaaaaaaaa"));
  assert(!FalsePositiveFilter::isLowDiversity("a1B2c3D4e5F6g7H8i9J0"));

  // 5. Ignored path
  assert(FalsePositiveFilter::isIgnoredPath("package-lock.json"));
  assert(FalsePositiveFilter::isIgnoredPath("bundle.min.js"));
  assert(!FalsePositiveFilter::isIgnoredPath("config/production.env"));

  std::cout << "testSuppressionFilters: PASSED\n";
}

void testNoFalsePositivesInRuleEngine() {
  scanner::RuleEngine engine;
  std::vector<scanner::SecretFinding> findings;

  // UUID in a JSON response
  engine.scanLine("{\"requestId\": \"123e4567-e89b-12d3-a456-426614174000\"}", "response.json", 1,
                  "", "", "", findings);
  assert(findings.empty());

  // Commit hash in a script
  engine.scanLine("PREV_COMMIT=e0a81d45c6b908f1b67280e2f5b4a9234125b6a7", "deploy.sh", 4, "", "",
                  "", findings);
  assert(findings.empty());

  // Placeholder in documentation
  engine.scanLine("apiKey = 'YOUR_API_KEY_HERE'", "README.md", 15, "", "", "", findings);
  assert(findings.empty());

  std::cout << "testNoFalsePositivesInRuleEngine: PASSED\n";
}

int main() {
  testSuppressionFilters();
  testNoFalsePositivesInRuleEngine();
  std::cout << "All false positive tests passed successfully.\n";
  return 0;
}
