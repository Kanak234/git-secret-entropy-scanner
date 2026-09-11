#include <cassert>
#include <iostream>
#include <vector>

#include "scanner/RuleEngine.hpp"

void testMasking() {
  assert(scanner::RuleEngine::maskSecret("short") == "******");
  assert(scanner::RuleEngine::maskSecret("12345678") == "1****8");

  std::string key = std::string("AK") + "IAIOSFODNN7EXAMPLE";
  std::string masked = scanner::RuleEngine::maskSecret(key);
  assert(masked == "AKIA****...****MPLE");

  std::cout << "testMasking: PASSED\n";
}

void testVendorSignatures() {
  scanner::RuleEngine engine;
  std::vector<scanner::SecretFinding> findings;

  // 1. AWS Access Key
  std::string awsToken = std::string("AK") + "IA1234567890ABCDEF";
  engine.scanLine("aws_key = " + awsToken, "config.py", 10, "c1", "Alice", "2026-01-01", findings);
  assert(!findings.empty());
  assert(findings.back().ruleId == "AWS_ACCESS_KEY");
  assert(findings.back().matchedText == awsToken);

  // 2. GitHub PAT
  std::string ghpToken = std::string("gh") + "p_1234567890abcdefghijklmnopqrstuvwxyz";
  engine.scanLine("GITHUB_TOKEN=" + ghpToken, ".env", 5, "c2", "Bob", "2026-01-02", findings);
  assert(findings.back().ruleId == "GITHUB_PAT");

  // 3. Slack Token
  std::string slackToken = std::string("xo") + "xb-123456789012-123456789012-abcdef123456";
  engine.scanLine("slack_token = \"" + slackToken + "\"", "bot.go", 12, "c3", "Carol", "2026-01-03",
                  findings);
  assert(findings.back().ruleId == "SLACK_TOKEN");

  // 4. Stripe Key (Constructed dynamically to prevent GitHub push protection triggers)
  std::string stripeToken = std::string("sk_") + "live_" + "1234567890abcdef12345678";
  engine.scanLine("stripe.api_key = '" + stripeToken + "'", "stripe.js", 8, "c4", "Dave",
                  "2026-01-04", findings);
  assert(findings.back().ruleId == "STRIPE_KEY");

  // 5. Google API Key
  std::string gcpToken = std::string("AI") + "zaSyD-123456789012345678901234567890";
  engine.scanLine("const GOOGLE_KEY = \"" + gcpToken + "\";", "app.ts", 4, "c5", "Eve",
                  "2026-01-05", findings);
  assert(findings.back().ruleId == "GOOGLE_API_KEY");

  // 6. PEM Private Key
  std::string pemHeader = std::string("-----BEGIN ") + "RSA PRIVATE KEY-----";
  engine.scanLine(pemHeader, "id_rsa", 1, "c6", "Frank", "2026-01-06", findings);
  assert(findings.back().ruleId == "PEM_PRIVATE_KEY");

  // 7. JWT Token
  std::string jwtToken = std::string("eyJ") +
                         "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                         "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozS6w_XYZ";
  engine.scanLine("Authorization: Bearer " + jwtToken, "req.http", 2, "c7", "Grace", "2026-01-07",
                  findings);
  assert(findings.back().ruleId == "JWT_TOKEN");

  std::cout << "testVendorSignatures: PASSED (7/7 signatures detected)\n";
}

int main() {
  testMasking();
  testVendorSignatures();
  std::cout << "All rule tests passed successfully.\n";
  return 0;
}
