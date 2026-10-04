/**
 * tests/js/run_parity_test.js
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Verify that the JavaScript engine (frontend/js/engine.js) produces the
 *   same score, classification and finding types as the Python engine, using
 *   tests/fixtures/expected_results.json as the shared source of truth.
 *
 * WHY THIS MATTERS
 *   The GitHub Pages build runs entirely in the browser. If the JS port drifted
 *   from the Python engine, the deployed site would quietly disagree with the
 *   documented backend. This test fails the build when that happens.
 *
 * RUN
 *   node tests/js/run_parity_test.js
 * ---------------------------------------------------------------------------
 */
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..", "..");
const fixturePath = path.join(PROJECT_ROOT, "tests", "fixtures", "expected_results.json");
if (!fs.existsSync(fixturePath)) {
  console.error("Fixture file missing. Run: python scripts/generate_fixtures.py");
  process.exit(2);
}

global.window = global.window || {};
["common_passwords", "keyboard_patterns", "common_phrases", "passphrase_words"].forEach((name) => {
  require(path.join(PROJECT_ROOT, "frontend", "js", "data", name + ".js"));
});
const engine = require(path.join(PROJECT_ROOT, "frontend", "js", "engine.js"));

const fixtures = JSON.parse(fs.readFileSync(fixturePath, "utf8")).fixtures;
let passed = 0;
const failures = [];

fixtures.forEach((fixture) => {
  const result = engine.analyzePassword(fixture.password, { context: fixture.context });
  const problems = [];
  if (result.score !== fixture.score) problems.push(`score ${result.score} != ${fixture.score}`);
  if (result.classification !== fixture.classification) {
    problems.push(`classification ${result.classification} != ${fixture.classification}`);
  }
  if (result.metrics.length !== fixture.length) problems.push(`length ${result.metrics.length} != ${fixture.length}`);
  if (result.metrics.pattern_count !== fixture.pattern_count) {
    problems.push(`pattern_count ${result.metrics.pattern_count} != ${fixture.pattern_count}`);
  }
  if (result.policy.policy_pass !== fixture.policy_pass) {
    problems.push(`policy_pass ${result.policy.policy_pass} != ${fixture.policy_pass}`);
  }
  const jsTypes = result.findings.map((f) => f.type).sort().join(",");
  const pyTypes = fixture.finding_types.join(",");
  if (jsTypes !== pyTypes) problems.push(`finding types [${jsTypes}] != [${pyTypes}]`);
  // Privacy assertions: every evidence string must be fully masked, and the
  // raw value must not appear anywhere in the serialised result.
  result.findings.forEach((f) => {
    if (f.evidence && !/^[\u2022\s]*$/.test(f.evidence)) {
      problems.push(`unmasked evidence for ${f.type}: ${JSON.stringify(f.evidence)}`);
    }
  });
  // NOTE on the substring check: the static educational text legitimately
  // contains dictionary words such as "password" or "qwerty" (for example the
  // sentence "shapes like qwerty are in every wordlist"). A naive substring
  // test would flag those fixtures even though nothing was derived from the
  // user's input. The unambiguous check therefore uses a high-entropy probe in
  // the extraChecks block below, plus a masked-evidence assertion here.
  result.findings.forEach((f) => {
    if (f.evidence === fixture.password) problems.push("evidence equals the raw password");
  });
  if (problems.length) failures.push({ password: JSON.stringify(fixture.password), problems });
  else passed += 1;
});

const extraChecks = [
  ["empty input yields only the input notice",
   engine.analyzePassword("").findings.every((f) => f.type === "input")],
  ["generated 24-character password is strong",
   ["STRONG", "VERY STRONG"].includes(
     engine.analyzePassword(engine.generatePassword({ length: 24 }).password).classification)],
  ["generated 5-word passphrase is strong",
   ["STRONG", "VERY STRONG"].includes(
     engine.analyzePassword(engine.generatePassphrase({ words: 5 }).password).classification)],
  ["over-length input is rejected gracefully",
   engine.analyzePassword("a".repeat(300)).input_error !== undefined],
  ["evidence strings never contain the password",
   engine.analyzePassword("Demo-Pattern-123!").findings
     .every((f) => f.evidence.indexOf("Demo-Pattern-123!") === -1)],
  ["a high-entropy probe password never appears in its own result",
   (function () {
     const probe = "Zq7#vP2!mL9@Rk4t";
     const result = engine.analyzePassword(probe);
     return JSON.stringify(result).indexOf(probe) === -1;
   })()],
  ["a probe password never appears in generated suggestions",
   (function () {
     const probe = "Qw3$nB8!sT5@yU1k";
     const result = engine.analyzePassword(probe);
     return result.suggestions.every((s) =>
       JSON.stringify(s).indexOf(probe) === -1);
   })()],
  ["generated passwords differ between calls",
   engine.generatePassword({ length: 20 }).password !== engine.generatePassword({ length: 20 }).password],
];
extraChecks.forEach(([label, ok]) => {
  if (ok) passed += 1; else failures.push({ password: "(behaviour check)", problems: [label] });
});

console.log("=".repeat(74));
console.log(`JavaScript engine parity test: ${passed} passed, ${failures.length} failed`);
console.log("=".repeat(74));
if (failures.length) {
  failures.forEach((f) => {
    console.log(`FAIL  ${f.password}`);
    f.problems.forEach((p) => console.log(`        - ${p}`));
  });
  process.exit(1);
}
console.log("Both engines agree on score, classification, findings and policy verdict.");
console.log(`Data loaded: ${JSON.stringify(engine.dataStats)}`);
