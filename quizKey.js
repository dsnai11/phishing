// Correct answer index (0 = A, 1 = B, 2 = C, 3 = D) for each question,
// in the same order as the QUIZ array in public/index.html.
// Scores are calculated on the server from these keys, so a learner cannot
// fake a score by editing the page in their browser.
//
// IMPORTANT: if you add, remove or reorder questions in a page, update its key here too.
const MODULES = {
  advanced: {
    name: "Phishing Awareness – Advanced (CISA-level)",
    page: "public/index.html",
    key: [1, 3, 0, 2, 1, 0, 3, 2, 1, 0, 3, 2, 0, 1, 3, 2, 0, 1, 2, 3, 0, 2, 1, 3, 0],
    passMark: Number(process.env.PASS_MARK_ADVANCED || process.env.PASS_MARK || 80),
  },
};
// The earlier "basic" module has been retired. Its old results stay in the database
// (module = 'basic') but are no longer shown on the dashboard or accepted from the page.
const DEFAULT_MODULE = "advanced";

function scoreAnswers(moduleId, answers) {
  const m = MODULES[moduleId];
  const total = m.key.length;
  const correct = answers.reduce((n, a, i) => n + (a === m.key[i] ? 1 : 0), 0);
  const score = Math.round((correct / total) * 100);
  return { total, correct, score, passed: score >= m.passMark, passMark: m.passMark };
}

module.exports = { MODULES, DEFAULT_MODULE, scoreAnswers };
