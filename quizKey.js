// Correct answer index (0 = A, 1 = B, 2 = C, 3 = D) for each module's questions,
// in the same order as the QUIZ array in that module's page.
// Scores are calculated on the server from these keys, so a learner cannot
// fake a score by editing the page in their browser.
//
// IMPORTANT: if you add, remove or reorder questions in a page, update its key here too.
const MODULES = {
  basic: {
    name: "Phishing Awareness (Basic)",
    page: "public/index.html",
    key: [1, 2, 1, 2, 2, 0, 2, 1, 2, 1],
    passMark: Number(process.env.PASS_MARK || 80),
  },
  advanced: {
    name: "Phishing Awareness – Advanced (CISA-level)",
    page: "public/advanced.html",
    key: [1, 3, 0, 2, 1, 0, 3, 2, 1, 0, 3, 2, 0, 1, 3, 2, 0, 1, 2, 3, 0, 2, 1, 3, 0],
    passMark: Number(process.env.PASS_MARK_ADVANCED || process.env.PASS_MARK || 80),
  },
};

function scoreAnswers(moduleId, answers) {
  const m = MODULES[moduleId];
  const total = m.key.length;
  const correct = answers.reduce((n, a, i) => n + (a === m.key[i] ? 1 : 0), 0);
  const score = Math.round((correct / total) * 100);
  return { total, correct, score, passed: score >= m.passMark, passMark: m.passMark };
}

module.exports = { MODULES, scoreAnswers };
