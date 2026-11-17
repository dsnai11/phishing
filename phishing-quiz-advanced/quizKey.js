// Correct answer index (0 = A, 1 = B, 2 = C, 3 = D) for each module's questions,
// in the ORIGINAL order of the QUIZ array in that module's page. (The page shuffles questions
// and options for each learner, but always sends answers back in this original order.)
// Scores are calculated on the server, so a learner cannot fake a score by editing the page.
//
// IMPORTANT: if you add, remove or reorder questions in a page, update its key here too.
const MODULES = {
  basic: {
    name: "Phishing Awareness (Basic)",
    page: "public/basic.html",
    key: [1, 2, 1, 2, 2, 0, 2, 1, 2, 1, 3, 0, 1, 3, 2],
    passMark: Number(process.env.PASS_MARK || 80),
    timeLimitMin: Number(process.env.TIME_LIMIT_BASIC_MIN || 0), // 0 = no time limit
  },
  advanced: {
    name: "Phishing Awareness – Advanced (CISA-level)",
    page: "public/advanced.html",
    key: [1, 3, 0, 2, 1, 0, 3, 2, 1, 0, 3, 2, 0, 1, 3, 2, 0, 1, 2, 3, 0, 2, 1, 3, 0],
    passMark: Number(process.env.PASS_MARK_ADVANCED || process.env.PASS_MARK || 80),
    timeLimitMin: Number(process.env.TIME_LIMIT_ADVANCED_MIN || 30),
  },
};

// Proctoring: number of warnings allowed. The rule break after the last warning ends the
// assessment, and such attempts are always recorded as FAILED.
const MAX_WARNINGS = Number(process.env.MAX_WARNINGS || 2);

// Unanswered questions are sent as -1 and count as wrong.
function scoreAnswers(moduleId, answers) {
  const m = MODULES[moduleId];
  const total = m.key.length;
  const correct = answers.reduce((n, a, i) => n + (a === m.key[i] ? 1 : 0), 0);
  const score = Math.round((correct / total) * 100);
  return { total, correct, score, passed: score >= m.passMark, passMark: m.passMark };
}

module.exports = { MODULES, MAX_WARNINGS, scoreAnswers };
