// Module settings. The questions and answers themselves are in phishBank.js (server only): every attempt gets a
// question paper from papers.js, the page shuffles question and option order, and answers are scored here on the
// server, so a learner cannot see the answers or fake a score by editing the page.
const MODULES = {
  basic: {
    name: "Phishing Awareness (Basic)",
    page: "public/basic.html",
    paper: true,
    questions: 25,
    // Answer key of the OLD 15-question basic quiz – kept only so earlier attempts can still be reviewed/audited.
    legacyKey: [1, 2, 1, 2, 2, 0, 2, 1, 2, 1, 3, 0, 1, 3, 2],
    passMark: Number(process.env.PASS_MARK || 80),
    timeLimitMin: Number(process.env.TIME_LIMIT_BASIC_MIN || 0), // 0 = no time limit
  },
  advanced: {
    name: "Phishing Awareness – Advanced (CISA-level)",
    page: "public/advanced.html",
    paper: true,
    questions: 25,
    // Answer key of the OLD single-paper advanced quiz (now set A) – kept only for reviewing/auditing earlier attempts.
    legacyKey: [1, 3, 0, 2, 1, 0, 3, 2, 1, 0, 3, 2, 0, 1, 3, 2, 0, 1, 2, 3, 0, 2, 1, 3, 0],
    passMark: Number(process.env.PASS_MARK_ADVANCED || process.env.PASS_MARK || 80),
    timeLimitMin: Number(process.env.TIME_LIMIT_ADVANCED_MIN || 30),
  },
};
const questionCount = (id) => MODULES[id].questions;

// Proctoring: number of warnings allowed. The rule break after the last warning ends the
// assessment, and such attempts are always recorded as FAILED.
const MAX_WARNINGS = Number(process.env.MAX_WARNINGS || 2);

// Unanswered questions are sent as -1 and count as wrong.
function scoreAnswers(moduleId, answers) {
  // Legacy scoring (old fixed papers) – only used when re-checking attempts made before question papers existed.
  const m = MODULES[moduleId];
  const total = m.legacyKey.length;
  const correct = answers.reduce((n, a, i) => n + (a === m.legacyKey[i] ? 1 : 0), 0);
  const score = Math.round((correct / total) * 100);
  return { total, correct, score, passed: score >= m.passMark, passMark: m.passMark };
}

module.exports = { MODULES, MAX_WARNINGS, scoreAnswers, questionCount };
