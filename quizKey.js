// Correct answer index (0 = A, 1 = B, 2 = C, 3 = D) for each quiz question,
// in the same order as the QUIZ array in public/index.html.
// Scores are calculated on the server from this key, so a learner cannot
// fake a score by editing the page in their browser.
//
// IMPORTANT: if you add, remove or reorder questions in public/index.html,
// update this list too.
const ANSWER_KEY = [1, 2, 1, 2, 2, 0, 2, 1, 2, 1];

const PASS_MARK = Number(process.env.PASS_MARK || 80);

function scoreAnswers(answers) {
  const total = ANSWER_KEY.length;
  const correct = answers.reduce((n, a, i) => n + (a === ANSWER_KEY[i] ? 1 : 0), 0);
  const score = Math.round((correct / total) * 100);
  return { total, correct, score, passed: score >= PASS_MARK };
}

module.exports = { ANSWER_KEY, PASS_MARK, scoreAnswers };
