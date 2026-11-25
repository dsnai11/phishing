// Question papers for the Phishing Awareness modules (basic + advanced).
// The questions (with answers) live only on the server; the browser receives the question text and options
// when a test starts, and the correct answers + explanations only after the result is saved.
//
// Basic module: one set of 25 (order of questions and options is shuffled in the browser on every attempt).
// Advanced module: 5 parallel sets (A–E) of 25 questions. Question slot k covers the same topic in every set.
// Each paper takes one question per slot from one of the sets, so:
//   • a person's next attempt uses, in every slot, a set they have not had yet (until all 5 have been used);
//   • no two people (or attempts) ever receive exactly the same paper — the server checks every issued paper.
const crypto = require("crypto");
const BANK = require("./phishBank");
const { query } = require("./db");

const SETS = Object.keys(BANK.advanced);                 // ["A","B","C","D","E"]
const SLOT_COUNT = BANK.slots.length;                     // 25
const BY_ID = new Map();
for (const q of BANK.basic) BY_ID.set(q.id, q);
for (const s of SETS) for (const q of BANK.advanced[s]) BY_ID.set(q.id, q);

const publicQuestion = (q) => ({ id: q.id, d: q.d, q: q.q, o: q.o });          // no answer, no explanation
const pick = (arr) => arr[crypto.randomInt(arr.length)];

/** Paper ids for a module. Advanced papers avoid sets this employee already had in each slot, and are unique. */
async function issuePaper(moduleId, empId) {
  if (moduleId === "basic") return { code: "BASIC", ids: BANK.basic.map((q) => q.id) };
  if (moduleId !== "advanced") throw new Error("Not a paper module");

  // How often has this employee seen each set in each slot?
  const { rows } = await query(
    `SELECT paper FROM proctor_sessions WHERE module = $1 AND emp_id = $2 AND paper IS NOT NULL`, [moduleId, empId]);
  const used = Array.from({ length: SLOT_COUNT }, () => Object.fromEntries(SETS.map((s) => [s, 0])));
  for (const r of rows) (Array.isArray(r.paper) ? r.paper : []).forEach((id, k) => { const s = String(id)[0]; if (used[k] && s in used[k]) used[k][s]++; });

  for (let attempt = 0; attempt < 40; attempt++) {
    // In each slot, choose among the sets this person has seen least (0 times on early attempts).
    const sets = used.map((u) => { const min = Math.min(...Object.values(u)); return pick(SETS.filter((s) => u[s] === min)); });
    const code = sets.join("");
    const { rows: dup } = await query(`SELECT 1 FROM proctor_sessions WHERE module = $1 AND paper_code = $2 LIMIT 1`, [moduleId, code]);
    if (!dup.length) return { code, ids: sets.map((s, k) => `${s}${String(k + 1).padStart(2, "0")}`) };
  }
  // Practically impossible (5^25 combinations); fall back to a fully random unique paper.
  for (;;) {
    const sets = Array.from({ length: SLOT_COUNT }, () => pick(SETS)); const code = sets.join("");
    const { rows: dup } = await query(`SELECT 1 FROM proctor_sessions WHERE module = $1 AND paper_code = $2 LIMIT 1`, [moduleId, code]);
    if (!dup.length) return { code, ids: sets.map((s, k) => `${s}${String(k + 1).padStart(2, "0")}`) };
  }
}

const questionsFor = (ids) => ids.map((id) => publicQuestion(BY_ID.get(id)));
const reviewFor = (ids) => ids.map((id) => { const q = BY_ID.get(id); return q ? { a: q.a, e: q.e } : { a: -1, e: { en: "", hi: "" } }; });
const validPaper = (ids) => Array.isArray(ids) && ids.length === SLOT_COUNT && ids.every((id) => BY_ID.has(id));

function scorePaper(ids, answers, passMark) {
  const total = ids.length;
  const correct = ids.reduce((n, id, i) => n + (answers[i] === BY_ID.get(id).a ? 1 : 0), 0);
  const score = Math.round((correct / total) * 100);
  return { total, correct, score, passed: score >= passMark, passMark };
}

module.exports = { BANK, BY_ID, SLOT_COUNT, issuePaper, questionsFor, reviewFor, validPaper, scorePaper };
