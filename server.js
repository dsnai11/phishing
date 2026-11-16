const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { query, migrate } = require("./db");
const { MODULES, scoreAnswers } = require("./quizKey");

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
// Optional: comma-separated list of other websites (e.g. your LMS) allowed to submit results.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.warn("WARNING: ADMIN_PASSWORD is missing or shorter than 8 characters. The admin dashboard is disabled until it is set.");
}

const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy; needed for correct client IPs.
app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));

// Basic security headers
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  next();
});

/* ------------------------------------------------------------------
   Admin authentication (HTTP Basic Auth)
------------------------------------------------------------------- */
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function requireAdmin(req, res, next) {
  if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
    return res.status(503).send("Admin dashboard disabled: set ADMIN_PASSWORD (min 8 characters) in the environment.");
  }
  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme === "Basic" && encoded) {
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const idx = decoded.indexOf(":");
    const user = decoded.slice(0, idx);
    const pass = decoded.slice(idx + 1);
    if (safeEqual(user, ADMIN_USER) && safeEqual(pass, ADMIN_PASSWORD)) return next();
  }
  res.setHeader("WWW-Authenticate", 'Basic realm="Phishing Quiz Admin", charset="UTF-8"');
  return res.status(401).send("Authentication required.");
}

const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 200, standardHeaders: true, legacyHeaders: false });

/* ------------------------------------------------------------------
   Public API: submit a quiz attempt
------------------------------------------------------------------- */
// Many employees can share one office IP, so this limit is generous.
const submitLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many submissions. Please try again in a few minutes." } });

const corsForSubmit = cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.includes(origin)),
  methods: ["POST"],
});

const clean = (v, max) => String(v ?? "").replace(/[\u0000-\u001F\u007F<>]/g, "").replace(/\s+/g, " ").trim().slice(0, max);

app.options("/api/results", corsForSubmit);
app.post("/api/results", corsForSubmit, submitLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const fullName = clean(b.name, 120);
    const empId = clean(b.empId, 30).toUpperCase();
    const department = clean(b.department, 80) || null;
    const language = b.language === "hi" ? "hi" : "en";
    const durationSec = Number.isFinite(+b.durationSec) ? Math.max(0, Math.min(86400, Math.round(+b.durationSec))) : null;
    const answers = Array.isArray(b.answers) ? b.answers : [];
    const moduleId = MODULES[b.module] ? b.module : "basic";
    const expected = MODULES[moduleId].key.length;

    const errors = [];
    if (fullName.length < 2) errors.push("Name is required.");
    if (!/^[A-Z0-9][A-Z0-9\-_/.]{0,29}$/.test(empId)) errors.push("Employee ID must contain only letters, numbers, - _ / .");
    if (answers.length !== expected || !answers.every((a) => Number.isInteger(a) && a >= 0 && a <= 3)) {
      errors.push(`Exactly ${expected} answers are required.`);
    }
    if (errors.length) return res.status(400).json({ error: errors.join(" ") });

    const result = scoreAnswers(moduleId, answers);

    const { rows: prev } = await query("SELECT COUNT(*)::int AS n FROM quiz_attempts WHERE emp_id = $1 AND module = $2", [empId, moduleId]);
    const attemptNo = prev[0].n + 1;

    const { rows } = await query(
      `INSERT INTO quiz_attempts
        (module, emp_id, full_name, department, language, score, correct_count, total_questions, passed,
         answers, duration_sec, attempt_no, ip_address, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       RETURNING id, created_at`,
      [moduleId, empId, fullName, department, language, result.score, result.correct, result.total, result.passed,
       JSON.stringify(answers), durationSec, attemptNo, clean(req.ip, 64), clean(req.headers["user-agent"], 300)]
    );

    res.status(201).json({ id: rows[0].id, savedAt: rows[0].created_at, module: moduleId, attemptNo, ...result });
  } catch (err) {
    console.error("Save failed:", err);
    res.status(500).json({ error: "Could not save the result. Please try again." });
  }
});

/* ------------------------------------------------------------------
   Admin API
------------------------------------------------------------------- */
function buildFilter(q) {
  const where = [];
  const params = [];
  if (q.module && MODULES[q.module]) { params.push(q.module); where.push(`module = $${params.length}`); }
  if (q.search) {
    params.push(`%${String(q.search).trim()}%`);
    where.push(`(emp_id ILIKE $${params.length} OR full_name ILIKE $${params.length} OR department ILIKE $${params.length})`);
  }
  if (q.status === "passed") where.push("passed = true");
  if (q.status === "failed") where.push("passed = false");
  if (q.from && /^\d{4}-\d{2}-\d{2}$/.test(q.from)) { params.push(q.from); where.push(`created_at >= $${params.length}::date`); }
  if (q.to && /^\d{4}-\d{2}-\d{2}$/.test(q.to)) { params.push(q.to); where.push(`created_at < ($${params.length}::date + interval '1 day')`); }
  return { where: where.length ? "WHERE " + where.join(" AND ") : "", params };
}

// view = all (every attempt) | latest (latest attempt per employee) | best (best attempt per employee)
function resultsQuery(q, { limit, offset } = {}) {
  const { where, params } = buildFilter(q);
  const cols = `id, module, emp_id, full_name, department, language, score, correct_count, total_questions,
                passed, duration_sec, attempt_no, created_at`;
  let sql;
  if (q.view === "latest" || q.view === "best") {
    const order = q.view === "latest" ? "created_at DESC" : "score DESC, created_at DESC";
    sql = `SELECT * FROM (SELECT DISTINCT ON (module, emp_id) ${cols} FROM quiz_attempts ${where}
           ORDER BY module, emp_id, ${order}) t ORDER BY created_at DESC`;
  } else {
    sql = `SELECT ${cols} FROM quiz_attempts ${where} ORDER BY created_at DESC`;
  }
  if (limit) { params.push(limit); sql += ` LIMIT $${params.length}`; }
  if (offset) { params.push(offset); sql += ` OFFSET $${params.length}`; }
  return { sql, params };
}

app.use("/api/admin", adminLimiter, requireAdmin);

app.get("/api/admin/stats", async (req, res) => {
  try {
    const { where, params } = buildFilter({ module: req.query.module });
    const { rows } = await query(`
      SELECT
        COUNT(*)::int                                   AS total_attempts,
        COUNT(DISTINCT emp_id)::int                     AS employees,
        COUNT(DISTINCT emp_id) FILTER (WHERE passed)::int AS employees_passed,
        COALESCE(ROUND(AVG(score))::int, 0)             AS avg_score,
        COUNT(*) FILTER (WHERE created_at >= now() - interval '7 days')::int AS last_7_days
      FROM quiz_attempts ${where}`, params);
    const m = MODULES[req.query.module];
    res.json({ ...rows[0], pass_mark: m ? m.passMark : null,
      modules: Object.fromEntries(Object.entries(MODULES).map(([k, v]) => [k, { name: v.name, questions: v.key.length, passMark: v.passMark }])) });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "Could not load stats." });
  }
});

app.get("/api/admin/results", async (req, res) => {
  try {
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const countQ = resultsQuery(req.query);
    const { rows: c } = await query(`SELECT COUNT(*)::int AS n FROM (${countQ.sql}) x`, countQ.params);
    const q = resultsQuery(req.query, { limit, offset: (page - 1) * limit });
    const { rows } = await query(q.sql, q.params);
    res.json({ total: c[0].n, page, limit, rows });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "Could not load results." });
  }
});

app.get("/api/admin/results.csv", async (req, res) => {
  try {
    const q = resultsQuery(req.query);
    const { rows } = await query(q.sql, q.params);
    const headers = ["Attempt ID", "Module", "Employee ID", "Name", "Department", "Language", "Score (%)", "Correct",
      "Total Questions", "Result", "Attempt No", "Time Taken (min)", "Submitted At (IST)"];
    const esc = (v) => {
      let s = v === null || v === undefined ? "" : String(v);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // protect against spreadsheet formula injection
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const fmt = (d) => new Date(d).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", hour12: false });
    const lines = [headers.join(",")].concat(rows.map((r) => [
      r.id, MODULES[r.module] ? MODULES[r.module].name : r.module, r.emp_id, r.full_name, r.department, r.language === "hi" ? "Hindi" : "English", r.score,
      r.correct_count, r.total_questions, r.passed ? "PASSED" : "FAILED", r.attempt_no,
      r.duration_sec === null ? "" : (r.duration_sec / 60).toFixed(1), fmt(r.created_at),
    ].map(esc).join(",")));
    const stamp = new Date().toISOString().slice(0, 10);
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="phishing-quiz-results-${stamp}.csv"`);
    res.send("﻿" + lines.join("\r\n")); // BOM so Excel shows Hindi names correctly
  } catch (err) {
    console.error(err); res.status(500).send("Could not export results.");
  }
});

app.delete("/api/admin/results/:id", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: "Invalid id." });
  try {
    const { rowCount } = await query("DELETE FROM quiz_attempts WHERE id = $1", [id]);
    res.json({ deleted: rowCount });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "Could not delete." });
  }
});

/* ------------------------------------------------------------------
   Pages
------------------------------------------------------------------- */
app.get("/healthz", async (req, res) => {
  try { await query("SELECT 1"); res.json({ ok: true }); }
  catch { res.status(503).json({ ok: false }); }
});

// Pages normally live in /public. If they were uploaded to the top level of the repo instead
// (GitHub's web upload can flatten folders), use them from there — but ONLY these pages
// are ever served from the top level, never server.js, db.js or other code.
const fs = require("fs");
function pagePath(name) {
  const inPublic = path.join(__dirname, "public", name);
  if (fs.existsSync(inPublic)) return inPublic;
  const atRoot = path.join(__dirname, name);
  if (fs.existsSync(atRoot)) return atRoot;
  return null;
}
const INDEX_PAGE = pagePath("index.html");
const ADMIN_PAGE = pagePath("admin.html");
const ADVANCED_PAGE = pagePath("advanced.html");
console.log(`Training page: ${INDEX_PAGE || "MISSING"} | Advanced page: ${ADVANCED_PAGE || "MISSING"} | Admin page: ${ADMIN_PAGE || "MISSING"}`);

const noPage = (name) => (req, res) =>
  res.status(500).send(`${name} was not found on the server. Upload it to the "public" folder of the GitHub repo.`);

app.get(["/admin", "/admin.html"], adminLimiter, requireAdmin, ADMIN_PAGE ? (req, res) => res.sendFile(ADMIN_PAGE) : noPage("admin.html"));
app.get(["/", "/index.html"], INDEX_PAGE ? (req, res) => res.sendFile(INDEX_PAGE) : noPage("index.html"));
app.get(["/advanced", "/advanced.html"], ADVANCED_PAGE ? (req, res) => res.sendFile(ADVANCED_PAGE) : noPage("advanced.html"));

// Any other static files (only from the public folder, if it exists)
if (fs.existsSync(path.join(__dirname, "public"))) {
  app.use(express.static(path.join(__dirname, "public"), { index: false }));
}

app.use((req, res) => res.status(404).send("Not found"));

/* ------------------------------------------------------------------ */
migrate()
  .then(() => app.listen(PORT, () => console.log(`Phishing quiz running on port ${PORT}`)))
  .catch((err) => { console.error("Database setup failed:", err); process.exit(1); });
