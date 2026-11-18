const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { query, migrate } = require("./db");
const { MODULES, MAX_WARNINGS, scoreAnswers } = require("./quizKey");

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
// Optional: comma-separated list of other websites (e.g. your LMS) allowed to submit results.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map((s) => s.trim()).filter(Boolean);
// Extra seconds allowed after a time limit (network delays) before an attempt is flagged "late".
const TIME_GRACE_SEC = 120;
// An unsubmitted session with no activity for this long is shown as "Not submitted" on the dashboard.
const ABANDON_MINUTES = 60;
// Webcam photos: at most this many per assessment, and deleted automatically after this many days.
const MAX_SNAPSHOTS = 60;
const SNAPSHOT_RETENTION_DAYS = Number(process.env.SNAPSHOT_RETENTION_DAYS || 180);
// Full video + sound recordings (advanced module): deleted automatically after this many days.
const RECORDING_RETENTION_DAYS = Number(process.env.RECORDING_RETENTION_DAYS || 90);
const MAX_RECORDING_MB_PER_TEST = 150;           // safety cap per attempt (a 30-minute test is about 20 MB)
const DB_STORAGE_LIMIT_MB = Number(process.env.DB_STORAGE_LIMIT_MB || 1024); // Neon free plan: 1 GB per project

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.warn("WARNING: ADMIN_PASSWORD is missing or shorter than 8 characters. The admin dashboard is disabled until it is set.");
}

const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy; needed for correct client IPs.
app.disable("x-powered-by");
app.use(express.json({ limit: "200kb" })); // webcam photos are about 10-25 KB each

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

const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false });

/* ------------------------------------------------------------------
   Public API — shared helpers
------------------------------------------------------------------- */
// Many employees can share one office IP, so these limits are generous.
const submitLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 600, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many requests. Please try again in a few minutes." } });
const eventLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5000, standardHeaders: true, legacyHeaders: false });

const corsForPublic = cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.includes(origin)),
  methods: ["POST"],
});

const clean = (v, max) => String(v ?? "").replace(/[\u0000-\u001F\u007F<>]/g, "").replace(/\s+/g, " ").trim().slice(0, max);

// Event types the page may record. "counted" events are rule breaks.
const EVENT_TYPES = new Set([
  "session_start", "resume", "submit", "time_up", "terminated", "leave_attempt", "fullscreen_unavailable",
  "tab_hidden", "window_blur", "fullscreen_exit", "copy", "cut", "paste", "right_click", "shortcut",
  "print_screen", "multiple_tabs", "page_reload", "result_saved",
  "camera_start", "camera_off", "camera_blocked", "no_face", "multiple_faces", "face_check_unavailable", "snapshot", "extension",
  "mic_off", "recording_start", "recording_failed", "recording_gap",
]);
function cleanEvent(e) {
  if (!e || !EVENT_TYPES.has(e.type)) return null;
  return {
    type: e.type,
    counted: e.counted === true,
    detail: e.detail ? clean(e.detail, 120) : null,
    q: Number.isInteger(e.q) && e.q > 0 && e.q < 200 ? e.q : null,
    at: typeof e.at === "string" && !isNaN(Date.parse(e.at)) ? new Date(e.at).toISOString() : new Date().toISOString(),
  };
}

function readIdentity(b) {
  const fullName = clean(b.name, 120);
  const empId = clean(b.empId, 30).toUpperCase();
  const department = clean(b.department, 80) || null;
  const language = b.language === "hi" ? "hi" : "en";
  const errors = [];
  if (fullName.length < 2) errors.push("Name is required.");
  if (!/^[A-Z0-9][A-Z0-9\-_/.]{0,29}$/.test(empId)) errors.push("Employee ID must contain only letters, numbers, - _ / .");
  return { fullName, empId, department, language, errors };
}
const SID_RE = /^[a-f0-9]{32}$/;

/* ------------------------------------------------------------------
   Proctoring: start a monitored session
------------------------------------------------------------------- */
app.options("/api/session/start", corsForPublic);
app.post("/api/session/start", corsForPublic, submitLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const moduleId = MODULES[b.module] ? b.module : null;
    const id = readIdentity(b);
    if (!moduleId) id.errors.push("Unknown module.");
    if (id.errors.length) return res.status(400).json({ error: id.errors.join(" ") });
    const sid = crypto.randomBytes(16).toString("hex");
    const { rows } = await query(
      `INSERT INTO proctor_sessions (id, module, emp_id, full_name, department, language, fullscreen, camera, face_check, recording, ip_address, user_agent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING started_at`,
      [sid, moduleId, id.empId, id.fullName, id.department, id.language, b.fullscreen === true, b.camera === true, b.faceCheck === true, b.recording === true,
       clean(req.ip, 64), clean(req.headers["user-agent"], 300)]);
    const m = MODULES[moduleId];
    res.status(201).json({ sessionId: sid, startedAt: rows[0].started_at, timeLimitMin: m.timeLimitMin, maxWarnings: MAX_WARNINGS });
  } catch (err) {
    console.error("Session start failed:", err);
    res.status(500).json({ error: "Could not start the assessment. Please try again." });
  }
});

/* ------------------------------------------------------------------
   Proctoring: record an action (tab switch, full-screen exit, copy, …)
------------------------------------------------------------------- */
app.options("/api/session/:sid/event", corsForPublic);
app.post("/api/session/:sid/event", corsForPublic, eventLimiter, async (req, res) => {
  const sid = String(req.params.sid || "");
  const ev = cleanEvent(req.body);
  if (!SID_RE.test(sid) || !ev) return res.status(204).end();
  try {
    await query(
      `UPDATE proctor_sessions
          SET events = CASE WHEN jsonb_array_length(events) < 400 THEN events || $2::jsonb ELSE events END,
              violations = violations + $3,
              last_event_at = now()
        WHERE id = $1 AND status = 'in_progress'`,
      [sid, JSON.stringify([ev]), ev.counted ? 1 : 0]);
  } catch (err) {
    console.error("Event save failed:", err.message);
  }
  res.status(204).end();
});

/* ------------------------------------------------------------------
   Proctoring: save a webcam photo (start, every 5 minutes, and on face problems)
------------------------------------------------------------------- */
const SNAP_REASONS = new Set(["start", "periodic", "no_face", "multiple_faces", "camera_blocked"]);
app.options("/api/session/:sid/snapshot", corsForPublic);
app.post("/api/session/:sid/snapshot", corsForPublic, eventLimiter, async (req, res) => {
  const sid = String(req.params.sid || "");
  const b = req.body || {};
  const img = typeof b.image === "string" ? b.image : "";
  if (!SID_RE.test(sid) || !SNAP_REASONS.has(b.reason) || !/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(img) || img.length > 150000) {
    return res.status(204).end();
  }
  try {
    await query(
      `INSERT INTO proctor_snapshots (session_id, reason, question, image)
       SELECT $1::varchar, $2::varchar, $3::smallint, $4::text FROM proctor_sessions
        WHERE id = $1::varchar AND status = 'in_progress'
          AND (SELECT COUNT(*) FROM proctor_snapshots WHERE session_id = $1::varchar) < ${MAX_SNAPSHOTS}`,
      [sid, b.reason, Number.isInteger(b.q) && b.q > 0 && b.q < 200 ? b.q : null, img]);
  } catch (err) {
    console.error("Snapshot save failed:", err.message);
  }
  res.status(204).end();
});

/* ------------------------------------------------------------------
   Proctoring: save a 5-second piece of the video + sound recording
------------------------------------------------------------------- */
app.options("/api/session/:sid/recording", corsForPublic);
app.post("/api/session/:sid/recording", corsForPublic, eventLimiter,
  express.raw({ type: "application/octet-stream", limit: "4mb" }), async (req, res) => {
  const sid = String(req.params.sid || "");
  const part = parseInt(req.query.part, 10), seq = parseInt(req.query.seq, 10);
  const mime = String(req.query.mime || "").replace(/[^a-z0-9/;=,.\-]/gi, "").slice(0, 60) || null;
  const buf = req.body;
  if (!SID_RE.test(sid) || !(part >= 0 && part < 100) || !(seq >= 0 && seq < 100000) || !Buffer.isBuffer(buf) || !buf.length) {
    return res.status(400).json({ error: "Invalid recording piece." });
  }
  try {
    // Accept pieces while the test runs, and for 10 minutes after it ends (the last pieces arrive after submitting).
    const { rows } = await query(
      `SELECT s.status, s.ended_at, COALESCE((SELECT SUM(bytes) FROM proctor_recordings r WHERE r.session_id = s.id), 0)::bigint AS used
         FROM proctor_sessions s WHERE s.id = $1`, [sid]);
    const s = rows[0];
    if (!s) return res.status(404).json({ error: "Unknown session." });
    const open = s.status === "in_progress" || (s.ended_at && Date.now() - new Date(s.ended_at).getTime() < 10 * 60 * 1000);
    if (!open) return res.status(409).json({ error: "This assessment has ended." });
    if (Number(s.used) + buf.length > MAX_RECORDING_MB_PER_TEST * 1024 * 1024) return res.status(413).json({ error: "Recording too large." });
    await query(
      `INSERT INTO proctor_recordings (session_id, part, seq, mime, bytes, data) VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (session_id, part, seq) DO NOTHING`, [sid, part, seq, mime, buf.length, buf]);
    res.status(204).end();
  } catch (err) {
    console.error("Recording save failed:", err.message);
    res.status(500).json({ error: "Could not save." });
  }
});

/* ------------------------------------------------------------------
   Submit a quiz attempt
------------------------------------------------------------------- */
app.options("/api/results", corsForPublic);
app.post("/api/results", corsForPublic, submitLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const moduleId = MODULES[b.module] ? b.module : "basic";
    const m = MODULES[moduleId];
    const answers = Array.isArray(b.answers) ? b.answers : [];
    const endReason = ["completed", "time_up", "terminated"].includes(b.endReason) ? b.endReason : "completed";
    const sid = SID_RE.test(String(b.sessionId || "")) ? String(b.sessionId) : null;

    if (answers.length !== m.key.length || !answers.every((a) => Number.isInteger(a) && a >= -1 && a <= 3)) {
      return res.status(400).json({ error: `Exactly ${m.key.length} answers are required.` });
    }

    // Use the monitored session (identity, start time, rule breaks) when there is one.
    let session = null;
    if (sid) {
      const { rows } = await query("SELECT * FROM proctor_sessions WHERE id = $1", [sid]);
      session = rows[0] || null;
      if (session && session.module !== moduleId) session = null;
    }
    // Already submitted (e.g. the learner pressed "Retry saving") → return the saved result.
    if (session && session.attempt_id) {
      const { rows } = await query("SELECT * FROM quiz_attempts WHERE id = $1", [session.attempt_id]);
      if (rows[0]) {
        const r = rows[0];
        return res.status(200).json({ id: r.id, savedAt: r.created_at, module: r.module, attemptNo: r.attempt_no, total: r.total_questions,
          correct: r.correct_count, score: r.score, passed: r.passed, passMark: m.passMark, violations: r.violations, proctorStatus: r.proctor_status, duplicate: true });
      }
    }

    const id = session
      ? { fullName: session.full_name, empId: session.emp_id, department: session.department, language: b.language === "hi" ? "hi" : session.language || "en", errors: [] }
      : readIdentity(b);
    if (id.errors.length) return res.status(400).json({ error: id.errors.join(" ") });

    const clientEvents = (Array.isArray(b.events) ? b.events : []).slice(-150).map(cleanEvent).filter(Boolean);
    const clientViolations = Number.isInteger(b.violations) ? Math.max(0, Math.min(50, b.violations)) : 0;
    const violations = Math.max(session ? session.violations : 0, clientViolations);
    const terminated = endReason === "terminated" || violations > MAX_WARNINGS;

    let durationSec = Number.isFinite(+b.durationSec) ? Math.max(0, Math.min(86400, Math.round(+b.durationSec))) : null;
    if (session) durationSec = Math.round((Date.now() - new Date(session.started_at).getTime()) / 1000);
    const late = !!(session && m.timeLimitMin && durationSec > m.timeLimitMin * 60 + TIME_GRACE_SEC);

    const proctorStatus = terminated ? "terminated" : late ? "late" : endReason === "time_up" ? "time_up"
      : !session ? "unverified" : violations > 0 ? "warned" : "clean";

    const result = scoreAnswers(moduleId, answers);
    const passed = result.passed && !terminated;

    const { rows: prev } = await query("SELECT COUNT(*)::int AS n FROM quiz_attempts WHERE emp_id = $1 AND module = $2", [id.empId, moduleId]);
    const attemptNo = prev[0].n + 1;

    let sessionId = session ? session.id : crypto.randomBytes(16).toString("hex");
    const { rows } = await query(
      `INSERT INTO quiz_attempts
        (module, emp_id, full_name, department, language, score, correct_count, total_questions, passed,
         answers, duration_sec, attempt_no, ip_address, user_agent, session_id, violations, proctor_status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
       RETURNING id, created_at`,
      [moduleId, id.empId, id.fullName, id.department, id.language, result.score, result.correct, result.total, passed,
       JSON.stringify(answers), durationSec, attemptNo, clean(req.ip, 64), clean(req.headers["user-agent"], 300),
       sessionId, violations, proctorStatus]
    );
    const attemptId = rows[0].id;

    if (session) {
      await query(
        `UPDATE proctor_sessions SET status = $2, attempt_id = $3, ended_at = now(), violations = $4,
                events = CASE WHEN jsonb_array_length(events) < 400 THEN events || $5::jsonb ELSE events END
          WHERE id = $1`,
        [sessionId, terminated ? "terminated" : "submitted", attemptId, violations,
         JSON.stringify([{ type: "result_saved", counted: false, detail: `${result.score}% · ${passed ? "PASSED" : "FAILED"}`, q: null, at: new Date().toISOString() }])]);
    } else {
      // No monitored session reached the server (e.g. network problem at the start): keep the page's own log.
      await query(
        `INSERT INTO proctor_sessions (id, module, emp_id, full_name, department, language, status, violations, events, attempt_id,
                                       ip_address, user_agent, started_at, ended_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12, now() - make_interval(secs => $13), now())`,
        [sessionId, moduleId, id.empId, id.fullName, id.department, id.language, terminated ? "terminated" : "submitted",
         violations, JSON.stringify(clientEvents), attemptId, clean(req.ip, 64), clean(req.headers["user-agent"], 300), durationSec || 0]);
    }

    res.status(201).json({ id: attemptId, savedAt: rows[0].created_at, module: moduleId, attemptNo, ...result, passed,
      violations, proctorStatus });
  } catch (err) {
    console.error("Save failed:", err);
    res.status(500).json({ error: "Could not save the result. Please try again." });
  }
});

/* ------------------------------------------------------------------
   Admin API
------------------------------------------------------------------- */
const FLAGGED = ["warned", "terminated", "late", "unverified"];

function buildFilter(q, { dateCol = "created_at", proctorCol = "proctor_status" } = {}) {
  const where = [];
  const params = [];
  if (q.module && MODULES[q.module]) { params.push(q.module); where.push(`module = $${params.length}`); }
  if (q.search) {
    params.push(`%${String(q.search).trim()}%`);
    where.push(`(emp_id ILIKE $${params.length} OR full_name ILIKE $${params.length} OR department ILIKE $${params.length})`);
  }
  if (q.status === "passed") where.push("passed = true");
  if (q.status === "failed") where.push("passed = false");
  if (q.proctor === "flagged") where.push(`${proctorCol} IN ('${FLAGGED.join("','")}')`);
  if (q.proctor === "clean") where.push(`${proctorCol} = 'clean'`);
  if (q.from && /^\d{4}-\d{2}-\d{2}$/.test(q.from)) { params.push(q.from); where.push(`${dateCol} >= $${params.length}::date`); }
  if (q.to && /^\d{4}-\d{2}-\d{2}$/.test(q.to)) { params.push(q.to); where.push(`${dateCol} < ($${params.length}::date + interval '1 day')`); }
  return { where: where.length ? "WHERE " + where.join(" AND ") : "", params };
}

// view = all (every attempt) | latest (latest attempt per employee) | best (best attempt per employee)
function resultsQuery(q, { limit, offset } = {}) {
  const { where, params } = buildFilter(q);
  const cols = `id, module, emp_id, full_name, department, language, score, correct_count, total_questions,
                passed, duration_sec, attempt_no, created_at, session_id, violations, proctor_status`;
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

// Sessions = every time someone started an assessment, including ones never submitted.
const SESSION_STATUS_SQL = `CASE WHEN status = 'in_progress' AND COALESCE(last_event_at, started_at) < now() - interval '${ABANDON_MINUTES} minutes'
                                 THEN 'not_submitted' ELSE status END`;
function sessionsQuery(q, { limit, offset } = {}) {
  const { where, params } = buildFilter({ module: q.module, search: q.search, from: q.from, to: q.to }, { dateCol: "started_at" });
  const conds = where ? [where.replace(/^WHERE /, "")] : [];
  if (q.status === "violations") conds.push("violations > 0");
  if (["in_progress", "not_submitted", "submitted", "terminated"].includes(q.status)) {
    params.push(q.status); conds.push(`(${SESSION_STATUS_SQL}) = $${params.length}`);
  }
  let sql = `SELECT id, module, emp_id, full_name, department, language, ${SESSION_STATUS_SQL} AS status, violations,
                    jsonb_array_length(events) AS event_count,
                    (SELECT e->>'type' FROM jsonb_array_elements(events) e WHERE (e->>'counted')::boolean ORDER BY e->>'at' DESC LIMIT 1) AS last_violation,
                    attempt_id, fullscreen, camera, face_check, started_at, ended_at, last_event_at,
                    (SELECT COUNT(*)::int FROM proctor_snapshots ps WHERE ps.session_id = proctor_sessions.id) AS photos,
                    recording,
                    (SELECT COALESCE(SUM(bytes), 0)::bigint FROM proctor_recordings pr WHERE pr.session_id = proctor_sessions.id) AS recording_bytes
               FROM proctor_sessions ${conds.length ? "WHERE " + conds.join(" AND ") : ""}
              ORDER BY started_at DESC`;
  if (limit) { params.push(limit); sql += ` LIMIT $${params.length}`; }
  if (offset) { params.push(offset); sql += ` OFFSET $${params.length}`; }
  return { sql, params };
}

const csvEsc = (v) => {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // protect against spreadsheet formula injection
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const fmtIST = (d) => (d ? new Date(d).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", hour12: false }) : "");
function sendCsv(res, name, headers, rows) {
  const stamp = new Date().toISOString().slice(0, 10);
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${name}-${stamp}.csv"`);
  res.send("﻿" + [headers.join(",")].concat(rows.map((r) => r.map(csvEsc).join(","))).join("\r\n")); // BOM: Excel shows Hindi correctly
}
const PROCTOR_LABEL = { clean: "Clean", warned: "Warned", terminated: "Terminated (3rd rule break)", time_up: "Time up", late: "Submitted late", unverified: "Not monitored", none: "Before proctoring" };
const STATUS_LABEL = { in_progress: "In progress", not_submitted: "Not submitted", submitted: "Submitted", terminated: "Terminated" };

app.use("/api/admin", adminLimiter, requireAdmin);

app.get("/api/admin/stats", async (req, res) => {
  try {
    const { where, params } = buildFilter({ module: req.query.module });
    const { rows } = await query(`
      SELECT
        COUNT(*)::int                                             AS total_attempts,
        COUNT(DISTINCT emp_id)::int                               AS employees,
        COUNT(DISTINCT emp_id) FILTER (WHERE passed)::int         AS employees_passed,
        COALESCE(ROUND(AVG(score))::int, 0)                       AS avg_score,
        COUNT(*) FILTER (WHERE proctor_status IN ('${FLAGGED.join("','")}'))::int AS flagged_attempts,
        COUNT(*) FILTER (WHERE proctor_status = 'terminated')::int AS terminated
      FROM quiz_attempts ${where}`, params);
    const s = sessionsQuery({ module: req.query.module, status: "not_submitted" });
    const { rows: ns } = await query(`SELECT COUNT(*)::int AS n FROM (${s.sql}) x`, s.params);
    const { rows: st } = await query(`SELECT pg_database_size(current_database())::bigint AS db_bytes,
                                              (SELECT COALESCE(SUM(bytes), 0) FROM proctor_recordings)::bigint AS rec_bytes,
                                              (SELECT COUNT(DISTINCT session_id) FROM proctor_recordings)::int AS rec_count`);
    res.json({ ...rows[0], not_submitted: ns[0].n, max_warnings: MAX_WARNINGS,
      storage: { db_mb: Math.round(Number(st[0].db_bytes) / 1048576), recordings_mb: Math.round(Number(st[0].rec_bytes) / 1048576),
                 recordings: st[0].rec_count, limit_mb: DB_STORAGE_LIMIT_MB, recording_retention_days: RECORDING_RETENTION_DAYS },
      pages: { basic: !!PAGES.basic, advanced: !!PAGES.advanced },
      modules: Object.fromEntries(Object.entries(MODULES).map(([k, v]) => [k, { name: v.name, questions: v.key.length, passMark: v.passMark, timeLimitMin: v.timeLimitMin }])) });
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
    sendCsv(res, "phishing-quiz-results",
      ["Attempt ID", "Module", "Employee ID", "Name", "Department", "Language", "Score (%)", "Correct", "Total Questions",
       "Result", "Proctoring", "Rule Breaks", "Attempt No", "Time Taken (min)", "Submitted At (IST)"],
      rows.map((r) => [r.id, MODULES[r.module] ? MODULES[r.module].name : r.module, r.emp_id, r.full_name, r.department,
        r.language === "hi" ? "Hindi" : "English", r.score, r.correct_count, r.total_questions, r.passed ? "PASSED" : "FAILED",
        PROCTOR_LABEL[r.proctor_status] || r.proctor_status, r.violations, r.attempt_no,
        r.duration_sec === null ? "" : (r.duration_sec / 60).toFixed(1), fmtIST(r.created_at)]));
  } catch (err) {
    console.error(err); res.status(500).send("Could not export results.");
  }
});

app.get("/api/admin/sessions", async (req, res) => {
  try {
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const countQ = sessionsQuery(req.query);
    const { rows: c } = await query(`SELECT COUNT(*)::int AS n FROM (${countQ.sql}) x`, countQ.params);
    const q = sessionsQuery(req.query, { limit, offset: (page - 1) * limit });
    const { rows } = await query(q.sql, q.params);
    res.json({ total: c[0].n, page, limit, rows });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "Could not load the integrity log." });
  }
});

app.get("/api/admin/sessions.csv", async (req, res) => {
  try {
    const q = sessionsQuery(req.query);
    const { rows } = await query(q.sql, q.params);
    const ids = rows.map((r) => r.id);
    const evMap = {};
    if (ids.length) {
      const { rows: ev } = await query("SELECT id, events FROM proctor_sessions WHERE id = ANY($1)", [ids]);
      ev.forEach((e) => { evMap[e.id] = e.events; });
    }
    sendCsv(res, "phishing-quiz-integrity-log",
      ["Started (IST)", "Module", "Employee ID", "Name", "Department", "Status", "Rule Breaks", "Rule breaks in detail", "Camera", "Face check", "Photos", "Recording (MB)", "Ended (IST)", "Attempt ID"],
      rows.map((r) => [fmtIST(r.started_at), MODULES[r.module] ? MODULES[r.module].name : r.module, r.emp_id, r.full_name, r.department,
        STATUS_LABEL[r.status] || r.status, r.violations,
        (evMap[r.id] || []).filter((e) => e.counted).map((e) => `${fmtIST(e.at)} ${e.type}${e.detail ? " (" + e.detail + ")" : ""}${e.q ? " Q" + e.q : ""}`).join(" | "),
        r.camera ? "Yes" : r.camera === false ? "No" : "", r.face_check ? "Yes" : r.face_check === false ? "No" : "", r.photos,
        r.recording_bytes ? (Number(r.recording_bytes) / 1048576).toFixed(1) : "",
        fmtIST(r.ended_at), r.attempt_id || ""]));
  } catch (err) {
    console.error(err); res.status(500).send("Could not export the integrity log.");
  }
});

app.get("/api/admin/sessions/:sid", async (req, res) => {
  const sid = String(req.params.sid || "");
  if (!SID_RE.test(sid)) return res.status(400).json({ error: "Invalid session." });
  try {
    const { rows } = await query(`SELECT *, ${SESSION_STATUS_SQL} AS display_status FROM proctor_sessions WHERE id = $1`, [sid]);
    if (!rows[0]) return res.status(404).json({ error: "Not found." });
    let attempt = null;
    if (rows[0].attempt_id) {
      const { rows: a } = await query("SELECT id, score, correct_count, total_questions, passed, proctor_status, created_at FROM quiz_attempts WHERE id = $1", [rows[0].attempt_id]);
      attempt = a[0] || null;
    }
    res.json({ ...rows[0], status: rows[0].display_status, attempt, max_warnings: MAX_WARNINGS });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "Could not load the session." });
  }
});

app.get("/api/admin/sessions/:sid/snapshots", async (req, res) => {
  const sid = String(req.params.sid || "");
  if (!SID_RE.test(sid)) return res.status(400).json({ error: "Invalid session." });
  try {
    const { rows } = await query("SELECT id, reason, question, taken_at FROM proctor_snapshots WHERE session_id = $1 ORDER BY taken_at", [sid]);
    res.json({ rows: rows.map((r) => ({ ...r, url: `/api/admin/snapshots/${r.id}` })) });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "Could not load photos." });
  }
});

app.get("/api/admin/snapshots/:id", async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).end();
  try {
    const { rows } = await query("SELECT image FROM proctor_snapshots WHERE id = $1", [id]);
    if (!rows[0]) return res.status(404).end();
    const buf = Buffer.from(rows[0].image.replace(/^data:image\/jpeg;base64,/, ""), "base64");
    res.setHeader("Content-Type", "image/jpeg");
    res.setHeader("Cache-Control", "private, max-age=3600");
    res.send(buf);
  } catch (err) {
    console.error(err); res.status(500).end();
  }
});

// Recording: the list of parts, a part as one video file (played in the dashboard or downloaded), and delete.
app.get("/api/admin/sessions/:sid/recording", async (req, res) => {
  const sid = String(req.params.sid || "");
  if (!SID_RE.test(sid)) return res.status(400).json({ error: "Invalid session." });
  try {
    const { rows } = await query(
      `SELECT part, COUNT(*)::int AS pieces, SUM(bytes)::bigint AS bytes, MIN(created_at) AS started, MAX(created_at) AS ended, MAX(mime) AS mime
         FROM proctor_recordings WHERE session_id = $1 GROUP BY part ORDER BY part`, [sid]);
    res.json({ parts: rows.map((p) => ({ ...p, bytes: Number(p.bytes), url: `/api/admin/sessions/${sid}/recording/${p.part}` })) });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "Could not load the recording." });
  }
});

app.get("/api/admin/sessions/:sid/recording/:part", async (req, res) => {
  const sid = String(req.params.sid || ""), part = parseInt(req.params.part, 10);
  if (!SID_RE.test(sid) || !(part >= 0)) return res.status(400).end();
  try {
    const { rows } = await query("SELECT seq, mime, data FROM proctor_recordings WHERE session_id = $1 AND part = $2 ORDER BY seq", [sid, part]);
    if (!rows.length) return res.status(404).send("No recording.");
    const mime = (rows[0].mime || "video/webm").split(";")[0];
    const ext = mime.includes("mp4") ? "mp4" : "webm";
    const all = Buffer.concat(rows.map((r) => r.data));
    res.setHeader("Content-Type", mime);
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("Accept-Ranges", "none");
    if (req.query.download) res.setHeader("Content-Disposition", `attachment; filename="recording-${sid.slice(0, 8)}-part${part + 1}.${ext}"`);
    res.send(all);
  } catch (err) {
    console.error(err); res.status(500).end();
  }
});

app.delete("/api/admin/sessions/:sid/recording", async (req, res) => {
  const sid = String(req.params.sid || "");
  if (!SID_RE.test(sid)) return res.status(400).json({ error: "Invalid session." });
  try {
    const { rowCount } = await query("DELETE FROM proctor_recordings WHERE session_id = $1", [sid]);
    res.json({ deleted: rowCount });
  } catch (err) {
    console.error(err); res.status(500).json({ error: "Could not delete." });
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
function pagePath(name) {
  const inPublic = path.join(__dirname, "public", name);
  if (fs.existsSync(inPublic)) return inPublic;
  const atRoot = path.join(__dirname, name);
  if (fs.existsSync(atRoot)) return atRoot;
  return null;
}
const PAGES = {
  index: pagePath("index.html"),
  basic: pagePath("basic.html"),
  advanced: pagePath("advanced.html"),
  admin: pagePath("admin.html"),
};
console.log("Pages:", Object.entries(PAGES).map(([k, v]) => `${k}=${v || "MISSING"}`).join(" | "));

const servePage = (key) => (req, res) => PAGES[key]
  ? res.sendFile(PAGES[key], { headers: { "Cache-Control": "no-cache" } })
  : (key === "basic" || key === "advanced") && (PAGES.basic || PAGES.advanced)
    ? res.status(404).send("This module is not installed on this site.")
    : res.status(500).send(`${key}.html was not found on the server. Upload it to the "public" folder of the GitHub repo.`);

app.get(["/admin", "/admin.html"], adminLimiter, requireAdmin, servePage("admin"));
// "/" = the start page; in a single-module package (no start page) it opens that module directly.
const HOME = PAGES.index ? "index" : PAGES.basic && !PAGES.advanced ? "basic" : PAGES.advanced && !PAGES.basic ? "advanced" : "index";
app.get(["/", "/index.html"], servePage(HOME));
app.get(["/basic", "/basic.html"], servePage("basic"));
app.get(["/advanced", "/advanced.html"], servePage("advanced"));

// Any other static files (only from the public folder, if it exists)
if (fs.existsSync(path.join(__dirname, "public"))) {
  app.use(express.static(path.join(__dirname, "public"), { index: false }));
}

app.use((req, res) => res.status(404).send("Not found"));

/* ------------------------------------------------------------------ */
// Delete webcam photos older than SNAPSHOT_RETENTION_DAYS (runs at start-up and once a day).
async function cleanupSnapshots() {
  if (SNAPSHOT_RETENTION_DAYS > 0) {
    try {
      const { rowCount } = await query(`DELETE FROM proctor_snapshots WHERE taken_at < now() - make_interval(days => $1)`, [SNAPSHOT_RETENTION_DAYS]);
      if (rowCount) console.log(`Deleted ${rowCount} webcam photo(s) older than ${SNAPSHOT_RETENTION_DAYS} days.`);
    } catch (err) { console.error("Photo clean-up failed:", err.message); }
  }
  if (RECORDING_RETENTION_DAYS > 0) {
    try {
      const { rowCount } = await query(`DELETE FROM proctor_recordings WHERE created_at < now() - make_interval(days => $1)`, [RECORDING_RETENTION_DAYS]);
      if (rowCount) console.log(`Deleted ${rowCount} recording piece(s) older than ${RECORDING_RETENTION_DAYS} days.`);
    } catch (err) { console.error("Recording clean-up failed:", err.message); }
  }
}

migrate()
  .then(() => { cleanupSnapshots(); setInterval(cleanupSnapshots, 24 * 60 * 60 * 1000); })
  .then(() => app.listen(PORT, () => console.log(`Phishing quiz running on port ${PORT}`)))
  .catch((err) => { console.error("Database setup failed:", err); process.exit(1); });
