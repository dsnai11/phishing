// Integrity audit of an assessment attempt: looks through everything recorded for one session
// (actions, device details, photos, recording, answers, network) and lists anything that suggests
// someone tried to get around the proctoring.
const { MODULES } = require("./quizKey");
let QUIZ_TEXT = {};
try { QUIZ_TEXT = require("./quizText"); } catch (e) { /* question text is optional */ }
// Question papers: question text and answers come from the server-side bank (phishBank.js).
// Attempts made before question papers existed are checked against the old fixed key (legacyKey + quizText.js).
const BANK_BY_ID = new Map();
try { const b = require("./phishBank"); for (const q of [...b.basic, ...Object.values(b.advanced).flat()]) BANK_BY_ID.set(q.id, q); } catch (e) { /* bank optional */ }

const DEVTOOL_KEYS = /^(F12|(Ctrl\+|Cmd\+)+Shift\+[IJCK]|(Ctrl\+|Cmd\+)U)$/i;

// level: high = likely attempt to cheat or bypass; medium = needs a look; info = context only
const RULES = {
  devtools_open:   ["high",   "Opened browser developer tools (Inspect)"],
  automation:      ["high",   "Browser was controlled by automation software"],
  virtual_camera:  ["high",   "Virtual camera / microphone software in use (can feed fake video)"],
  multiple_faces:  ["high",   "More than one person on camera"],
  multiple_tabs:   ["high",   "Assessment opened in a second tab or window"],
  extension:       ["high",   "Browser extension changed the page"],
  camera_off:      ["high",   "Camera turned off or disconnected during the test"],
  mic_off:         ["high",   "Microphone muted, turned off or disconnected"],
  paste:           ["high",   "Tried to paste text"],
  no_face:         ["medium", "Face not visible to the camera"],
  camera_blocked:  ["medium", "Camera covered or too dark"],
  tab_hidden:      ["medium", "Switched tab or minimised the browser"],
  window_blur:     ["medium", "Left the assessment window (another app or window)"],
  fullscreen_exit: ["medium", "Exited full screen"],
  copy:            ["medium", "Tried to copy text"],
  cut:             ["medium", "Tried to cut text"],
  print_screen:    ["medium", "Tried to take a screenshot"],
  right_click:     ["medium", "Right-clicked (opens the menu that contains Inspect)"],
  page_reload:     ["medium", "Reloaded or reopened the page during the test"],
  leave_attempt:   ["medium", "Tried to close or leave the page"],
  extended_display:["medium", "More than one screen connected"],
  recording_failed:["medium", "Recording could not start"],
  recording_gap:   ["medium", "Part of the recording could not be uploaded"],
  face_check_unavailable: ["medium", "Automatic face check was not available"],
  fullscreen_unavailable: ["medium", "Full screen was not available"],
};

const LEVEL_ORDER = { high: 0, medium: 1, info: 2 };

function browserName(ua) {
  ua = String(ua || "");
  const b = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "Unknown browser";
  const v = (ua.match(/(?:Edg|OPR|Chrome|Firefox|Version)\/(\d+)/) || [])[1];
  const os = /Windows NT 10/.test(ua) ? "Windows 10/11" : /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android"
    : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "Unknown OS";
  const headless = /HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium/i.test(ua);
  return { label: `${b}${v ? " " + v : ""} on ${os}`, headless, mobile: /Mobi|Android|iPhone|iPad/.test(ua) };
}

/**
 * @param s        proctor_sessions row (with events)
 * @param attempt  quiz_attempts row or null
 * @param extra    { photos: [{reason, taken_at}], recParts: [{part, pieces, bytes, first, last}], sameIp: [{emp_id, full_name, started_at}] }
 */
function buildAudit(s, attempt, extra = {}) {
  const m = MODULES[s.module] || { key: [], timeLimitMin: 0, name: s.module };
  const events = (Array.isArray(s.events) ? s.events : []).slice().sort((a, b) => String(a.at).localeCompare(String(b.at)));
  const flags = new Map();
  const addFlag = (key, level, title, detail, at) => {
    const f = flags.get(key) || { level, title, count: 0, details: [], times: [] };
    f.count++; if (detail && f.details.length < 6 && !f.details.includes(detail)) f.details.push(detail); if (at) f.times.push(at);
    flags.set(key, f);
  };

  // 1. Every recorded action
  for (const e of events) {
    if (e.type === "shortcut") {
      if (DEVTOOL_KEYS.test(e.detail || "")) addFlag("devtools_key", "high", "Pressed a key that opens developer tools / page source (blocked)", e.detail, e.at);
      else addFlag("shortcut", "medium", "Used a blocked keyboard shortcut", e.detail, e.at);
      continue;
    }
    const r = RULES[e.type];
    if (r) addFlag(e.type, r[0], r[1], e.detail && !/same incident|while leaving/.test(e.detail) ? e.detail : null, e.at);
  }
  if (events.length >= 400) addFlag("log_full", "medium", "Activity log reached its 400-entry limit (later actions not stored)", null);

  // 2. Device and network
  const ua = browserName(s.user_agent);
  if (ua.headless) addFlag("headless", "high", "Test taken in an automated (headless) browser", ua.label);
  if (ua.mobile) addFlag("mobile", "info", "Test taken on a phone or tablet", ua.label);
  if (attempt) {
    if (attempt.ip_address && s.ip_address && attempt.ip_address !== s.ip_address)
      addFlag("ip_change", "high", "Result was submitted from a different network address than the one that started the test", `${s.ip_address} → ${attempt.ip_address}`);
    if (attempt.user_agent && s.user_agent && attempt.user_agent !== s.user_agent)
      addFlag("ua_change", "high", "Result was submitted from a different browser/device than the one that started the test", `${ua.label} → ${browserName(attempt.user_agent).label}`);
    if (attempt.proctor_status === "unverified")
      addFlag("unverified", "high", "Result was submitted without a monitored session", null);
    if (attempt.proctor_status === "late")
      addFlag("late", "medium", "Result arrived after the time limit", null);
  }
  if ((extra.sameIp || []).length) {
    const f = { level: "info", title: "Other employees started a test from the same network address within 2 hours (normal on a shared office connection)",
      count: extra.sameIp.length, details: [extra.sameIp.map((o) => `${o.emp_id} ${o.full_name}`).join(", ")], times: [] };
    flags.set("same_ip", f);
  }

  // 3. Camera and recording
  if (s.camera === false) addFlag("no_camera", "high", "Camera was not on for this test", null);
  if (s.camera && s.face_check === false) addFlag("no_face_check", "medium", "Automatic face check did not run (photos only)", null);
  const started = new Date(s.started_at).getTime();
  const ended = s.ended_at ? new Date(s.ended_at).getTime() : s.last_event_at ? new Date(s.last_event_at).getTime() : null;
  const durationSec = ended ? Math.max(0, Math.round((ended - started) / 1000)) : null;
  const recPieces = (extra.recParts || []).reduce((n, p) => n + Number(p.pieces || 0), 0);
  const recSec = recPieces * 5;
  let recCoverage = null;
  if (s.recording) {
    if (!recPieces) addFlag("rec_missing", "high", "Recording was required but nothing was stored", null);
    else if (durationSec && durationSec > 60) {
      recCoverage = Math.min(100, Math.round((recSec / durationSec) * 100));
      if (recCoverage < 80) addFlag("rec_short", "medium", `Recording covers only about ${recCoverage}% of the test time`, `${Math.round(recSec / 60)} of ${Math.round(durationSec / 60)} min`);
    }
  }
  const photos = extra.photos || [];
  if (s.camera && durationSec && durationSec > 6 * 60 && photos.filter((p) => p.reason === "periodic").length === 0)
    addFlag("no_periodic", "medium", "No 5-minute webcam photos were stored", null);

  // 4. Answers and timing
  const paperIds = Array.isArray(s.paper) ? s.paper : attempt && Array.isArray(attempt.paper) ? attempt.paper : null;
  const keyList = paperIds ? paperIds.map((id) => (BANK_BY_ID.get(id) || {}).a) : (m.legacyKey || m.key || []);
  const text = paperIds ? paperIds.map((id) => { const q = BANK_BY_ID.get(id); return q ? { q: q.q.en, o: q.o.en } : null; }) : (QUIZ_TEXT[s.module] || []);
  const answers = attempt && Array.isArray(attempt.answers) ? attempt.answers : attempt && typeof attempt.answers === "string" ? JSON.parse(attempt.answers) : null;
  const answeredAt = {};
  let prevT = null;
  for (const e of events) {
    if (e.type === "session_start" || e.type === "page_reload") prevT = new Date(e.at).getTime();
    if (e.type === "answered") {
      const n = parseInt(String(e.detail || "").replace(/^Q/, ""), 10);
      const t = new Date(e.at).getTime();
      if (n > 0) answeredAt[n] = { at: e.at, sec: prevT ? Math.round((t - prevT) / 1000) : null };
      prevT = t;
    }
  }
  const qRows = keyList.map((k, i) => {
    const a = answers ? answers[i] : undefined;
    const t = answeredAt[i + 1];
    return {
      n: i + 1, qid: paperIds ? paperIds[i] : null, question: text[i] ? text[i].q : null,
      chosen: Number.isInteger(a) && a >= 0 ? a : null, chosenText: Number.isInteger(a) && a >= 0 && text[i] ? text[i].o[a] : null,
      correct: k, correctText: text[i] ? text[i].o[k] : null,
      right: Number.isInteger(a) && a === k, seconds: t ? t.sec : null,
    };
  });
  const timed = qRows.filter((q) => q.seconds !== null);
  const fastOnes = timed.filter((q) => q.seconds < 5);
  if (fastOnes.length >= 3) addFlag("fast_answers", "medium", `${fastOnes.length} questions answered in under 5 seconds`, fastOnes.map((q) => `Q${q.n}: ${q.seconds}s`).join(", "));
  if (attempt && attempt.duration_sec != null && keyList.length && attempt.duration_sec < keyList.length * 8)
    addFlag("too_fast", "medium", `Whole test finished in ${Math.round(attempt.duration_sec)} s (under 8 s per question)`, null);
  if (attempt && answers) {
    const blank = answers.filter((a) => !(Number.isInteger(a) && a >= 0)).length;
    if (blank) addFlag("blank", "info", `${blank} question(s) left unanswered`, null);
  }

  const list = [...flags.entries()].map(([key, f]) => ({ key, ...f, times: f.times.slice(0, 20) }))
    .sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level] || b.count - a.count);
  const high = list.filter((f) => f.level === "high").length, medium = list.filter((f) => f.level === "medium").length;
  const verdict = high ? { level: "high", text: "Signs of an attempt to get around the proctoring — watch the recording at the times listed" }
    : medium ? { level: "medium", text: "Some rule breaks or gaps — review the items below" }
    : { level: "ok", text: "No signs of an attempt to get around the proctoring" };

  const envEvent = events.find((e) => e.type === "environment");
  const newSignals = events.some((e) => e.type === "environment" || e.type === "answered");
  return {
    sessionId: s.id, module: s.module, moduleName: m.name, empId: s.emp_id, name: s.full_name, department: s.department,
    language: s.language, status: s.status, paperCode: s.paper_code || null, startedAt: s.started_at, endedAt: s.ended_at, durationSec,
    timeLimitMin: m.timeLimitMin, violations: s.violations,
    result: attempt ? { id: attempt.id, score: attempt.score, correct: attempt.correct_count, total: attempt.total_questions,
      passed: attempt.passed, proctorStatus: attempt.proctor_status, attemptNo: attempt.attempt_no, savedAt: attempt.created_at } : null,
    device: { browser: ua.label, userAgent: s.user_agent, ip: s.ip_address, submitIp: attempt ? attempt.ip_address : null,
      environment: envEvent ? envEvent.detail : null },
    camera: { on: s.camera, faceCheck: s.face_check, photos: photos.length, recording: !!s.recording, recordedSec: recSec, recCoverage,
      recParts: (extra.recParts || []).length },
    verdict, flags: list, questions: qRows, answersStored: !!answers, newSignals,
    events: events.map((e) => ({ at: e.at, type: e.type, counted: !!e.counted, detail: e.detail || null, q: e.q || null })),
  };
}

module.exports = { buildAudit, browserName };
