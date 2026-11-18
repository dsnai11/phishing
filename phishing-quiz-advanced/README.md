# Phishing Awareness Training — Advanced module (CISA-level) · Laxmi India Finance

5 interactive lessons + a 25-question proctored CISA/ISACA-level assessment with a **30-minute time limit**, for officers, managers, IT, audit, risk & compliance. English / हिंदी. Results are stored in a **Neon PostgreSQL** database; the app runs on **Render**.

| Page | URL | Who |
|---|---|---|
| Advanced module (CISA-level) | `https://<your-app>.onrender.com/` (also `/advanced`) | Employees |
| Admin dashboard | `https://<your-app>.onrender.com/admin` | HR / IT only (username + password) |

This package contains **only the advanced module (cisa-level)**. The other package (basic module: 15-question quiz, no time limit)
is a separate zip. Both can use the **same Neon database** — every result is tagged with its module, so either
admin dashboard shows both (use the Module filter).

---

## Proctoring

Before the quiz, the learner enters **name, Employee ID and department**, reads the rules and ticks a consent box.
The assessment then opens in **full screen**, and the page monitors and records:

| Action | Counted as a rule break |
|---|---|
| Switching tab, minimising the browser | ✔ |
| Clicking another window or app (Alt+Tab etc.) | ✔ |
| Leaving full screen (Esc) | ✔ |
| Copy / cut / paste | ✔ (blocked) |
| Right-click | ✔ (blocked) |
| Blocked shortcuts: Ctrl+C/V/X/A/P/S/U/F/O, F12, Ctrl+Shift+I/J/C | ✔ (blocked) |
| Print Screen key | ✔ |
| Opening the assessment in a second tab | ✔ |
| Reloading or reopening the page | ✔ |
| **Webcam:** no face visible for 8 seconds | ✔ (photo saved) |
| **Webcam:** more than one face for 3 seconds | ✔ (photo saved) |
| **Webcam:** camera covered / too dark for 5 seconds | ✔ (photo saved) |
| **Webcam:** camera turned off or disconnected | ✔ (must be turned back on to continue) |
| **Browser extension** changes the page (translators, Grammarly, AI helpers, injected panels) | ✔ |
| **Advanced only — microphone** muted, turned off or disconnected | ✔ |

- **2 warnings, then exit:** the 1st and 2nd rule breaks show a warning; the **3rd ends the assessment**, submits it
  automatically and records it as **FAILED** (flagged "Terminated"), whatever the score.
- Actions within 2 seconds of each other (e.g. Alt+Tab that also leaves full screen) count as **one** rule break.
- Questions **and** answer options are shuffled for every attempt. Lessons cannot be opened during the assessment.
- 30-minute timer; answers are submitted automatically when time runs out (unanswered = wrong).
  The server also flags anything submitted more than 2 minutes after the limit as "Late".
- Reloading does **not** restart the quiz: the same questions, answers so far and timer continue (and the reload counts as a rule break).
- **Every start is logged with name and Employee ID**, even if the learner closes the page and never submits.

Admin dashboard → **🔒 Integrity log** lists every started assessment (In progress / Not submitted / Submitted / Terminated),
the number of rule breaks, and an **Activity log** (🔍) with the exact time and question of each action.
The Results tab shows a **Proctoring** column (Clean / Warned / Terminated / Time up / Late) and both tabs export to CSV.

### Webcam monitoring
- The learner must turn on the webcam on the rules screen; **the Start button stays disabled until the camera
  works and a face is seen**. No camera or permission refused → they cannot start (ask IT to provide a webcam).
- A small camera preview stays at the bottom-right during the assessment. Face checks run **in the learner's
  browser** (face-api, MIT licence, files in `public/vendor/face-api/`); no video is streamed or recorded.
- **Photos** (320×240 JPEG, about 15 KB) are saved at the start, every 5 minutes, and at each face/camera problem
  — at most 60 per assessment. They appear in the admin **Activity log** (🔍) next to the timeline.
- Photos are deleted automatically after **180 days** (`SNAPSHOT_RETENTION_DAYS` on Render; `0` = keep).
  Storage guide: about 100–150 KB per attempt, so 1,000 attempts ≈ 150 MB of Neon's free 1 GB.
- The face check must load before the test can start; if it cannot (for example a network that blocks the
  files), the rules screen says so and the Start button stays disabled.
- While a problem continues, it keeps counting: no face for 8 seconds → warning 1, still no face 5 seconds later →
  warning 2, 5 seconds after that → the test ends (about 18 seconds in all). The same applies to more than one face
  and to a covered camera.

### Video + sound recording (advanced module only)
- The **whole advanced assessment is recorded**: webcam video (320×240, 15 fps) and microphone sound, from Start
  to submit. A camera **and a microphone** are required; the Start button stays disabled until both work.
  The learner sees "🔴 REC" on the camera preview and agrees to the recording on the rules screen.
- The browser sends a piece every 5 seconds, stored in Neon (`proctor_recordings`). If the page is reloaded,
  recording continues as **part 2**.
- Admin dashboard → **🔍 Activity log** → **🎥 Video + sound recording**: play, **Download** (.webm, opens in
  Chrome, Edge or VLC) or **Delete**. The storage bar at the top shows how full the database is.
- **Size:** about **20 MB per 30-minute test**. Neon's free plan holds 1 GB, so roughly **40 recordings** at a
  time. Recordings are deleted automatically after **90 days** (`RECORDING_RETENTION_DAYS`). For more, delete
  old recordings or move Neon to its paid Launch plan (same connection string).
- Recording is switched on by `record: true` in `CONFIG` of `public/advanced.html` (the basic module has `record: false`).

### Browser extensions
A web page **cannot block or switch off extensions** — browsers do not allow it. The assessment therefore:
- **detects** extensions that change the page (translators, Grammarly, AI helpers, injected panels or buttons,
  `chrome-extension://` resources): the Start button is blocked until they are turned off, and any that appear
  during the assessment count as a rule break;
- tells learners that an Incognito / InPrivate window normally runs without extensions.

To truly switch extensions off, IT should apply the Chrome / Edge policy `ExtensionInstallBlocklist = *` to the
exam PCs — see the separate **IT guide** document. Extensions that never touch the page (e.g. a side panel) can
only be stopped by that policy.

**What browser monitoring cannot do:** it cannot see a second device held out of camera view,  and it cannot stop operating-system screenshots on every computer — it records
the Print Screen key where the browser can see it. Use a supervised room if you need that level of control.
Works best on a laptop/desktop with Chrome or Edge; iPhone Safari does not support full screen (the attempt is
still monitored and marked "Full screen: No").

---

---

## Uploading to GitHub
Upload **everything in this folder** to the repository, keeping the folders:
`server.js`, `db.js`, `quizKey.js`, `package.json`, `render.yaml`, `.gitignore`, `.env.example`, `README.md`,
`public/advanced.html`, `public/admin.html`, and the whole **`public/vendor/`** folder (face-detection library —
drag the `vendor` folder into `public/` on GitHub). Never upload a `.env` file or `node_modules`.

If this replaces an existing Render service, also delete any other `index.html`, `basic.html` or `advanced.html`
left in the repo so `/` opens this module. In the Render logs check for `Pages: … advanced=…/public/advanced.html` and `Database ready`.

---

## Deploy: Neon (database) + Render (app) — about 15 minutes

### Step 1 — Create the Neon database
1. Sign up / log in at <https://console.neon.tech> (free, no credit card).
2. **New Project** → name it `phishing-quiz-advanced` (or reuse the Neon project you already have) → Postgres version: latest →
   **Region: AWS Asia Pacific (Singapore)** (closest to India and to Render's Singapore region) → **Create**.
3. On the project dashboard click **Connect**. Keep the database `neondb`, turn **Connection pooling ON**,
   and copy the connection string. It looks like:
   `postgresql://neondb_owner:xxxx@ep-xxxx-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require`
4. Keep it private — it contains the database password.

You don't need to create any table: the app creates `quiz_attempts` automatically on first start.

### Step 2 — Put the code on GitHub
1. Create a new **private** repository on GitHub (e.g. `phishing-quiz-advanced`).
2. Upload all files from this zip (keep the folder structure; `node_modules` is not needed).

### Step 3 — Deploy the app on Render (Blueprint)
1. Log in to <https://dashboard.render.com> → **New +** → **Blueprint**.
2. Connect GitHub and choose your repository. Render reads `render.yaml` and shows the web service **phishing-quiz-advanced**.
3. When asked, enter:
   - **DATABASE_URL** — the Neon connection string from Step 1
   - **ADMIN_PASSWORD** — a strong password for the dashboard (min. 8 characters)
   - **ALLOWED_ORIGINS** — leave blank (only needed for the LMS option below)
4. Click **Apply**. In the **Logs** you should see `Database ready (SSL, ep-xxxx…neon.tech)`.
5. Open the URL Render shows (e.g. `https://phishing-quiz-advanced.onrender.com`) — the training loads.
6. Open `/admin` and sign in with **admin** / your password.

**Manual alternative (no Blueprint):** Render → **New + → Web Service** → connect the repo →
Runtime **Node**, Build `npm install`, Start `node server.js`, Region **Singapore** →
add environment variables `DATABASE_URL` (Neon string), `ADMIN_USER=admin`, `ADMIN_PASSWORD`, `PASS_MARK=80`.

### See the data directly in Neon
Neon Console → your project → **Tables** → `quiz_attempts` to browse rows, or **SQL Editor**, e.g.:

```sql
-- Latest attempt of every employee
SELECT DISTINCT ON (emp_id) emp_id, full_name, department, score, passed, created_at
FROM quiz_attempts ORDER BY emp_id, created_at DESC;

-- Employees who have not passed yet
SELECT emp_id, MAX(full_name) AS name, MAX(score) AS best_score
FROM quiz_attempts GROUP BY emp_id HAVING NOT BOOL_OR(passed);
```

### Good to know about the free plans
- **Neon Free:** no expiry date and no credit card. Limits per project: 1 GB storage
  (tens of thousands of quiz attempts use only a few MB) and 100 compute-hours a month.
  The database "sleeps" after 5 minutes without activity and wakes automatically on the next request
  (the app waits for it, so learners don't see an error). For guaranteed backups and longer
  restore history, consider Neon's paid Launch plan — upgrading keeps the same connection string.
- **Render Free web service:** sleeps after 15 minutes without visitors and takes about a minute to
  wake for the first person. Change `plan: free` to `starter` in `render.yaml` for always-on.

---

## What gets stored

**`quiz_attempts`** — one row per submitted attempt: `module`, `emp_id`, `full_name`, `department`, `language`,
`score`, `correct_count`, `total_questions`, `passed`, `answers`, `duration_sec`, `attempt_no`,
`session_id`, `violations` (rule breaks), `proctor_status`, `ip_address`, `user_agent`, `created_at`.

**`proctor_sessions`** — one row per started assessment: identity, `status`, `violations`, `events`
(timeline of every action), `fullscreen`, `camera`, `face_check`, `started_at`, `ended_at`, linked `attempt_id`.

**`proctor_snapshots`** — webcam photos: `session_id`, `reason` (start / periodic / no_face / multiple_faces /
camera_blocked), `question`, `image`, `taken_at`. Deleted automatically after `SNAPSHOT_RETENTION_DAYS`.

Both tables are created/updated automatically when the app starts. Scores are calculated on the server
(`quizKey.js`), so nobody can fake a score by editing the page.

Older rows: results from the earlier 10-question basic quiz are kept (`total_questions = 10`) and show
"—" under Proctoring because they were taken before proctoring existed.

---

## Customising

| What | Where |
|---|---|
| Reporting contact shown to learners | `CONFIG.reportTo` in `public/basic.html` and `public/advanced.html` |
| Pass mark | `CONFIG.passMark` in each page **and** `PASS_MARK` / `PASS_MARK_ADVANCED` on Render |
| Time limit | `CONFIG.timeLimitMin` in each page **and** `TIME_LIMIT_BASIC_MIN` / `TIME_LIMIT_ADVANCED_MIN` on Render (defaults 0 and 30) |
| Number of warnings | `CONFIG.maxWarnings` in each page **and** `MAX_WARNINGS` on Render (default 2) |
| Shuffle questions/options | `CONFIG.shuffle` in each page |
| Webcam on/off | `CONFIG.camera` in each page (`true` = required) |
| Face-check timings, photo interval | `FACE` near the webcam code in each page (`noFaceSec` 8, `multiSec` 3, `darkSec` 5, `snapEveryMin` 5) |
| Photo retention | `SNAPSHOT_RETENTION_DAYS` on Render (default 180) |
| Recording retention | `RECORDING_RETENTION_DAYS` on Render (default 90) |
| Quiz questions | `QUIZ` array in the page — **also update that module's `key` in `quizKey.js`** (original order) |
| Certificate logo | the `cert-logo` image in each page and the start page (embedded as base64) |
| Admin username / password | `ADMIN_USER` / `ADMIN_PASSWORD` on Render → Environment |

## Security & privacy notes
- The admin dashboard and all `/api/admin/*` endpoints require the admin username + password (HTTP Basic Auth over HTTPS).
- Learners agree to monitoring, **webcam video and microphone sound recording** on the rules screen before starting.
- Webcam photos of employees are personal data: keep the retention period as short as your policy allows,
  restrict the admin password to the people who review integrity cases, and check the notice/consent wording
  with your compliance team.
- Submissions are validated and rate-limited; text is cleaned before saving; CSV exports are protected against spreadsheet formula injection.
- The Neon connection string is a secret: keep it only in Render's environment variables / your local `.env` (never in GitHub).
- Employee names, IDs and activity logs are personal data — share the admin password only with the people responsible for training records.

## Using it with your LMS

**Option A — Link (simplest).** Add the Render URL as a web link / URL activity in the LMS.
Use `https://<your-app>.onrender.com/`. Results are stored in your Neon database and seen on `/admin`.

**Option B — Upload as SCORM and still save to Render.** The LMS tracks completion *and* Render keeps the results.
1. In `public/advanced.html`, find `CONFIG` near the top of the script and set
   `apiBase: "https://<your-app>.onrender.com"`.
2. Copy that page, renamed to `index.html`, into the `lms-scorm/` folder (next to `imsmanifest.xml`) and zip **the two files** (not the folder).
3. Upload the zip to the LMS as a SCORM 1.2 package.
4. In Render, set `ALLOWED_ORIGINS` to your LMS website address, e.g. `https://lms.yourcompany.com`
   (comma-separate several). Redeploy.

When launched from an LMS, the learner's name and LMS user ID are pre-filled automatically.

---

> Proctoring needs the page to run in a normal browser tab. Some LMS players show courses inside a frame that blocks full screen; in that case use Option A (link).

## Project structure
```
phishing-quiz-advanced/
├── server.js          Express server: page, proctoring API, results API, admin API, CSV exports
├── db.js              Neon / PostgreSQL connection + automatic table setup
├── quizKey.js         Answer keys, pass marks, time limits, warnings (server-side scoring)
├── package.json
├── render.yaml        Render Blueprint (web service; database is on Neon)
├── .env.example       Settings for local development
├── public/
│   ├── advanced.html    Advanced module (CISA-level) (opens at /)
│   ├── admin.html     Results dashboard + integrity log + webcam photos
│   └── vendor/face-api/  Face-detection library + model (MIT licence)
└── lms-scorm/imsmanifest.xml
```
