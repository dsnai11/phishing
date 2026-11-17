# Phishing Awareness Training 

Basic Quiz URL: https://phishing-quiz-3di2.onrender.com

Advanced Quiz URL: https://phishing-quiz-advanced.onrender.com

Interactive, bilingual phishing awareness training with **two proctored assessments**.
Each module is a separate app in its own folder and runs as its own **Render** web service.
Both save results to the same **Neon PostgreSQL** database.

| Module | Folder | What learners get | For |
|---|---|---|---|
| **Basic** | `phishing-quiz-basic/` | 5 lessons + 15-question quiz, **no time limit** | All employees |
| **Advanced (CISA-level)** | `phishing-quiz-advanced/` | Same 5 lessons + 25-question CISA/ISACA-level assessment, **30-minute limit** | Officers, managers, IT, audit, risk & compliance |

Each service opens its module at its main address (`https://<service>.onrender.com/`). The admin dashboard is
at `/admin` on either service, and it shows results from **both** modules (use the Module filter).

---

## Repository layout

```
<repo>/
├── README.md                     ← this file
├── phishing-quiz-basic/
│   ├── server.js                 Express server: page, proctoring API, results API, admin API, CSV exports
│   ├── db.js                     Neon connection + automatic table setup
│   ├── quizKey.js                Answer keys, pass marks, time limits, warnings (server-side scoring)
│   ├── package.json
│   ├── render.yaml               (not used when the service is set up by hand — see below)
│   ├── .env.example              Settings for running on your own computer
│   ├── public/
│   │   ├── basic.html            The basic module (opens at /)
│   │   ├── admin.html            Results dashboard + integrity log + webcam photos
│   │   └── vendor/face-api/      Face-detection library + model (MIT licence)
│   └── lms-scorm/imsmanifest.xml
└── phishing-quiz-advanced/
    └── … same files, with public/advanced.html instead of basic.html
```

The two folders are independent: each has its own `server.js` and `package.json`. Render only redeploys a
service when files inside **its own** folder change.

---

## Deployment

### 1. Neon (database)
1. Go to <https://console.neon.tech> and click **New Project** (or reuse your existing one). Choose region **AWS Asia Pacific (Singapore)**.
2. Click **Connect**, turn **Connection pooling ON**, and copy the connection string
   (`postgresql://…-pooler…neon.tech/neondb?sslmode=require`).
3. You don't need to create any tables. Each app creates and updates its tables automatically when it starts.

### 2. GitHub
Both folders sit at the top level of this repository. To update a module, open its folder on github.com and use
**Add file → Upload files** (drag folders onto the page). A file with the same name is replaced.
Never upload a `.env` file or a `node_modules` folder.

### 3. Render: one web service per module

| Setting | Basic service | Advanced service |
|---|---|---|
| Type | Web Service | Web Service |
| Repository / branch | this repo · `main` | this repo · `main` |
| **Root Directory** | `phishing-quiz-basic` | `phishing-quiz-advanced` |
| Language | Node | Node |
| Build Command | `npm install` | `npm install` |
| Start Command | `node server.js` | `node server.js` |
| Health Check Path | `/healthz` | `/healthz` |
| Region | Singapore | Singapore |
| Instance type | Starter recommended (Free sleeps after 15 min idle) | Starter recommended |

**Environment variables** (same for both services):

| Key | Value | Required |
|---|---|---|
| `DATABASE_URL` | Neon connection string (the **same** for both) | ✔ |
| `ADMIN_USER` | `admin` | ✔ |
| `ADMIN_PASSWORD` | Strong password, at least 8 characters | ✔ |
| `NODE_VERSION` | `20` | ✔ |
| `PASS_MARK` / `PASS_MARK_ADVANCED` | Pass mark in % (default 80) | optional |
| `TIME_LIMIT_BASIC_MIN` / `TIME_LIMIT_ADVANCED_MIN` | Time limits (defaults 0 and 30) | optional |
| `MAX_WARNINGS` | Warnings before the test ends (default 2) | optional |
| `SNAPSHOT_RETENTION_DAYS` | Days to keep webcam photos (default 180; 0 = keep) | optional |
| `ALLOWED_ORIGINS` | LMS website address, if the page is uploaded to an LMS | optional |

When you set or change the Root Directory, Render asks you to confirm the build and start commands. Click **Update Fields**.

### 4. Check it worked
- **Logs** should show `Pages: index=MISSING | basic=…` (or `advanced=…`), then `Database ready (SSL, …neon.tech)`
  and `Phishing quiz running`. `index=MISSING` is expected, because each service opens its module directly.
- `https://<service>.onrender.com/healthz` → `{"ok":true}`
- The basic site shows 15 questions with no timer; the advanced site shows 25 questions and a 30-minute timer.
- On a laptop with a webcam: start the quiz, allow the camera, and confirm that the rules screen says "Your face is clearly visible".
- `/admin` (username and password) shows results from both modules.

---

## Proctoring (both modules)

The learner enters **name, Employee ID and department**, reads the rules, turns on the webcam and ticks a
consent box. The assessment then opens in **full screen**.

| Action | Counted as a rule break |
|---|---|
| Switching tab / minimising the browser | ✔ |
| Clicking another window or app | ✔ |
| Leaving full screen | ✔ |
| Copy / cut / paste, right-click | ✔ (blocked) |
| Blocked shortcuts (Ctrl+C/V/X/A/P/S/U/F/O, F12, Ctrl+Shift+I/J/C) and Print Screen | ✔ |
| Opening the assessment in a second tab | ✔ |
| Reloading / reopening the page | ✔ |
| **Webcam:** no face visible for 8 s | ✔ + photo |
| **Webcam:** more than one face for 3 s | ✔ + photo |
| **Webcam:** camera covered or too dark for 5 s | ✔ + photo |
| **Webcam:** camera turned off or disconnected | ✔ (must be turned back on to continue) |
| **Browser extension** changes the page (translators, Grammarly, AI helpers, injected panels) | ✔ |

- **2 warnings, then exit:** the 1st and 2nd rule breaks show a warning. The **3rd ends the assessment**, which is
  submitted automatically and recorded as **FAILED** ("Terminated") whatever the score.
- Actions within 2 seconds of each other count as one rule break.
- Questions and answer options are shuffled for every attempt. Learners answer and press **Save & next**: they
  can't go back, and correct answers and explanations appear **only after submitting**.
- Reloading doesn't restart the test. The same questions, answers so far and timer continue.
- **Every start is logged with name and Employee ID**, even if the learner closes the page and never submits.

**Webcam:** the Start button stays disabled until the camera works and a face is seen. Face checks run in the
learner's browser. No video or audio is recorded or sent. Photos (320×240 JPEG, about 15 KB) are saved at the
start, every 5 minutes and at each problem, with at most 60 per attempt. They are deleted automatically after
`SNAPSHOT_RETENTION_DAYS`. Storage is roughly 150 MB per 1,000 attempts, within Neon's free 1 GB.

**Extensions:** a web page **cannot block or switch off browser extensions**. The page detects extensions that change it,
blocks the start until they are off, and counts new ones during the test. To truly switch extensions off on
exam PCs, IT applies the Chrome/Edge policy `ExtensionInstallBlocklist = *` (see the separate IT guide).
An Incognito / InPrivate window normally runs without extensions.

**Limits:** browser monitoring cannot see a second device held out of camera view, cannot hear anyone, and
cannot stop operating-system screenshot tools on every PC. iPhone Safari has no full screen. Use a laptop or desktop
with Chrome or Edge.

---

## Admin dashboard (`/admin`)

- **Results** tab: every submitted attempt, with score, PASSED/FAILED, **Proctoring** status
  (Clean / Warned / Terminated / Time up / Late), rule-break count and attempt number. You can show every attempt,
  the latest per employee or the best per employee, and download a CSV that opens in Excel with Hindi names intact.
- **🔒 Integrity log** tab: every started assessment (In progress / Not submitted / Submitted / Terminated),
  with rule breaks, camera status and photo count. The CSV export includes each rule break.
- **🔍 Activity log**: timeline of each action (time, question number) plus the webcam photos.
  Photos taken because of a problem are outlined in red.

### Data in Neon
| Table | Contents |
|---|---|
| `quiz_attempts` | One row per submitted attempt: module, Employee ID, name, department, language, score, answers, time taken, rule breaks, proctoring status |
| `proctor_sessions` | One row per started assessment: identity, status, rule breaks, full timeline of actions, camera / full-screen status |
| `proctor_snapshots` | Webcam photos (start / every 5 min / no face / multiple faces / camera covered) |

Useful queries (Neon → **SQL Editor**):
```sql
-- Latest attempt per employee and module
SELECT DISTINCT ON (module, emp_id) module, emp_id, full_name, score, passed, proctor_status, created_at
FROM quiz_attempts ORDER BY module, emp_id, created_at DESC;

-- Employees who have not passed a module yet
SELECT module, emp_id, MAX(full_name) AS name, MAX(score) AS best_score
FROM quiz_attempts GROUP BY module, emp_id HAVING NOT BOOL_OR(passed);
```

---

## Customising

| What | Where (in the module's folder) |
|---|---|
| Questions | `QUIZ` in `public/basic.html` / `public/advanced.html`, **and** that module's `key` in `quizKey.js` (original order) |
| Pass mark, time limit, warnings | `CONFIG` near the top of the page **and** the matching environment variable on Render |
| Webcam on/off | `CONFIG.camera` in the page |
| Face-check timings, photo interval | `FACE` in the page (`noFaceSec` 8, `multiSec` 3, `darkSec` 5, `snapEveryMin` 5) |
| Reporting contact shown to learners | `CONFIG.reportTo` in the page |
| Certificate logo | the `cert-logo` image in the page (embedded) |

If you change something shared, such as `server.js`, make the same change in **both** folders.

## Security & privacy
- The admin dashboard and all `/api/admin/*` endpoints require the admin username and password (over HTTPS).
- Scores are calculated on the server, so editing the page cannot fake a score.
- Learners consent to monitoring **and webcam photos** before starting. Photos are personal data: keep the
  retention period as short as your policy allows, share the admin password only with the people who review
  integrity cases, and check the notice and consent wording with your compliance team.
- The Neon connection string is a secret. Keep it only in Render's environment variables, never in GitHub.

## Run locally (optional)
Requires Node.js 20+. In either folder:
```bash
npm install
cp .env.example .env      # set DATABASE_URL and ADMIN_PASSWORD
npm run dev               # http://localhost:3000  and  /admin
```
