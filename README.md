# Phishing Awareness Training (English / हिंदी) — with Results Database


LIVE URL : https://phishing-quiz-3di2.onrender.com/

An interactive, bilingual phishing awareness course with a 10-question final quiz.
Before the quiz, every learner enters **Full name, Employee ID and (optionally) Department**.
When they finish, the attempt is saved in a **Neon PostgreSQL** database (the app itself runs on **Render**), and HR / IT can view,
filter and download all results from a password-protected **admin dashboard**.

| Page | URL | Who |
|---|---|---|
| Training + quiz | `https://<your-app>.onrender.com/` | All employees |
| Admin dashboard | `https://<your-app>.onrender.com/admin` | HR / IT only (username + password) |
| CSV export | button on the dashboard | HR / IT only |

---

## What gets stored

Table `quiz_attempts` (created automatically on first start):

| Column | Meaning |
|---|---|
| `emp_id` | Employee ID (stored in UPPER CASE) |
| `full_name` | Name as entered (Hindi or English) |
| `department` | Department / branch (optional) |
| `language` | `en` or `hi` — language used during the quiz |
| `score` | Percentage (0–100) |
| `correct_count`, `total_questions` | e.g. 9 / 10 |
| `passed` | true / false against the pass mark |
| `answers` | The option chosen for each question (for audit) |
| `duration_sec` | Time taken on the quiz |
| `attempt_no` | 1st, 2nd, 3rd… attempt by that Employee ID |
| `ip_address`, `user_agent` | For audit |
| `created_at` | Submission time |

**The score is calculated on the server** (`quizKey.js`), so nobody can fake a score by editing the page.

The dashboard can show **every attempt**, the **latest attempt per employee**, or the **best attempt per employee**.
It can also search by Employee ID, name or department, filter by Passed / Failed and date range, delete test entries, and **download CSV** (opens in Excel with Hindi names shown correctly).

---

## Deploy: Neon (database) + Render (app) — about 15 minutes

### Step 1 — Create the Neon database
1. Sign up / log in at <https://console.neon.tech> (free, no credit card).
2. **New Project** → name it `phishing-quiz` → Postgres version: latest →
   **Region: AWS Asia Pacific (Singapore)** (closest to India and to Render's Singapore region) → **Create**.
3. On the project dashboard click **Connect**. Keep the database `neondb`, turn **Connection pooling ON**,
   and copy the connection string. It looks like:
   `postgresql://neondb_owner:xxxx@ep-xxxx-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require`
4. Keep it private — it contains the database password.

You don't need to create any table: the app creates `quiz_attempts` automatically on first start.

### Step 2 — Put the code on GitHub
1. Create a new **private** repository on GitHub (e.g. `phishing-quiz`).
2. Upload all files from this zip (keep the folder structure; `node_modules` is not needed).

### Step 3 — Deploy the app on Render (Blueprint)
1. Log in to <https://dashboard.render.com> → **New +** → **Blueprint**.
2. Connect GitHub and choose your repository. Render reads `render.yaml` and shows the web service **phishing-quiz**.
3. When asked, enter:
   - **DATABASE_URL** — the Neon connection string from Step 1
   - **ADMIN_PASSWORD** — a strong password for the dashboard (min. 8 characters)
   - **ALLOWED_ORIGINS** — leave blank (only needed for the LMS option below)
4. Click **Apply**. In the **Logs** you should see `Database ready (SSL, ep-xxxx…neon.tech)`.
5. Open the URL Render shows (e.g. `https://phishing-quiz.onrender.com`) — the training loads.
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

## Run it on your own computer (optional)

Needs Node.js 20+.

```bash
npm install
cp .env.example .env        # paste your Neon DATABASE_URL and set ADMIN_PASSWORD
npm run dev                 # http://localhost:3000  and  http://localhost:3000/admin
```

Tip: in Neon you can create a **branch** (e.g. `dev`) of the database and use its connection string
locally, so testing never touches the real results.

---

## Using it with your LMS

**Option A — Link (simplest).** Add the Render URL as a web link / URL activity in the LMS.
Results are stored in your Neon database and seen on `/admin`.

**Option B — Upload as SCORM and still save to Render.** The LMS tracks completion *and* Render keeps the results.
1. In `public/index.html`, find `CONFIG` near the top of the script and set
   `apiBase: "https://<your-app>.onrender.com"`.
2. Copy that `index.html` into the `lms-scorm/` folder (next to `imsmanifest.xml`) and zip **the two files** (not the folder).
3. Upload the zip to the LMS as a SCORM 1.2 package.
4. In Render, set `ALLOWED_ORIGINS` to your LMS website address, e.g. `https://lms.yourcompany.com`
   (comma-separate several). Redeploy.

When launched from an LMS, the learner's name and LMS user ID are pre-filled automatically.

---

## Customising

| What | Where |
|---|---|
| Reporting contact shown to learners | `CONFIG.reportTo` in `public/index.html` |
| Pass mark | `CONFIG.passMark` in `public/index.html` **and** `PASS_MARK` on Render |
| Quiz questions | `QUIZ` array in `public/index.html` — **also update `ANSWER_KEY` in `quizKey.js`** (same order) |
| Admin username / password | `ADMIN_USER` / `ADMIN_PASSWORD` on Render → Environment |
| Employee ID format | regex in `startQuiz()` (index.html) and in `server.js` — currently letters, numbers and `- _ / .`, up to 30 characters |

## Security notes
- The admin dashboard and all `/api/admin/*` endpoints require the admin username + password (HTTP Basic Auth over HTTPS).
- Submissions are validated and rate-limited; text is cleaned before saving; CSV export is protected against spreadsheet formula injection.
- The Neon connection string is a secret: keep it only in Render's environment variables / your local `.env` (never in GitHub). Connections use SSL with certificate verification. For extra protection, Neon's paid plans offer IP Allow lists.
- Employee names and IDs are personal data — share the admin password only with the people responsible for training records, and change it if someone leaves the role.

## Project structure
```
phishing-quiz-app/
├── server.js          Express server: pages, save API, admin API, CSV export
├── db.js              Neon / PostgreSQL connection (SSL, wake-up retry) + automatic table creation
├── quizKey.js         Correct answers & pass mark (server-side scoring)
├── package.json
├── render.yaml        Render Blueprint (web service; database is on Neon)
├── .env.example       Settings for local development
├── public/
│   ├── index.html     The bilingual training + quiz (also works as SCORM)
│   └── admin.html     Results dashboard
└── lms-scorm/
    └── imsmanifest.xml   SCORM 1.2 manifest for Option B
```
