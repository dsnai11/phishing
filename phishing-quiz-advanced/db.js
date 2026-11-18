const { Pool } = require("pg");

// Tidy up common copy-paste mistakes: spaces/line breaks, surrounding quotes,
// a leading "psql " (from Neon's psql tab) or "DATABASE_URL=".
function tidyUrl(raw) {
  let s = String(raw || "").trim();
  s = s.replace(/^DATABASE_URL\s*=\s*/i, "").replace(/^psql\s+/i, "").trim();
  s = s.replace(/^['"`]+|['"`]+$/g, "").trim();
  return s;
}

const DATABASE_URL = tidyUrl(process.env.DATABASE_URL);
if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not set. Paste your Neon connection string (see README.md).");
  process.exit(1);
}
let parsedHost = "";
try {
  const u = new URL(DATABASE_URL);
  if (!/^postgres(ql)?:$/.test(u.protocol) || !u.hostname) throw new Error("bad");
  parsedHost = u.hostname;
  if (u.password && /^\*+$/.test(decodeURIComponent(u.password))) {
    console.error("ERROR: DATABASE_URL contains '****' instead of the real password. In Neon click 'Show password' (or the copy button) and paste the string again.");
    process.exit(1);
  }
} catch {
  console.error(
    "ERROR: DATABASE_URL is not a valid connection string. It must start with postgresql:// — " +
    "in Neon choose 'Connection string' (not psql), copy it, and paste ONLY that line into Render's DATABASE_URL value. " +
    `Current value starts with: "${DATABASE_URL.slice(0, 14)}…"`
  );
  process.exit(1);
}

// Neon (and most cloud Postgres) requires SSL. SSL is turned on automatically for any
// non-local database. Set DATABASE_SSL=false only for a local Postgres without SSL.
const isLocal = /@(localhost|127\.0\.0\.1|\[::1\])(:|\/)/.test(DATABASE_URL);
const sslSetting = String(process.env.DATABASE_SSL || "").toLowerCase();
const useSSL = sslSetting === "true" || (sslSetting !== "false" && !isLocal);

// Remove sslmode / channel_binding from the URL; SSL is configured below instead
// (newer versions of the pg driver otherwise print warnings about sslmode=require).
function stripSslParams(url) {
  try {
    const u = new URL(url);
    ["sslmode", "channel_binding"].forEach((k) => u.searchParams.delete(k));
    return u.toString();
  } catch {
    return url;
  }
}

const pool = new Pool({
  connectionString: useSSL ? stripSslParams(DATABASE_URL) : DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: true } : false, // Neon uses publicly trusted certificates
  max: 10,
  idleTimeoutMillis: 30000,       // close idle connections (Neon suspends idle computes after 5 min)
  connectionTimeoutMillis: 15000, // allow time for a suspended Neon compute to wake up
  keepAlive: true,
});

// Neon may close idle connections when the compute scales to zero; the pool reconnects on next use.
pool.on("error", (err) => console.error("PostgreSQL connection closed:", err.message));

// Retries a query once if the connection was dropped while Neon was waking up.
async function query(text, params) {
  try {
    return await pool.query(text, params);
  } catch (err) {
    const transient = ["ECONNRESET", "57P01", "08006", "08003"].includes(err.code) || /Connection terminated/i.test(err.message);
    if (!transient) throw err;
    return pool.query(text, params);
  }
}

// Creates the table on first start. Safe to run on every start.
async function migrate(retries = 5) {
  for (let i = 1; ; i++) {
    try {
      await query(`
        CREATE TABLE IF NOT EXISTS quiz_attempts (
          id               BIGSERIAL PRIMARY KEY,
          emp_id           VARCHAR(30)  NOT NULL,
          full_name        VARCHAR(120) NOT NULL,
          department       VARCHAR(80),
          language         VARCHAR(5)   NOT NULL DEFAULT 'en',
          score            SMALLINT     NOT NULL,
          correct_count    SMALLINT     NOT NULL,
          total_questions  SMALLINT     NOT NULL,
          passed           BOOLEAN      NOT NULL,
          answers          JSONB        NOT NULL,
          duration_sec     INTEGER,
          attempt_no       INTEGER      NOT NULL DEFAULT 1,
          ip_address       VARCHAR(64),
          user_agent       TEXT,
          created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
        );
        -- Added for multiple training modules; existing rows become 'basic'.
        ALTER TABLE quiz_attempts ADD COLUMN IF NOT EXISTS module VARCHAR(20) NOT NULL DEFAULT 'basic';
        CREATE INDEX IF NOT EXISTS idx_quiz_attempts_emp_id     ON quiz_attempts (emp_id);
        CREATE INDEX IF NOT EXISTS idx_quiz_attempts_module     ON quiz_attempts (module, emp_id);

        -- Proctoring (added for full-screen / tab-switch monitoring)
        ALTER TABLE quiz_attempts ADD COLUMN IF NOT EXISTS session_id     VARCHAR(40);
        ALTER TABLE quiz_attempts ADD COLUMN IF NOT EXISTS violations     INTEGER     NOT NULL DEFAULT 0;
        ALTER TABLE quiz_attempts ADD COLUMN IF NOT EXISTS proctor_status VARCHAR(20) NOT NULL DEFAULT 'none';
        CREATE TABLE IF NOT EXISTS proctor_sessions (
          id             VARCHAR(40)  PRIMARY KEY,
          module         VARCHAR(20)  NOT NULL,
          emp_id         VARCHAR(30)  NOT NULL,
          full_name      VARCHAR(120) NOT NULL,
          department     VARCHAR(80),
          language       VARCHAR(5),
          status         VARCHAR(20)  NOT NULL DEFAULT 'in_progress',
          violations     INTEGER      NOT NULL DEFAULT 0,
          events         JSONB        NOT NULL DEFAULT '[]'::jsonb,
          attempt_id     BIGINT,
          fullscreen     BOOLEAN,
          ip_address     VARCHAR(64),
          user_agent     TEXT,
          started_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
          last_event_at  TIMESTAMPTZ,
          ended_at       TIMESTAMPTZ
        );
        CREATE INDEX IF NOT EXISTS idx_proctor_sessions_emp     ON proctor_sessions (emp_id);
        CREATE INDEX IF NOT EXISTS idx_proctor_sessions_started ON proctor_sessions (started_at DESC);

        -- Webcam monitoring
        ALTER TABLE proctor_sessions ADD COLUMN IF NOT EXISTS camera     BOOLEAN;
        ALTER TABLE proctor_sessions ADD COLUMN IF NOT EXISTS face_check BOOLEAN;
        CREATE TABLE IF NOT EXISTS proctor_snapshots (
          id          BIGSERIAL    PRIMARY KEY,
          session_id  VARCHAR(40)  NOT NULL,
          reason      VARCHAR(30)  NOT NULL,
          question    SMALLINT,
          image       TEXT         NOT NULL,   -- JPEG as a data URL (about 10-25 KB)
          taken_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS idx_proctor_snapshots_session ON proctor_snapshots (session_id, taken_at);
        CREATE INDEX IF NOT EXISTS idx_proctor_snapshots_taken   ON proctor_snapshots (taken_at);

        -- Full video + sound recording (advanced module)
        ALTER TABLE proctor_sessions ADD COLUMN IF NOT EXISTS recording BOOLEAN;
        CREATE TABLE IF NOT EXISTS proctor_recordings (
          session_id  VARCHAR(40)  NOT NULL,
          part        SMALLINT     NOT NULL,   -- a new part starts if the page is reloaded
          seq         INTEGER      NOT NULL,   -- 5-second pieces, in order
          mime        VARCHAR(60),
          bytes       INTEGER      NOT NULL,
          data        BYTEA        NOT NULL,
          created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
          PRIMARY KEY (session_id, part, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_proctor_recordings_created ON proctor_recordings (created_at);
        CREATE INDEX IF NOT EXISTS idx_quiz_attempts_created_at ON quiz_attempts (created_at DESC);
      `);
      console.log(`Database ready (${useSSL ? "SSL" : "no SSL"}, ${isLocal ? "local" : new URL(DATABASE_URL).hostname})`);
      return;
    } catch (err) {
      if (i >= retries) throw err;
      console.warn(`Database not reachable yet (attempt ${i}/${retries}): ${err.message}. Retrying in ${i * 2}s…`);
      await new Promise((r) => setTimeout(r, i * 2000));
    }
  }
}

module.exports = { pool, query, migrate };
