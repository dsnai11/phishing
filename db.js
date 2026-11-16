const { Pool } = require("pg");

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is not set. Paste your Neon connection string (see README.md).");
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
        CREATE INDEX IF NOT EXISTS idx_quiz_attempts_emp_id     ON quiz_attempts (emp_id);
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
