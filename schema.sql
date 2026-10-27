-- schema.sql - database layout. Run by `flask --app app init-db`.
-- CHECK constraints are a second line of defence: even if validation in Python
-- were skipped by mistake, the database refuses clearly invalid values.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,                      -- never plaintext
    role          TEXT    NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS students (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    student_code   TEXT    UNIQUE,                       -- e.g. SSP20260001
    full_name      TEXT    NOT NULL,
    phone          TEXT    NOT NULL DEFAULT '',
    address        TEXT    NOT NULL DEFAULT '',
    course         TEXT    NOT NULL DEFAULT 'BCA',
    year_of_study  INTEGER NOT NULL DEFAULT 3 CHECK (year_of_study BETWEEN 1 AND 3),
    attendance_pct REAL    NOT NULL DEFAULT 0 CHECK (attendance_pct BETWEEN 0 AND 100),
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS marks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    subject    TEXT    NOT NULL,
    score      REAL    NOT NULL CHECK (score >= 0),
    max_score  REAL    NOT NULL DEFAULT 100 CHECK (max_score > 0),
    CHECK (score <= max_score)
);

CREATE TABLE IF NOT EXISTS notices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Failed-login log used for rate limiting. "bucket" is "user:<name>" or "ip:<addr>".
CREATE TABLE IF NOT EXISTS login_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket       TEXT    NOT NULL,
    attempted_at INTEGER NOT NULL                        -- unix seconds
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_bucket ON login_attempts(bucket, attempted_at);

-- Security-relevant events (logins, denied access, admin changes).
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event      TEXT NOT NULL,
    user_id    INTEGER,
    ip         TEXT,
    detail     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
