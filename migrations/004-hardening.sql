-- Hardening pass: submission tickets, an admin audit trail, soft deletes,
-- per-username login throttling, and a record of which migrations have run.

-- Which migrations this database has already had applied. Until now this was
-- tracked in someone's head, and re-running a migration threw on a duplicate
-- column.
CREATE TABLE IF NOT EXISTS schema_migrations (
  name       TEXT PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

-- Single-use, short-lived tickets. A soldier's browser fetches one when the
-- page loads and spends it on submit, so a script cannot post records without
-- first walking the same path — and each ticket buys exactly one write.
CREATE TABLE IF NOT EXISTS tickets (
  id       TEXT PRIMARY KEY,        -- 32 hex chars
  expires  INTEGER NOT NULL,
  used_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_tickets_expires ON tickets(expires);

-- Every state-changing admin action, in clear. Deliberately holds no personal
-- data: what happened and to which id, never who it was about — that stays
-- encrypted in the record itself.
CREATE TABLE IF NOT EXISTS audit (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  at       INTEGER NOT NULL,
  username TEXT,
  action   TEXT NOT NULL,           -- 'approve' | 'delete' | 'vault' | 'user' | …
  target   TEXT,                    -- rid / report id / username
  detail   TEXT                     -- short, non-identifying
);

CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);

-- Soft delete: a deleted record leaves the console but stays recoverable for
-- 30 days, so one mis-click is not the end of a soldier's sign-out history.
ALTER TABLE records ADD COLUMN deleted_at INTEGER;
ALTER TABLE reports ADD COLUMN deleted_at INTEGER;

INSERT OR IGNORE INTO schema_migrations (name, applied_at)
VALUES ('001-initial', 0), ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0);
