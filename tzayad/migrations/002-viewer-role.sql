-- Adds the read-only viewer credential to a database created before it existed.
-- Safe to run once per environment; re-running errors on the duplicate column,
-- which is harmless — the table above is created with IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS viewer (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  salt         TEXT    NOT NULL,
  verifier     TEXT    NOT NULL,
  key_iv       TEXT    NOT NULL,
  wrapped_key  TEXT    NOT NULL,
  created_at   INTEGER NOT NULL
);

ALTER TABLE sessions ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
