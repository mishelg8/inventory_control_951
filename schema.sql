CREATE TABLE IF NOT EXISTS config (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  pub          TEXT    NOT NULL,   -- RSA public key, JWK JSON
  salt         TEXT    NOT NULL,   -- PBKDF2 salt for KEK + verifier
  id_salt      TEXT    NOT NULL,   -- PBKDF2 salt for record IDs
  verifier     TEXT    NOT NULL,   -- SHA-256 of auth half, 64 hex chars
  key_iv       TEXT    NOT NULL,
  wrapped_key  TEXT    NOT NULL,   -- private key encrypted under KEK
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
  rid         TEXT PRIMARY KEY,    -- 32 hex chars, masked derivation of the personal number
  ek          TEXT NOT NULL,
  iv          TEXT NOT NULL,
  ct          TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',   -- 'pending' | 'approved'
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);

CREATE TABLE IF NOT EXISTS sessions (
  token   TEXT PRIMARY KEY,        -- 64 hex chars
  expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS throttle (
  k     TEXT PRIMARY KEY,          -- 'login:<ip>' | 'sub:<ip>'
  hits  INTEGER NOT NULL,
  until INTEGER NOT NULL
);
