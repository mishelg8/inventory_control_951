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

-- Shortage reports: free-text "what I'm missing" notes from soldiers. Separate
-- from equipment sign-out entirely — a soldier may file several over time, so
-- the id is random per report rather than derived from the personal number.
-- Body is encrypted like everything else; only the handled flag is in clear.
CREATE TABLE IF NOT EXISTS reports (
  id          TEXT PRIMARY KEY,        -- 32 random hex chars
  ek          TEXT NOT NULL,
  iv          TEXT NOT NULL,
  ct          TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'open',   -- 'open' | 'partial' | 'done'
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);

-- Licence photos, one row per (soldier, kind). Kept out of the records table
-- so the admin console never downloads megabytes of images just to list
-- soldiers — they are fetched only when a specific licence is opened.
-- Same encryption envelope as records: the server sees ciphertext only.
CREATE TABLE IF NOT EXISTS docs (
  rid         TEXT NOT NULL,           -- same rid as the owning record
  kind        TEXT NOT NULL,           -- 'civil' | 'military'
  ek          TEXT NOT NULL,
  iv          TEXT NOT NULL,
  ct          TEXT NOT NULL,           -- encrypted JPEG, capped at ~400 KB b64
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (rid, kind)
);

-- Single admin-owned encrypted blob (inventory: opening stock, extra items,
-- free-text notes). Same envelope as records; readable only with the private key.
CREATE TABLE IF NOT EXISTS vault (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  ek          TEXT NOT NULL,
  iv          TEXT NOT NULL,
  ct          TEXT NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- A second, read-only credential. It holds its own copy of the same private
-- key, wrapped under the viewer's own password — decryption happens in the
-- browser, so there is no way to show the data without handing over a key.
-- What makes it read-only is the server: every mutating endpoint refuses a
-- session whose role is 'viewer'.
CREATE TABLE IF NOT EXISTS viewer (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  salt         TEXT    NOT NULL,   -- PBKDF2 salt for the viewer KEK + verifier
  verifier     TEXT    NOT NULL,
  key_iv       TEXT    NOT NULL,
  wrapped_key  TEXT    NOT NULL,   -- private key encrypted under the viewer KEK
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token   TEXT PRIMARY KEY,        -- 64 hex chars
  expires INTEGER NOT NULL,
  role    TEXT NOT NULL DEFAULT 'admin'   -- 'admin' | 'viewer'
);

CREATE TABLE IF NOT EXISTS throttle (
  k     TEXT PRIMARY KEY,          -- 'login:<ip>' | 'sub:<ip>'
  hits  INTEGER NOT NULL,
  until INTEGER NOT NULL
);
