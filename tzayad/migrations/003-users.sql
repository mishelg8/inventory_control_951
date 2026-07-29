-- Replaces the single admin credential + single viewer credential with a real
-- user table. Every row holds its own copy of the RSA private key, wrapped
-- under that user's own password — that is the only way a browser-side
-- decryption model can support more than one login.
--
-- The existing admin password is carried over untouched: the row is seeded
-- straight from `config`, so the same password keeps working under the new
-- username admin.951.

CREATE TABLE IF NOT EXISTS users (
  username     TEXT PRIMARY KEY,       -- 'admin.951', 'sagan.a', …
  role         TEXT NOT NULL DEFAULT 'viewer',   -- 'admin' | 'viewer'
  salt         TEXT NOT NULL,          -- PBKDF2 salt for this user's KEK
  verifier     TEXT NOT NULL,
  key_iv       TEXT NOT NULL,
  wrapped_key  TEXT NOT NULL,          -- private key encrypted under that KEK
  tabs         TEXT NOT NULL DEFAULT '*',   -- '*' or a JSON array of tab ids
  created_at   INTEGER NOT NULL,
  last_seen    INTEGER
);

-- the existing administrator, with the password already in use
INSERT OR IGNORE INTO users (username, role, salt, verifier, key_iv, wrapped_key, tabs, created_at)
SELECT 'admin.951', 'admin', salt, verifier, key_iv, wrapped_key, '*', created_at
FROM config WHERE id = 1;

-- the one-off viewer credential, if one was created before this table existed
INSERT OR IGNORE INTO users (username, role, salt, verifier, key_iv, wrapped_key, tabs, created_at)
SELECT 'viewer', 'viewer', salt, verifier, key_iv, wrapped_key, '*', created_at
FROM viewer WHERE id = 1;

ALTER TABLE sessions ADD COLUMN username TEXT;
ALTER TABLE sessions ADD COLUMN tabs TEXT NOT NULL DEFAULT '*';
