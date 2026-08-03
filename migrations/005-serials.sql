-- Stopping the same weapon being signed for twice.
--
-- Serial numbers live inside the encrypted payload, so the server cannot
-- compare them and a soldier's browser cannot see anyone else's. Two people
-- filing the same rifle therefore both succeeded, and the clash only surfaced
-- when an admin came to approve the second one — by which point both slips
-- were in and neither soldier knew.
--
-- What the server can hold is a blind index: a slow-KDF mask of the number
-- under the same id_salt already used to derive a record id from a personal
-- number. Equal numbers give equal tags, so a UNIQUE constraint refuses the
-- duplicate, and the server still never sees a serial.
--
-- The trade-off is the one the record id already accepts: a seven-digit
-- number is low entropy, so anyone holding both this table and id_salt could
-- work out which serials exist — not whose they are, which stays encrypted.
CREATE TABLE IF NOT EXISTS serial_tags (
  tag        TEXT PRIMARY KEY,   -- 32 hex, PBKDF2 of the normalised number
  field      TEXT NOT NULL,      -- 'weapon' | 'amral' | 'scope'
  state      TEXT NOT NULL,      -- 'pending' | 'approved' | 'deposit' | 'armoury'
  owner_kind TEXT NOT NULL,      -- 'record' | 'report'
  owner_id   TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Releasing a number when its record or report goes needs the owner, not the tag.
CREATE INDEX IF NOT EXISTS idx_serial_owner ON serial_tags(owner_kind, owner_id);

INSERT OR IGNORE INTO schema_migrations (name, applied_at)
VALUES ('001-initial', 0), ('002-viewer-role', 0), ('003-users', 0),
       ('004-hardening', 0), ('005-serials', 0);
