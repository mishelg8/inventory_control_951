-- Breaking the single vault blob into one row per domain.
--
-- Everything the logistics side holds — stock, the armoury, the signals
-- store, ammunition, vehicles, fuel cards, and the movement logs of each —
-- lived in one encrypted blob, rewritten in full on every change. Three
-- consequences, all of them felt:
--
--   * Two people editing at once meant a 409 and one of them redoing their
--     work, even when one was counting rifles and the other was entering a
--     kilometre reading. The conflict was in the storage, not in the data.
--   * One ceiling for everything. The movement logs grow forever and would
--     have been the ones to hit it, taking the vehicles down with them.
--   * Every save shipped the whole thing, however small the change.
--
-- Each row here is sealed exactly as before — the server sees ciphertext and
-- an update time, and can no more read a part than it could read the whole.
-- What it gains is the ability to say which part moved, so a save that
-- touches vehicles is not refused because someone else touched ammunition.
--
-- The old `vault` row is deliberately left in place and still written to. The
-- server cannot split a blob it cannot read, so the split happens in the
-- first admin browser to sign in after this ships; until every client is on
-- the new code, the blob is what an older one would read.
CREATE TABLE IF NOT EXISTS vault_parts (
  part       TEXT PRIMARY KEY,   -- 'stock' | 'armon' | 'armonLog' | …
  ek         TEXT NOT NULL,
  iv         TEXT NOT NULL,
  ct         TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO schema_migrations (name, applied_at)
VALUES ('001-initial', 0), ('002-viewer-role', 0), ('003-users', 0),
       ('004-hardening', 0), ('005-serials', 0), ('006-cards', 0),
       ('007-pick', 0), ('008-sessions', 0), ('009-vault-parts', 0);
