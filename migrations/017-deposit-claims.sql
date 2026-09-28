-- A weapon may be deposited more than once in its life.
--
-- The serial ledger was built to answer one question: is this number already
-- signed for by somebody? One row per number, and the row says who holds it.
-- A deposit slip was then made to claim the number the same way, and that is
-- where it went wrong, because a deposit is not a rival claim on a weapon. It
-- is the weapon's own owner saying "here, hold this for me".
--
-- Two consequences, both of them seen at the counter:
--
--   A soldier whose rifle is on her record could not deposit it at all. Her
--   record held the number, the deposit slip wanted the same number, and the
--   ledger — doing exactly what it was told — called her own rifle a
--   duplicate of itself.
--
--   And a deposit that WAS filed held the number for good. Nothing released
--   it: not the armoury taking the weapon in, not handing it back. The second
--   time that soldier went home, the counter told her the rifle was already
--   deposited and waiting for intake. Once per weapon, ever.
--
-- So deposits get their own small book. "Whose weapon is this" (serial_tags)
-- and "which weapons are waiting to be taken in" (here) are different
-- questions, and one row per number in each of them is right — it is one row
-- per number ACROSS them that was wrong.
--
-- Same blind index, same trade-off, same no-plaintext rule: the server still
-- never sees a serial number, only the mask of one.
CREATE TABLE IF NOT EXISTS deposit_claims (
  tag        TEXT PRIMARY KEY,   -- 32 hex, same derivation as serial_tags.tag
  field      TEXT NOT NULL,      -- 'weapon' | 'amral' | 'scope'
  report_id  TEXT NOT NULL,      -- the deposit slip holding it
  created_at INTEGER NOT NULL
);

-- Releasing a slip's numbers on intake or deletion needs the slip, not the tag.
CREATE INDEX IF NOT EXISTS idx_deposit_claim_report ON deposit_claims(report_id);

-- Deposits still waiting for intake keep their hold, in the new book.
INSERT OR IGNORE INTO deposit_claims (tag, field, report_id, created_at)
SELECT tag, field, owner_id, created_at FROM serial_tags
 WHERE owner_kind = 'report'
   AND owner_id IN (SELECT id FROM reports WHERE deleted_at IS NULL AND status <> 'done');

-- And every deposit hold in the old book goes, including the stale ones that
-- have been refusing deposits since the day they were taken in.
DELETE FROM serial_tags WHERE owner_kind = 'report';

INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES
       ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0),
       ('005-serials', 0), ('006-cards', 0), ('007-pick', 0),
       ('008-sessions', 0), ('009-vault-parts', 0), ('010-sessions-devices', 0),
       ('011-wa-pause', 0), ('012-wa-cloud', 0), ('013-mission-defs', 0),
       ('014-shift-watch', 0), ('015-shift-digest', 0), ('016-digest-items', 0),
       ('017-deposit-claims', 0);
