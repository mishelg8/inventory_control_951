-- Noticing that a shift report never arrived.
--
-- Everything the console knows about a shift report is inside the encrypted
-- blob: which mission it was for, who filed it, what they were carrying. That
-- is the whole design, and it is why nothing on the server can answer "did
-- נחל שכם report at 23:00?" — the server cannot read a single report it holds.
--
-- So the fact is recorded separately from the report, and it is the only fact
-- recorded: this mission filed something at this moment. No name, no personal
-- number, no phone, no content, and no link back to the report row. The
-- mission id is already public — pub_pick serves it to the unauthenticated
-- shift form so the commander can pick a mission by name — so this table adds
-- nothing to what an outsider could already see.
CREATE TABLE IF NOT EXISTS shift_beats (
  mission_id TEXT NOT NULL,          -- the vault's own mission id, as published
  at         INTEGER NOT NULL,       -- when the report was filed
  PRIMARY KEY (mission_id, at)
);

-- The lookup the watcher actually makes: the latest beat for one mission.
CREATE INDEX IF NOT EXISTS idx_beats_mission ON shift_beats(mission_id, at DESC);

-- What has already been shouted about.
--
-- The watcher wakes every quarter of an hour, and a handover that was missed
-- at 23:00 is still missed at 23:15 and at 23:30. Without a record of what
-- has been sent, one missing report becomes a message every fifteen minutes
-- all night — which is how people learn to ignore the alert that matters.
--
-- Keyed on the slot rather than the mission, so the next handover is a new
-- question and gets its own message.
CREATE TABLE IF NOT EXISTS shift_alerts (
  mission_id TEXT NOT NULL,
  slot       INTEGER NOT NULL,       -- the handover moment, as epoch ms
  at         INTEGER NOT NULL,       -- when we sent about it
  PRIMARY KEY (mission_id, slot)
);

INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES
       ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0),
       ('005-serials', 0), ('006-cards', 0), ('007-pick', 0),
       ('008-sessions', 0), ('009-vault-parts', 0), ('010-sessions-devices', 0),
       ('011-wa-pause', 0), ('012-wa-cloud', 0), ('013-mission-defs', 0),
       ('014-shift-watch', 0);
