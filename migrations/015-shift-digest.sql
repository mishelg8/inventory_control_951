-- Telling the supervisor what came in.
--
-- The beat was one fact and nothing else: this mission filed something at this
-- moment. That was enough to notice silence, and it is not enough to say what
-- arrived — a supervisor asking "did נחל שכם report?" wants the answer to name
-- the commander and say whether anything was short.
--
-- So the beat carries a little more, and this is a deliberate widening of what
-- the server can see. It is the same bargain already struck for the messages
-- the app sends soldiers: the text and the recipient pass through the server
-- in the clear on their way to Meta. What still never leaves the vault is the
-- report itself — the part numbers, the photographs, the reasons.
--
-- `who` is a name because a message reading "a commander reported" is not an
-- answer. There is no phone number here and no personal number: the message
-- goes to one configured recipient and needs neither.
ALTER TABLE shift_beats ADD COLUMN mission_name TEXT;
ALTER TABLE shift_beats ADD COLUMN who TEXT;
ALTER TABLE shift_beats ADD COLUMN short INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shift_beats ADD COLUMN partial INTEGER NOT NULL DEFAULT 0;

-- Whether the supervisor has been told. Reports are batched into one message
-- per run rather than one message each: a shift with four missions would
-- otherwise be four notifications inside a minute, and WhatsApp's per-recipient
-- limits are exactly what swallowed the first attempt at this.
ALTER TABLE shift_beats ADD COLUMN notified INTEGER NOT NULL DEFAULT 0;

-- Rows written before this migration have nothing to say and must not be
-- announced retroactively.
UPDATE shift_beats SET notified = 1;

CREATE INDEX IF NOT EXISTS idx_beats_pending ON shift_beats(notified, at);

INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES
       ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0),
       ('005-serials', 0), ('006-cards', 0), ('007-pick', 0),
       ('008-sessions', 0), ('009-vault-parts', 0), ('010-sessions-devices', 0),
       ('011-wa-pause', 0), ('012-wa-cloud', 0), ('013-mission-defs', 0),
       ('014-shift-watch', 0), ('015-shift-digest', 0);
