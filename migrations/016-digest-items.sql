-- What the shift actually had, item by item.
--
-- The digest could say "one missing" and not which one, which is the half of
-- the answer that does not help: a supervisor reading it still has to open the
-- console to learn whether the missing thing was a pair of binoculars or the
-- night sight.
--
-- So the beat carries the checklist's verdicts. Deliberately only the
-- verdicts: an item id and one letter for its state. No part numbers, no
-- reasons, no photographs, no counts of grenades by kind — the report itself
-- stays sealed, and this is the summary line it deserves.
--
-- Ids rather than names, because the names are already in the catalogue that
-- both the app and the watcher read. A name stored here would be a second
-- copy able to fall out of step with the first.
ALTER TABLE shift_beats ADD COLUMN items TEXT;

INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES
       ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0),
       ('005-serials', 0), ('006-cards', 0), ('007-pick', 0),
       ('008-sessions', 0), ('009-vault-parts', 0), ('010-sessions-devices', 0),
       ('011-wa-pause', 0), ('012-wa-cloud', 0), ('013-mission-defs', 0),
       ('014-shift-watch', 0), ('015-shift-digest', 0), ('016-digest-items', 0);
