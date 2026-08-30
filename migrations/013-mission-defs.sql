-- Missions the office defines, and the kit each one requires.
--
-- The shift form is public and unauthenticated: it cannot read the vault, so
-- whatever it offers has to be published to a table it may read. That is what
-- pub_pick already does for fuel cards and vehicles — an id and a label — and
-- a mission needs one thing more: the list of items it requires, with
-- quantities, so the form can put the right rows in front of the commander.
--
-- `data` is that list, as JSON, and it is null for every other kind. It is
-- operational information served without a login, which is the same bargain
-- already struck for vehicle plates on the refuelling form.
ALTER TABLE pub_pick ADD COLUMN data TEXT;

INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES
       ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0),
       ('005-serials', 0), ('006-cards', 0), ('007-pick', 0),
       ('008-sessions', 0), ('009-vault-parts', 0), ('010-sessions-devices', 0),
       ('011-wa-pause', 0), ('012-wa-cloud', 0), ('013-mission-defs', 0);
