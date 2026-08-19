-- An emergency stop, and a gate against sending the same thing twice.
--
--   config.wa_paused   one switch, held on the server rather than in a tab.
--                      A pause that lives in a browser is not a pause: reload
--                      it and sending resumes, and a second console never
--                      knew about it at all. The row is the system's single
--                      settings row, which is what this is.
--
-- The other half of this change needs no schema. "Was this exact message
-- already sent" is answered from the throttle table under a key made of the
-- record id and the message kind — identifiers, never a name, never a phone
-- number, never the text. The same rule the audit table follows.

ALTER TABLE config ADD COLUMN wa_paused INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES
       ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0),
       ('005-serials', 0), ('006-cards', 0), ('007-pick', 0),
       ('008-sessions', 0), ('009-vault-parts', 0),
       ('010-sessions-devices', 0), ('011-wa-pause', 0);
