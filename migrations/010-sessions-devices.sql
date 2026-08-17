-- Seeing who is connected, and being able to stop them.
--
-- The console could end every session at once and nothing finer. "Somebody is
-- signed in as me somewhere" was answerable only by signing everybody out,
-- including yourself, and an account that had to be stopped could only be
-- deleted — which takes its wrapped key with it and cannot be undone.
--
-- Two columns:
--
--   sessions.agent   a short device label — "אנדרואיד · Chrome" — derived on
--                    the server from the User-Agent header and stored as that
--                    label only. The raw header is not kept, and neither is
--                    the address: a whole base sits behind one address, so it
--                    would identify nobody while still being one more thing
--                    written down about people in plaintext.
--
--   users.blocked    an account that may not sign in, without deleting it.
--                    Deleting a user destroys their wrapped copy of the
--                    private key; blocking is the reversible answer, which is
--                    the one you want at the moment you are not yet sure what
--                    happened.

ALTER TABLE sessions ADD COLUMN agent TEXT;
ALTER TABLE users ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES
       ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0),
       ('005-serials', 0), ('006-cards', 0), ('007-pick', 0),
       ('008-sessions', 0), ('009-vault-parts', 0),
       ('010-sessions-devices', 0);
