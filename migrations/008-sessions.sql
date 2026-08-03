-- Giving a session an end, and the audit trail its most important events.
--
-- A session was refreshed on every authenticated request and never expired
-- while the console stayed open: an hour from the last request, always, with
-- no ceiling. A console left signed in on a shared laptop stayed signed in
-- indefinitely, and there was no way to end sessions other than waiting for
-- them to idle out one by one.
--
-- Knowing when a session began is what makes an absolute limit possible.
-- Existing rows have no start time; they are treated as having begun now, so
-- nobody is thrown out mid-approval by the migration itself.
ALTER TABLE sessions ADD COLUMN created_at INTEGER;

-- The audit trail is read newest-first and filtered by user often enough to
-- deserve the index now that logins are written to it too.
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(username, at);

INSERT OR IGNORE INTO schema_migrations (name, applied_at)
VALUES ('001-initial', 0), ('002-viewer-role', 0), ('003-users', 0),
       ('004-hardening', 0), ('005-serials', 0), ('006-cards', 0),
       ('007-pick', 0), ('008-sessions', 0);
