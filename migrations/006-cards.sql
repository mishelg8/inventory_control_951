-- Letting a soldier pick the fuel card instead of typing its number.
--
-- The cards live in the admin's encrypted vault, which a soldier cannot read,
-- so the refuelling form had them typing the number off the card by hand —
-- and a typo there files litres against the wrong card.
--
-- This is the roster the admin publishes for that form: an id and a label,
-- nothing else. The label is masked (type plus the last four digits), because
-- a fuel card is a payment instrument and the form it appears on is public.
-- The soldier picks an id; only the admin's browser can turn that back into
-- a card. A card that has been credited or removed is simply not published,
-- which is what makes it unpickable.
CREATE TABLE IF NOT EXISTS pub_cards (
  id         TEXT PRIMARY KEY,   -- the card's id inside the vault
  label      TEXT NOT NULL,      -- 'דיזל · ‏5678' — masked, never the full number
  sort       INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO schema_migrations (name, applied_at)
VALUES ('001-initial', 0), ('002-viewer-role', 0), ('003-users', 0),
       ('004-hardening', 0), ('005-serials', 0), ('006-cards', 0);
