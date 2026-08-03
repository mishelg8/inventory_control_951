-- Letting a soldier pick the vehicle too, not only the card.
--
-- 006 published a roster of fuel cards so the refuelling form could offer
-- them instead of asking a soldier to copy a number off the card. The vehicle
-- number had the same problem and no such list: it was typed by hand, and a
-- typo there files the litres against a vehicle that does not exist.
--
-- Rather than a second table shaped exactly like the first, the roster
-- becomes one table with a kind. Everything else is unchanged: the admin's
-- browser is the only thing that can read the vault, so it is the only thing
-- that can publish, and it replaces the whole list of a kind each time — so
-- a card that was credited, or a vehicle that left the fleet, disappears from
-- the soldiers' form the moment it leaves the console.
--
-- A card's label stays masked (type plus last four); it is a payment
-- instrument. A vehicle's label is the plate as it is written on the vehicle,
-- because a soldier standing at the pump has to recognise their own vehicle
-- in the list, and a plate is already visible to anyone who walks past it.
CREATE TABLE IF NOT EXISTS pub_pick (
  kind       TEXT NOT NULL,      -- 'card' | 'vehicle'
  id         TEXT NOT NULL,      -- the item's id inside the vault
  label      TEXT NOT NULL,      -- 'דיזל · ••5678' | '12-345-67 · אלדן'
  sort       INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (kind, id)
);

-- The cards already published keep working across the deploy.
INSERT OR IGNORE INTO pub_pick (kind, id, label, sort, updated_at)
SELECT 'card', id, label, sort, updated_at FROM pub_cards;

DROP TABLE IF EXISTS pub_cards;

INSERT OR IGNORE INTO schema_migrations (name, applied_at)
VALUES ('001-initial', 0), ('002-viewer-role', 0), ('003-users', 0),
       ('004-hardening', 0), ('005-serials', 0), ('006-cards', 0),
       ('007-pick', 0);
