-- The official WhatsApp Cloud API, alongside the existing gateway.
--
-- Everything the provider sends us about a person is sealed here on arrival,
-- with the same envelope the browser uses (ek/iv/ct, AES-GCM under an
-- RSA-OAEP-wrapped content key). The Worker holds the public key and can
-- write; it has never held the private key and cannot read a word of what it
-- wrote. That is the property the whole system rests on, and an inbound
-- message is no reason to make an exception to it.
--
-- What stays in clear is what stays in clear everywhere else: identifiers,
-- timestamps, states. A phone number is not an identifier for this purpose —
-- it names a person — so it is sealed like a name, and grouping is done on a
-- blind index of it, derived the same way a record id is derived from a
-- personal number (PBKDF2 over the shared id_salt). The server can put two
-- messages in the same conversation without being able to say whose.

-- One row per person we have exchanged messages with.
CREATE TABLE IF NOT EXISTS wa_contacts (
  tag         TEXT PRIMARY KEY,        -- 32 hex, blind index of the E.164 number
  ek          TEXT NOT NULL,           -- sealed { phone, profileName }
  iv          TEXT NOT NULL,
  ct          TEXT NOT NULL,
  first_seen  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL
);

-- A conversation is a thread with one person on one of our numbers.
--
-- window_expires is WhatsApp's own rule, not ours: a free-text reply is only
-- allowed for 24 hours after the person last wrote. Outside it, only an
-- approved template may be sent. Keeping the deadline here means the server
-- can refuse rather than let Meta refuse — a rejection that costs a round
-- trip and reads like a fault.
CREATE TABLE IF NOT EXISTS wa_conversations (
  id              TEXT PRIMARY KEY,    -- 32 random hex
  contact_tag     TEXT NOT NULL,
  phone_number_id TEXT NOT NULL,       -- ours, the number they wrote to
  window_expires  INTEGER NOT NULL DEFAULT 0,
  last_inbound_at INTEGER,
  last_message_at INTEGER,
  unread          INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_wa_conv_contact
  ON wa_conversations(contact_tag, phone_number_id);
CREATE INDEX IF NOT EXISTS idx_wa_conv_recent ON wa_conversations(last_message_at);

-- Every message, both directions, sealed body.
--
-- wamid is Meta's id and is unique: it is what makes a redelivered webhook a
-- no-op instead of a second row. Outbound rows are written before the request
-- goes out, with no wamid yet, so a message that vanished mid-flight is still
-- visible as one that was tried.
CREATE TABLE IF NOT EXISTS wa_messages (
  id           TEXT PRIMARY KEY,       -- 32 random hex, ours
  conv         TEXT NOT NULL,
  wamid        TEXT,                   -- Meta's id, unique when present
  direction    TEXT NOT NULL,          -- 'in' | 'out'
  type         TEXT NOT NULL,          -- 'text' | 'image' | 'document' | 'audio' | 'video' | 'sticker' | 'interactive' | 'button' | 'template' | 'unsupported'
  status       TEXT NOT NULL,          -- 'queued' | 'accepted' | 'sent' | 'delivered' | 'read' | 'failed' | 'received'
  ek           TEXT NOT NULL,          -- sealed { text, caption, interactive, templateName, … }
  iv           TEXT NOT NULL,
  ct           TEXT NOT NULL,
  media_id     TEXT,                   -- Meta's media id, when the message carries one
  template     TEXT,                   -- template name for outbound templates, not personal
  err_code     INTEGER,
  err_subcode  INTEGER,
  err_title    TEXT,
  err_detail   TEXT,
  err_trace    TEXT,                   -- fbtrace_id
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  sent_at      INTEGER,
  delivered_at INTEGER,
  read_at      INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_wa_msg_wamid ON wa_messages(wamid);
CREATE INDEX IF NOT EXISTS idx_wa_msg_conv ON wa_messages(conv, created_at);

-- The idempotency ledger. Meta retries; a retry must change nothing.
--
-- One row per (message or status) event actually applied, keyed by something
-- stable that Meta gives us: the wamid for a message, the wamid plus the
-- status name for a status. Retention is short because its only job is to
-- answer "have I already done this", and Meta stops retrying long before.
CREATE TABLE IF NOT EXISTS wa_events (
  k           TEXT PRIMARY KEY,        -- 'msg:<wamid>' | 'st:<wamid>:<status>'
  at          INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wa_events_at ON wa_events(at);

-- Media, sealed, fetched once.
--
-- Meta's download URL is short-lived and carries no auth of its own — it
-- needs the access token in a header — so it is never handed to a browser.
-- The bytes are pulled server-side, sealed, and stored here; the console asks
-- this table, not Meta.
CREATE TABLE IF NOT EXISTS wa_media (
  media_id    TEXT PRIMARY KEY,        -- Meta's id
  mime        TEXT NOT NULL,
  bytes       INTEGER NOT NULL,
  ek          TEXT NOT NULL,           -- sealed raw bytes
  iv          TEXT NOT NULL,
  ct          TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);

INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES
       ('002-viewer-role', 0), ('003-users', 0), ('004-hardening', 0),
       ('005-serials', 0), ('006-cards', 0), ('007-pick', 0),
       ('008-sessions', 0), ('009-vault-parts', 0),
       ('010-sessions-devices', 0), ('011-wa-pause', 0),
       ('012-wa-cloud', 0);
