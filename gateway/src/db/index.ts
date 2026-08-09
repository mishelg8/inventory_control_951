/* One SQLite file, opened once, migrated on open.
 *
 * SQLite rather than a server: the gateway is a single process holding a
 * single WhatsApp session, so a second writer cannot exist, and the queue
 * has to survive a restart on a box where the fewest moving parts is the
 * whole design goal. WAL so a long read cannot block the queue's writes.
 */
import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { config } from '../config/index.js';
import { log } from '../utils/logger.js';

mkdirSync(dirname(config.DATABASE_PATH), { recursive: true });

export const db = new Database(config.DATABASE_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

const MIGRATIONS: ReadonlyArray<{ name: string; sql: string }> = [
  {
    name: '001_initial',
    sql: `
      CREATE TABLE messages (
        id            TEXT PRIMARY KEY,
        phone         TEXT NOT NULL,
        message       TEXT NOT NULL,
        template      TEXT,
        status        TEXT NOT NULL,
        attempts      INTEGER NOT NULL DEFAULT 0,
        error_code    TEXT,
        error         TEXT,
        wa_message_id TEXT,
        created_at    INTEGER NOT NULL,
        scheduled_at  INTEGER NOT NULL,
        sent_at       INTEGER,
        failed_at     INTEGER
      );
      CREATE INDEX idx_messages_status_sched ON messages(status, scheduled_at);
      CREATE INDEX idx_messages_created ON messages(created_at DESC);
      CREATE INDEX idx_messages_phone ON messages(phone);

      CREATE TABLE idempotency (
        key        TEXT PRIMARY KEY,
        message_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX idx_idem_expires ON idempotency(expires_at);

      CREATE TABLE connection_events (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        at      INTEGER NOT NULL,
        state   TEXT NOT NULL,
        detail  TEXT
      );
      CREATE INDEX idx_events_at ON connection_events(at DESC);

      CREATE TABLE number_cache (
        phone      TEXT PRIMARY KEY,
        registered INTEGER NOT NULL,
        checked_at INTEGER NOT NULL
      );
    `,
  },
];

db.exec('CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)');

const applied = new Set(
  db.prepare('SELECT name FROM migrations').all().map((r) => (r as { name: string }).name),
);

for (const m of MIGRATIONS) {
  if (applied.has(m.name)) continue;
  db.transaction(() => {
    db.exec(m.sql);
    db.prepare('INSERT INTO migrations (name, applied_at) VALUES (?, ?)').run(m.name, Date.now());
  })();
  log.info('db.migrated', { migration: m.name });
}

export const closeDb = () => {
  try {
    db.close();
  } catch {
    /* already closed */
  }
};
