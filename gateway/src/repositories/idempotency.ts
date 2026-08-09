/* "I already did that one."
 *
 * The console retries — a flaky phone connection, an impatient thumb on the
 * send button, the Worker replaying a request. Each of those arrives with the
 * same idempotency key, and each must produce the same single message.
 *
 * The claim is an INSERT, not a SELECT-then-INSERT: the uniqueness of the
 * primary key is what decides the race, not the order two handlers happen to
 * run in.
 */
import { db } from '../db/index.js';
import { config } from '../config/index.js';

const claimStmt = db.prepare(`
  INSERT INTO idempotency (key, message_id, created_at, expires_at)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(key) DO NOTHING
`);

const readStmt = db.prepare('SELECT message_id FROM idempotency WHERE key = ? AND expires_at > ?');

/**
 * Bind a key to a message id.
 * @returns null when the key was ours to take, or the id it was already bound to.
 */
export function claim(key: string, messageId: string, now = Date.now()): string | null {
  const expires = now + config.IDEMPOTENCY_TTL_SECONDS * 1000;
  const res = claimStmt.run(key, messageId, now, expires);
  if (res.changes === 1) return null;
  const existing = readStmt.get(key, now) as { message_id: string } | undefined;
  // Expired but not yet swept: take it over rather than reject a fresh request.
  if (!existing) {
    db.prepare('DELETE FROM idempotency WHERE key = ?').run(key);
    return claim(key, messageId, now);
  }
  return existing.message_id;
}

export const lookup = (key: string, now = Date.now()): string | null =>
  (readStmt.get(key, now) as { message_id: string } | undefined)?.message_id ?? null;

const sweepStmt = db.prepare('DELETE FROM idempotency WHERE expires_at <= ?');

export const sweep = (now = Date.now()): number => sweepStmt.run(now).changes;
