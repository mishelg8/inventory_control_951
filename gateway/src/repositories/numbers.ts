/* Which numbers are on WhatsApp at all.
 *
 * Asking WhatsApp is a network round trip through the browser session, and
 * asking it repeatedly for the same number is exactly the kind of chatter that
 * gets an account flagged. The answer changes rarely, so it is cached — but
 * with an expiry, because "not registered" turns into "registered" the day the
 * soldier installs the app.
 */
import { db } from '../db/index.js';

const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const readStmt = db.prepare('SELECT registered, checked_at FROM number_cache WHERE phone = ?');
const writeStmt = db.prepare(`
  INSERT INTO number_cache (phone, registered, checked_at) VALUES (?, ?, ?)
  ON CONFLICT(phone) DO UPDATE SET registered = excluded.registered, checked_at = excluded.checked_at
`);
const sweepStmt = db.prepare('DELETE FROM number_cache WHERE checked_at <= ?');

export function get(phone: string, ttlMs = DEFAULT_TTL_MS, now = Date.now()): boolean | null {
  const row = readStmt.get(phone) as { registered: number; checked_at: number } | undefined;
  if (!row || now - row.checked_at > ttlMs) return null;
  return row.registered === 1;
}

export const put = (phone: string, registered: boolean, now = Date.now()) =>
  void writeStmt.run(phone, registered ? 1 : 0, now);

export const sweep = (before: number): number => sweepStmt.run(before).changes;
