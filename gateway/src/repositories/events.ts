/* A short history of the connection.
 *
 * When someone asks "why did it stop sending last Tuesday", the answer is in
 * here: the session logged out, or the phone lost its data, or WhatsApp shut
 * the door. Only states and short details — never a message and never a number.
 */
import { db } from '../db/index.js';

export interface ConnectionEvent {
  at: number;
  state: string;
  detail: string | null;
}

const insert = db.prepare('INSERT INTO connection_events (at, state, detail) VALUES (?, ?, ?)');
const list = db.prepare('SELECT at, state, detail FROM connection_events ORDER BY at DESC LIMIT ?');
const trim = db.prepare(`
  DELETE FROM connection_events
  WHERE id NOT IN (SELECT id FROM connection_events ORDER BY at DESC LIMIT ?)
`);

export const record = (state: string, detail?: string | null, now = Date.now()) =>
  void insert.run(now, state, detail ?? null);

export const recent = (limit = 30): ConnectionEvent[] =>
  list.all(Math.min(limit, 200)) as ConnectionEvent[];

/** Keep the log bounded; nobody needs the reconnect storm from six months ago. */
export const keepLast = (n = 500): number => trim.run(n).changes;
