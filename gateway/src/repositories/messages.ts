/* The outbox.
 *
 * Every message is a row before it is an attempt, and it stays a row after it
 * succeeds or gives up. A restart mid-send must never lose a message and must
 * never send one twice, so "I am about to try this" is written down before the
 * try, not after.
 */
import { randomUUID } from 'node:crypto';
import { db } from '../db/index.js';
import type { ErrorCodeName } from '../utils/errors.js';

export type MessageStatus = 'queued' | 'sending' | 'sent' | 'failed';

export interface MessageRow {
  id: string;
  phone: string;
  message: string;
  template: string | null;
  status: MessageStatus;
  attempts: number;
  error_code: string | null;
  error: string | null;
  wa_message_id: string | null;
  created_at: number;
  scheduled_at: number;
  sent_at: number | null;
  failed_at: number | null;
}

/** What a caller is told about a message. Never includes the body. */
export interface MessageView {
  id: string;
  status: MessageStatus;
  attempts: number;
  template: string | null;
  createdAt: number;
  scheduledAt: number;
  sentAt: number | null;
  failedAt: number | null;
  error: { code: string; message: string } | null;
}

export const toView = (row: MessageRow): MessageView => ({
  id: row.id,
  status: row.status,
  attempts: row.attempts,
  template: row.template,
  createdAt: row.created_at,
  scheduledAt: row.scheduled_at,
  sentAt: row.sent_at,
  failedAt: row.failed_at,
  error: row.error_code ? { code: row.error_code, message: row.error || '' } : null,
});

const insert = db.prepare(`
  INSERT INTO messages (id, phone, message, template, status, attempts, created_at, scheduled_at)
  VALUES (@id, @phone, @message, @template, 'queued', 0, @now, @scheduledAt)
`);

const byId = db.prepare('SELECT * FROM messages WHERE id = ?');

export function create(input: {
  phone: string;
  message: string;
  template?: string | null;
  scheduledAt?: number;
}): MessageRow {
  const id = randomUUID();
  const now = Date.now();
  insert.run({
    id,
    phone: input.phone,
    message: input.message,
    template: input.template ?? null,
    now,
    scheduledAt: input.scheduledAt ?? now,
  });
  return byId.get(id) as MessageRow;
}

export const get = (id: string): MessageRow | undefined => byId.get(id) as MessageRow | undefined;

/* Taking a message off the queue is one transaction: find the oldest due one
   and mark it 'sending' in the same breath. Two workers could otherwise read
   the same row and send it twice — which, to the soldier, is the gateway
   messaging them twice. */
const pick = db.prepare(`
  SELECT id FROM messages
  WHERE status = 'queued' AND scheduled_at <= ?
  ORDER BY scheduled_at, created_at
  LIMIT 1
`);

const take = db.prepare(`
  UPDATE messages SET status = 'sending', attempts = attempts + 1
  WHERE id = ? AND status = 'queued'
`);

export const claimNext = db.transaction((now: number): MessageRow | null => {
  const row = pick.get(now) as { id: string } | undefined;
  if (!row) return null;
  const res = take.run(row.id);
  if (res.changes !== 1) return null;
  return byId.get(row.id) as MessageRow;
});

const sent = db.prepare(`
  UPDATE messages SET status = 'sent', wa_message_id = ?, sent_at = ?, error_code = NULL, error = NULL
  WHERE id = ?
`);

const failed = db.prepare(`
  UPDATE messages SET status = 'failed', error_code = ?, error = ?, failed_at = ?
  WHERE id = ?
`);

const retry = db.prepare(`
  UPDATE messages SET status = 'queued', scheduled_at = ?, error_code = ?, error = ?
  WHERE id = ?
`);

export const markSent = (id: string, waMessageId: string | null, now = Date.now()) =>
  void sent.run(waMessageId, now, id);

export const markFailed = (id: string, code: ErrorCodeName, message: string, now = Date.now()) =>
  void failed.run(code, message, now, id);

export const reschedule = (id: string, at: number, code: ErrorCodeName, message: string) =>
  void retry.run(at, code, message, id);

/* A process that dies mid-send leaves a row saying 'sending' with nobody
   sending it. On boot those go back on the queue; the attempt was already
   counted, so a message that repeatedly kills the process still runs out of
   retries instead of looping forever. */
const recover = db.prepare(`UPDATE messages SET status = 'queued' WHERE status = 'sending'`);

export const recoverStuck = (): number => recover.run().changes;

const listStmt = db.prepare(`
  SELECT * FROM messages ORDER BY created_at DESC LIMIT ? OFFSET ?
`);

export const recent = (limit = 50, offset = 0): MessageRow[] =>
  listStmt.all(Math.min(limit, 200), offset) as MessageRow[];

const countStmt = db.prepare(`
  SELECT status, COUNT(*) AS n FROM messages GROUP BY status
`);

export function counts(): Record<MessageStatus, number> {
  const out: Record<MessageStatus, number> = { queued: 0, sending: 0, sent: 0, failed: 0 };
  for (const r of countStmt.all() as { status: MessageStatus; n: number }[]) out[r.status] = r.n;
  return out;
}

const dueStmt = db.prepare(`SELECT COUNT(*) AS n FROM messages WHERE status = 'queued'`);

export const pending = (): number => (dueStmt.get() as { n: number }).n;

/* The gateway is a queue, not an archive. Bodies of delivered messages are
   the most sensitive thing it holds and the least useful to keep. */
const scrub = db.prepare(`
  UPDATE messages SET message = '' WHERE message <> '' AND status IN ('sent','failed') AND created_at < ?
`);

const drop = db.prepare(`DELETE FROM messages WHERE status IN ('sent','failed') AND created_at < ?`);

export const scrubBodies = (before: number): number => scrub.run(before).changes;
export const purge = (before: number): number => drop.run(before).changes;
