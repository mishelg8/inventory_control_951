/* The sender.
 *
 * Nothing in the HTTP layer ever calls WhatsApp. A request writes a row and
 * returns; this loop is the only thing that sends. That separation is what
 * makes the two hard requirements possible at once: the console gets an
 * instant answer even when Chromium is halfway through a reconnect, and the
 * message still goes out afterwards.
 *
 * The loop is deliberately unclever. One message at a time, wait when told to
 * wait, write down every outcome.
 */
import { config } from '../../config/index.js';
import { log } from '../../utils/logger.js';
import { AppError, ErrorCode, codeOf, isTransient } from '../../utils/errors.js';
import * as messages from '../../repositories/messages.js';
import { whatsapp } from '../whatsapp/client.js';
import { RateLimiter } from './limiter.js';

const IDLE_POLL_MS = 1_000;
const OFFLINE_POLL_MS = 5_000;

export const limiter = new RateLimiter({
  perMinute: config.MAX_MESSAGES_PER_MINUTE,
  perSecond: config.MAX_MESSAGES_PER_SECOND,
  delayMinMs: config.MESSAGE_DELAY_MIN_MS,
  delayMaxMs: config.MESSAGE_DELAY_MAX_MS,
});

const sleep = (ms: number) =>
  new Promise<void>((resolve) => {
    const t = setTimeout(resolve, ms);
    t.unref?.();
  });

let running = false;
let workers: Promise<void>[] = [];

/** How long to wait before attempt number `n` (1-based). */
function backoffFor(attempts: number): number {
  const table = config.RETRY_BACKOFF_MS;
  return table[Math.min(attempts - 1, table.length - 1)] ?? table[table.length - 1] ?? 60_000;
}

async function attempt(row: messages.MessageRow): Promise<void> {
  const jid = `${row.phone}@c.us`;
  try {
    const waId = await whatsapp.send(jid, row.message);
    limiter.record();
    messages.markSent(row.id, waId);
    log.info('queue.sent', { id: row.id, phone: row.phone, attempts: row.attempts, template: row.template });
    return;
  } catch (e) {
    const code = codeOf(e);
    const detail = e instanceof AppError ? e.message : 'שגיאה לא צפויה';

    /* A send that failed because the client is not connected did not consume
       anything — it should not consume a retry either, or a ten-minute outage
       would burn every message's budget while the queue was helpless. */
    if (code === ErrorCode.WHATSAPP_NOT_CONNECTED) {
      messages.reschedule(row.id, Date.now() + OFFLINE_POLL_MS, code, detail);
      return;
    }

    if (!isTransient(e) || row.attempts > config.MAX_RETRIES) {
      messages.markFailed(row.id, code, detail);
      log.warn('queue.gave_up', { id: row.id, phone: row.phone, attempts: row.attempts, code });
      return;
    }

    const at = Date.now() + backoffFor(row.attempts);
    messages.reschedule(row.id, at, code, detail);
    log.info('queue.retry', { id: row.id, attempts: row.attempts, code, inMs: at - Date.now() });
  }
}

async function loop(): Promise<void> {
  while (running) {
    if (!whatsapp.ready) {
      await sleep(OFFLINE_POLL_MS);
      continue;
    }

    const wait = limiter.delayFor();
    if (wait > 0) {
      await sleep(Math.min(wait, 2_000));
      continue;
    }

    const row = messages.claimNext(Date.now());
    if (!row) {
      await sleep(IDLE_POLL_MS);
      continue;
    }

    try {
      await attempt(row);
    } catch (e) {
      /* attempt() is not supposed to throw. If it does, the row must not be
         left marked 'sending' with nobody sending it. */
      log.error('queue.attempt_threw', { id: row.id, error: e instanceof Error ? e.message : String(e) });
      messages.reschedule(row.id, Date.now() + 30_000, ErrorCode.INTERNAL_ERROR, 'שגיאה פנימית');
    }
  }
}

export function startQueue(): void {
  if (running) return;
  running = true;
  const recovered = messages.recoverStuck();
  if (recovered) log.warn('queue.recovered', { count: recovered });
  workers = Array.from({ length: config.QUEUE_CONCURRENCY }, () => loop());
  log.info('queue.started', { workers: config.QUEUE_CONCURRENCY, pending: messages.pending() });
}

export async function stopQueue(): Promise<void> {
  if (!running) return;
  running = false;
  await Promise.allSettled(workers);
  workers = [];
  log.info('queue.stopped');
}

export const queueStats = () => ({
  running,
  workers: running ? config.QUEUE_CONCURRENCY : 0,
  pending: messages.pending(),
  nextSendInMs: limiter.delayFor(),
  counts: messages.counts(),
});
