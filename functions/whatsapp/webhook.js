/* The public endpoint Meta talks to.
 *
 * Deliberately not under /api. That path is one catch-all function whose first
 * job is to find a session cookie, and this request has none and never will —
 * routing it through there would mean an authentication path with a hole in
 * it shaped exactly like a webhook. A separate file is a separate door.
 *
 *   GET   the verification handshake, once, when the URL is saved in Meta.
 *   POST  events. Answered immediately; the work happens after the answer.
 *
 * Meta's rule for POST is a fast 200. Anything slower is treated as a failure
 * and redelivered, so slow work here does not delay an event — it duplicates
 * it. The body is validated and handed to waitUntil, which keeps the Worker
 * alive after the response has already gone back.
 */

import { waConfig } from '../../lib/whatsapp/config.js';
import { verifySignature, verifyTokenMatches } from '../../lib/whatsapp/signature.js';
import { normalizeWebhook } from '../../lib/whatsapp/normalize.js';
import { processWebhook } from '../../lib/whatsapp/service.js';
import { waLog } from '../../lib/whatsapp/log.js';

const text = (body, status = 200) =>
  new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });

// Meta ignores our body on POST and reads only the status. Keep it tiny.
const ack = (status = 200) => new Response(null, { status });

// Larger than any real event; a body past this is not one of Meta's.
const MAX_BODY = 512 * 1024;

export async function onRequest(context) {
  const { request, env, waitUntil } = context;
  const cfg = waConfig(env);

  if (request.method === 'GET') {
    const q = new URL(request.url).searchParams;
    const mode = q.get('hub.mode');
    const token = q.get('hub.verify_token');
    const challenge = q.get('hub.challenge');

    if (mode !== 'subscribe') {
      waLog.warn('webhook.verify.bad-mode', { mode });
      return text('forbidden', 403);
    }
    if (!verifyTokenMatches(token, cfg.verifyToken)) {
      /* Which half was wrong is not said, here or in the log. A verify token
         is a shared secret and "wrong token" versus "no token configured" is
         a distinction useful mainly to whoever is guessing. */
      waLog.warn('webhook.verify.rejected', { configured: !!cfg.verifyToken });
      return text('forbidden', 403);
    }

    waLog.info('webhook.verify.ok', {});
    // Meta wants the challenge back verbatim, as plain text, nothing else.
    return text(challenge == null ? '' : String(challenge), 200);
  }

  if (request.method !== 'POST') return text('method not allowed', 405);

  /* Fail closed. Without the app secret there is no way to tell an event Meta
     sent from one anybody sent, and this endpoint writes to the database. An
     unconfigured integration accepts nothing rather than accepting everything. */
  if (!cfg.appSecret) {
    waLog.error('webhook.no-app-secret', { note: 'WHATSAPP_APP_SECRET is not set; rejecting' });
    return ack(403);
  }

  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > MAX_BODY) {
    waLog.warn('webhook.too-large', { len });
    return ack(413);
  }

  /* The raw bytes, exactly as sent. The signature is over these; re-encoding
     a parsed object changes key order and whitespace and produces a mismatch
     that looks like an attack and is a bug. */
  let raw;
  try {
    raw = await request.text();
  } catch {
    return ack(400);
  }
  if (raw.length > MAX_BODY) return ack(413);

  const sig = await verifySignature(raw, request.headers.get('X-Hub-Signature-256'), cfg.appSecret);
  if (!sig.ok) {
    waLog.error('webhook.signature.failed', { reason: sig.reason, bytes: raw.length });
    return ack(403);
  }

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    waLog.warn('webhook.bad-json', { bytes: raw.length });
    return ack(400);
  }

  const normalized = normalizeWebhook(payload);
  if (!normalized.ok) {
    waLog.warn('webhook.ignored', { reason: normalized.reason });
    return ack(200);   // not ours, but not a failure either — do not make Meta retry
  }

  /* One WABA, named in the environment. An event from another is dropped
     here: a duplicate business account pointed at the same URL is a real
     thing that happens, and it must not be able to write rows. */
  if (cfg.wabaId && normalized.wabaId && normalized.wabaId !== cfg.wabaId) {
    waLog.warn('webhook.foreign-waba', { got: normalized.wabaId, expected: cfg.wabaId });
    return ack(200);
  }

  const counts = normalized.batches.reduce(
    (a, b) => ({ m: a.m + b.messages.length, s: a.s + b.statuses.length }),
    { m: 0, s: 0 }
  );
  waLog.info('webhook.received', { messages: counts.m, statuses: counts.s, bytes: raw.length });

  /* The answer goes now; the writing happens after it. If the work throws,
     Meta has already been told 200 and will not retry — so it is logged here
     rather than surfaced, and the ledger makes a manual replay safe. */
  const work = processWebhook(env.DB, env, normalized).catch((e) => {
    waLog.error('webhook.processing-failed', { note: String((e && e.message) || e) });
  });
  if (typeof waitUntil === 'function') waitUntil(work);
  else await work;

  return ack(200);
}
