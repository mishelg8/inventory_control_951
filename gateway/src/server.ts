/* Wiring, and the order it goes in.
 *
 * The order below is the security model, so it is worth reading as one list
 * rather than as a pile of app.use calls: address first, then volume, then
 * signature, then the route. Nothing that talks to WhatsApp sits above the
 * signature check, and /health sits above all of it on purpose — a liveness
 * probe that needs a shared secret is a liveness probe that breaks the day
 * the secret rotates.
 */
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { config } from './config/index.js';
import { log } from './utils/logger.js';
import { db, closeDb } from './db/index.js';
import { whatsapp } from './services/whatsapp/client.js';
import { startQueue, stopQueue } from './services/queue/index.js';
import { requireSignature } from './middleware/auth.js';
import { ipAllowlist, enabled as ipCheckEnabled } from './middleware/ipAllow.js';
import { rateLimit } from './middleware/rateLimit.js';
import { errorHandler, notFound } from './middleware/error.js';
import { health } from './routes/health.js';
import { connection } from './routes/connection.js';
import { messageRoutes } from './routes/messages.js';
import * as messages from './repositories/messages.js';
import * as idempotency from './repositories/idempotency.js';
import * as events from './repositories/events.js';
import * as numbers from './repositories/numbers.js';

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', config.TRUST_PROXY);

/* No browser ever loads a page from here — every response is JSON to a
   server. The CSP and the frame rules cost nothing and close the door on
   the day someone points a browser at it anyway. */
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'none'"] } } }));

/* Cross-origin is off by default and stays off unless someone lists an origin.
   The only intended caller is a Cloudflare Worker, which has no origin. */
app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  if (origin && config.ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Signature, X-Timestamp');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  }
  if (req.method === 'OPTIONS') {
    res.sendStatus(origin && config.ALLOWED_ORIGINS.includes(origin) ? 204 : 403);
    return;
  }
  next();
});

app.use('/', health);

/* The signature covers the bytes that arrived, so those bytes have to be kept
   before anything reformats them. */
app.use(
  express.json({
    limit: config.BODY_LIMIT,
    verify: (req, _res, buf) => {
      (req as Request & { rawBody?: string }).rawBody = buf.toString('utf8');
    },
  }),
);

const api = express.Router();
api.use(ipAllowlist);
api.use(rateLimit({ limit: 300, windowMs: 60_000 }));
api.use(requireSignature);
api.use(connection);
api.use(messageRoutes);

app.use('/api', api);

app.use(notFound);
app.use(errorHandler);

/* ── Housekeeping ──────────────────────────────────────────────────── */

const HOUR_MS = 60 * 60 * 1000;

function maintenance() {
  const now = Date.now();
  const scrubbed = messages.scrubBodies(now - config.BODY_RETENTION_HOURS * HOUR_MS);
  const purged = messages.purge(now - config.MESSAGE_RETENTION_DAYS * 24 * HOUR_MS);
  const keys = idempotency.sweep(now);
  const stale = numbers.sweep(now - 30 * 24 * HOUR_MS);
  events.keepLast(500);
  if (scrubbed || purged || keys || stale) {
    log.info('maintenance', { scrubbed, purged, keys, stale });
  }
}

/* ── Boot ──────────────────────────────────────────────────────────── */

/* whatsapp-web.js's LocalAuth keeps its files under <dataPath>/session. If
   they are there, a restart should come back on its own; if they are not,
   starting would only spin Chromium up to print QR codes nobody is looking
   at, so it waits for someone to press connect. */
const hasSession = () => existsSync(join(config.SESSION_PATH, 'session'));

const server = createServer(app);

server.listen(config.PORT, () => {
  log.info('server.listening', {
    port: config.PORT,
    env: config.NODE_ENV,
    ipAllowlist: ipCheckEnabled,
    perMinute: config.MAX_MESSAGES_PER_MINUTE,
  });

  maintenance();
  const chores = setInterval(maintenance, HOUR_MS);
  chores.unref?.();

  startQueue();

  if (hasSession()) {
    log.info('wa.session_found');
    void whatsapp.start();
  } else {
    log.info('wa.no_session', { hint: 'POST /api/connect to get a QR code' });
  }
});

/* ── Shutdown ──────────────────────────────────────────────────────── */

let closing = false;

async function shutdown(signal: string) {
  if (closing) return;
  closing = true;
  log.info('server.shutdown', { signal });

  /* Order matters. Stop accepting work, let the sender finish the message it
     is holding, close the browser, then the database — a queue worker writing
     to a closed database is the one way a shutdown loses a message. */
  server.close();
  await stopQueue();
  await whatsapp.stop();
  closeDb();

  log.info('server.stopped');
  process.exit(0);
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  log.error('process.unhandled_rejection', {
    error: reason instanceof Error ? reason.message : String(reason),
    stack: reason instanceof Error ? reason.stack : undefined,
  });
});

process.on('uncaughtException', (err) => {
  log.error('process.uncaught_exception', { error: err.message, stack: err.stack });
  /* An unknown broken state holding a live WhatsApp session is worse than a
     restart: the container comes back, the session is on disk, the queue is
     in the database, and nothing is lost. */
  void shutdown('uncaughtException');
});

export { app, server, db };
