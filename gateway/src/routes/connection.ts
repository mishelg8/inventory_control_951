/* The session's controls: look at it, scan it, restart it, unlink it.
 *
 * These are the only endpoints a human drives directly. They are also the only
 * ones that can take a working gateway offline, so each says plainly what it
 * did and the destructive one is not reachable by accident.
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import { whatsapp } from '../services/whatsapp/client.js';
import { queueStats } from '../services/queue/index.js';
import * as events from '../repositories/events.js';
import { log } from '../utils/logger.js';

export const connection = Router();

const snapshot = () => ({
  success: true as const,
  whatsapp: whatsapp.status(),
  queue: queueStats(),
});

/** Everything the console's WhatsApp panel draws itself from. */
connection.get('/status', (_req: Request, res: Response) => {
  res.json({ ...snapshot(), events: events.recent(15) });
});

/** Just the QR, for a panel that polls while someone is holding a phone up. */
connection.get('/qr', (_req: Request, res: Response) => {
  const s = whatsapp.status();
  res.json({ success: true, state: s.state, qr: s.qr });
});

connection.post('/connect', async (_req: Request, res: Response) => {
  const status = await whatsapp.start();
  res.json({ success: true, whatsapp: status });
});

connection.post('/reconnect', async (_req: Request, res: Response) => {
  log.info('wa.reconnect_requested');
  const status = await whatsapp.reconnect();
  res.json({ success: true, whatsapp: status });
});

/* Deletes the stored session. The next connect needs a human with the phone,
   so this is the one button that cannot be undone from the console. */
connection.post('/logout', async (_req: Request, res: Response) => {
  log.warn('wa.logout_requested');
  const status = await whatsapp.logout();
  res.json({ success: true, whatsapp: status });
});

/* Server-sent events, for anything watching the gateway directly. The console
   polls /status instead — it reaches the gateway through the Worker, and a
   polled JSON endpoint survives that hop with far less to go wrong. */
connection.get('/events', (req: Request, res: Response) => {
  res.set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders?.();

  const send = (data: unknown) => res.write(`data: ${JSON.stringify(data)}\n\n`);
  send(snapshot());

  const onStatus = () => send(snapshot());
  whatsapp.on('status', onStatus);

  // Proxies drop a stream that goes quiet. A comment is not an event.
  const beat = setInterval(() => res.write(': ping\n\n'), 25_000);
  beat.unref?.();

  req.on('close', () => {
    clearInterval(beat);
    whatsapp.off('status', onStatus);
  });
});
