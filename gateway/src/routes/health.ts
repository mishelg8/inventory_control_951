/* Two different questions that get confused with each other.
 *
 * /health asks "is this process alive" — Docker restarts the container when it
 * says no, so it must not say no merely because a phone is out of battery.
 * /ready asks "can it send right now", which is the one a load balancer or an
 * operator dashboard wants.
 *
 * Both are unsigned: a health check that needs a shared secret is a health
 * check that stops working the day the secret rotates.
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import { whatsapp } from '../services/whatsapp/client.js';
import { queueStats } from '../services/queue/index.js';

export const health = Router();

const startedAt = Date.now();

health.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', uptimeMs: Date.now() - startedAt });
});

health.get('/ready', (_req: Request, res: Response) => {
  const wa = whatsapp.status();
  const q = queueStats();
  const ready = wa.state === 'ready' && q.running;
  res.status(ready ? 200 : 503).json({
    status: ready ? 'ready' : 'not_ready',
    whatsapp: wa.state,
    queue: { running: q.running, pending: q.pending },
  });
});
