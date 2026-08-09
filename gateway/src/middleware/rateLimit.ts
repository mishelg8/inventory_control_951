/* A ceiling on requests, separate from the ceiling on messages.
 *
 * The queue already limits how fast WhatsApp is talked to. This limits how
 * fast the *API* is talked to, which is a different problem: a loop calling
 * POST /api/messages ten thousand times would not send ten thousand messages,
 * but it would happily fill the disk with rows waiting to be sent.
 *
 * In-memory and per-process, which is right for a service that is one process
 * by construction.
 */
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { AppError, ErrorCode } from '../utils/errors.js';

interface Window {
  hits: number;
  until: number;
}

export function rateLimit(opts: { limit: number; windowMs: number; key?: (req: Request) => string }): RequestHandler {
  const buckets = new Map<string, Window>();
  const keyOf = opts.key ?? ((req: Request) => req.ip || req.socket.remoteAddress || 'unknown');

  /* Lapsed windows are dropped on read, but a key that is never seen again
     would linger forever. A periodic sweep keeps the map the size of the
     traffic rather than the size of history. */
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, w] of buckets) if (w.until <= now) buckets.delete(k);
  }, Math.max(opts.windowMs, 60_000));
  sweep.unref?.();

  return (req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    const key = keyOf(req);
    const cur = buckets.get(key);

    if (!cur || cur.until <= now) {
      buckets.set(key, { hits: 1, until: now + opts.windowMs });
      next();
      return;
    }

    cur.hits += 1;
    if (cur.hits > opts.limit) {
      res.setHeader('Retry-After', String(Math.ceil((cur.until - now) / 1000)));
      next(new AppError(ErrorCode.RATE_LIMITED, 'יותר מדי בקשות, נסו שוב מאוחר יותר'));
      return;
    }
    next();
  };
}
