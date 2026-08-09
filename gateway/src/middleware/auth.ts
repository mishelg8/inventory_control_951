/* Who is allowed to make this account send a message.
 *
 * The gateway is reachable over the internet and attached to a real WhatsApp
 * line, so "knows the URL" cannot be the credential. Every request carries an
 * HMAC over its own timestamp, method, path and body — which means a captured
 * request cannot be replayed against a different path, cannot be edited, and
 * goes stale on its own.
 *
 * The secret lives in the Cloudflare Worker and here. It never reaches a
 * browser.
 */
import { createHmac, timingSafeEqual, createHash } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { config } from '../config/index.js';
import { AppError, ErrorCode } from '../utils/errors.js';

export const SIGNATURE_HEADER = 'x-signature';
export const TIMESTAMP_HEADER = 'x-timestamp';

/** The exact bytes that get signed. Both sides must build this identically. */
export const signingString = (timestamp: string, method: string, path: string, body: string) =>
  [timestamp, method.toUpperCase(), path, createHash('sha256').update(body).digest('hex')].join('\n');

export const sign = (timestamp: string, method: string, path: string, body: string, secret: string) =>
  createHmac('sha256', secret).update(signingString(timestamp, method, path, body)).digest('hex');

const equal = (a: string, b: string): boolean => {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
};

const header = (req: Request, name: string): string => {
  const v = req.headers[name];
  return typeof v === 'string' ? v : '';
};

export function requireSignature(req: Request, _res: Response, next: NextFunction): void {
  const ts = header(req, TIMESTAMP_HEADER);
  const given = header(req, SIGNATURE_HEADER);

  if (!ts || !given) {
    next(new AppError(ErrorCode.AUTH_REQUIRED, 'הבקשה אינה חתומה'));
    return;
  }

  const seconds = Number(ts);
  if (!Number.isFinite(seconds)) {
    next(new AppError(ErrorCode.AUTH_REQUIRED, 'חותמת זמן שגויה'));
    return;
  }

  const skew = Math.abs(Date.now() / 1000 - seconds);
  if (skew > config.SIGNATURE_MAX_SKEW_SECONDS) {
    next(new AppError(ErrorCode.AUTH_REQUIRED, 'חותמת הזמן של הבקשה אינה בתוקף'));
    return;
  }

  /* The raw body, byte for byte as it arrived. Signing the parsed object would
     let anyone who can change JSON formatting change the signed content. */
  const raw = (req as Request & { rawBody?: string }).rawBody ?? '';

  /* originalUrl, not path: inside a mounted router `req.path` has had the
     mount point stripped, so the router would verify "/status" against a
     caller who quite reasonably signed "/api/status". It also keeps the query
     string under the signature, so ?limit= cannot be edited in transit. */
  const expected = sign(ts, req.method, req.originalUrl, raw, config.API_SECRET);

  if (!equal(given, expected)) {
    next(new AppError(ErrorCode.AUTH_REQUIRED, 'חתימת הבקשה שגויה'));
    return;
  }

  next();
}
