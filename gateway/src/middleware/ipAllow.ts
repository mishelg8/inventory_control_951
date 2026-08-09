/* An optional second lock.
 *
 * The HMAC is the real defence. This is for the deployment where the host is
 * on the open internet and there is no reason for anything but Cloudflare to
 * reach it: a wrong signature still costs a request, a wrong source address
 * costs nothing.
 *
 * Empty ALLOWED_IPS disables the check, deliberately — most people will run
 * this behind a tunnel where the source address is meaningless.
 */
import type { Request, Response, NextFunction } from 'express';
import { config } from '../config/index.js';
import { log } from '../utils/logger.js';
import { AppError, ErrorCode } from '../utils/errors.js';

interface V4Rule {
  base: number;
  mask: number;
}

const toV4 = (ip: string): number | null => {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
};

/** ::ffff:1.2.3.4 is how Node reports an IPv4 client on a dual-stack socket. */
const unwrap = (ip: string): string => (ip.startsWith('::ffff:') ? ip.slice(7) : ip);

const v4Rules: V4Rule[] = [];
const literals = new Set<string>();

for (const entry of config.ALLOWED_IPS) {
  const [addr = '', bitsRaw] = entry.split('/');
  const base = toV4(addr);
  if (base === null) {
    literals.add(unwrap(entry).toLowerCase());
    continue;
  }
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) {
    log.warn('ipallow.bad_entry', { entry });
    continue;
  }
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  v4Rules.push({ base: (base & mask) >>> 0, mask });
}

export const enabled = v4Rules.length > 0 || literals.size > 0;

export function permitted(ip: string): boolean {
  if (!enabled) return true;
  const clean = unwrap(ip).toLowerCase();
  if (literals.has(clean)) return true;
  const v4 = toV4(clean);
  if (v4 === null) return false;
  return v4Rules.some((r) => ((v4 & r.mask) >>> 0) === r.base);
}

export function ipAllowlist(req: Request, _res: Response, next: NextFunction): void {
  if (!enabled) {
    next();
    return;
  }
  const ip = req.ip || req.socket.remoteAddress || '';
  if (permitted(ip)) {
    next();
    return;
  }
  log.warn('ipallow.rejected', { ip, path: req.path });
  next(new AppError(ErrorCode.AUTH_REQUIRED, 'הבקשה נדחתה'));
}
