/* Structured logs, with a list of things that must never appear in one.
 *
 * The session directory holds a working login for a real WhatsApp account,
 * and the messages carry soldiers' names and telephone numbers. Neither
 * belongs in a log that gets shipped somewhere to be searched, so the
 * redactor runs over every field rather than relying on call sites to
 * remember.
 */
import { config } from '../config/index.js';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 } as const;
type Level = keyof typeof LEVELS;

const SECRET_KEY = /(secret|token|password|cookie|credential|signature|apikey|api_key|auth)/i;

/* A telephone number keeps its country code and its last two digits. Enough
   to match a log line against a complaint; not enough to be a contact list. */
export const maskPhone = (phone: string): string => {
  const s = String(phone);
  return s.length <= 6 ? '***' : `${s.slice(0, 4)}***${s.slice(-2)}`;
};

const redact = (value: unknown, key = ''): unknown => {
  if (SECRET_KEY.test(key)) return '[redacted]';
  if (typeof value === 'string') {
    if (key === 'phone' || key === 'to') return maskPhone(value);
    // Message bodies are private. Their length is the useful part.
    if (key === 'message' || key === 'body') return `[${value.length} chars]`;
    return value.length > 500 ? `${value.slice(0, 500)}…` : value;
  }
  if (Array.isArray(value)) return value.map((v) => redact(v));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = redact(v, k);
    return out;
  }
  return value;
};

const threshold = LEVELS[config.LOG_LEVEL as Level];

function emit(level: Level, event: string, fields?: Record<string, unknown>) {
  if (LEVELS[level] < threshold) return;
  const line = {
    t: new Date().toISOString(),
    level,
    event,
    ...(fields ? (redact(fields) as Record<string, unknown>) : {}),
  };
  const out = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  out.write(`${JSON.stringify(line)}\n`);
}

export const log = {
  debug: (event: string, fields?: Record<string, unknown>) => emit('debug', event, fields),
  info: (event: string, fields?: Record<string, unknown>) => emit('info', event, fields),
  warn: (event: string, fields?: Record<string, unknown>) => emit('warn', event, fields),
  error: (event: string, fields?: Record<string, unknown>) => emit('error', event, fields),
};
