/* Every knob the gateway has, read once, validated once, and frozen.
 *
 * Nothing else in the service reads process.env. A missing secret or a
 * nonsensical rate limit fails here, at boot, with a message naming the
 * variable — rather than at three in the morning when the first message goes
 * out unthrottled.
 */
import { z } from 'zod';

const csv = (v: string) =>
  v.split(',').map((s) => s.trim()).filter(Boolean);

const backoff = z.string().transform((v, ctx) => {
  const parts = csv(v).map(Number);
  if (!parts.length || parts.some((n) => !Number.isFinite(n) || n < 0)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'expected comma-separated milliseconds' });
    return z.NEVER;
  }
  return parts;
});

const schema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('production'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  /* The whole security boundary is this string. A gateway with a weak or
     absent secret is an open relay attached to a real WhatsApp account, so
     it refuses to start rather than start unprotected. */
  API_SECRET: z.string().min(32, 'API_SECRET must be at least 32 characters'),
  SIGNATURE_MAX_SKEW_SECONDS: z.coerce.number().int().min(5).max(3600).default(300),

  SESSION_PATH: z.string().min(1).default('/data/whatsapp'),
  DATABASE_PATH: z.string().min(1).default('/data/gateway.db'),

  MAX_MESSAGES_PER_MINUTE: z.coerce.number().int().min(1).max(600).default(12),
  MAX_MESSAGES_PER_SECOND: z.coerce.number().int().min(1).max(20).default(1),
  MESSAGE_DELAY_MIN_MS: z.coerce.number().int().min(0).default(3000),
  MESSAGE_DELAY_MAX_MS: z.coerce.number().int().min(0).default(9000),
  QUEUE_CONCURRENCY: z.coerce.number().int().min(1).max(4).default(1),

  MAX_RETRIES: z.coerce.number().int().min(0).max(10).default(3),
  RETRY_BACKOFF_MS: backoff.default('5000,15000,60000'),

  IDEMPOTENCY_TTL_SECONDS: z.coerce.number().int().min(60).default(86400),

  /* The gateway is a queue, not an archive. A delivered message's text is the
     most sensitive thing on this disk and the least useful to keep, so it is
     blanked long before the row itself is dropped. */
  BODY_RETENTION_HOURS: z.coerce.number().int().min(1).max(720).default(24),
  MESSAGE_RETENTION_DAYS: z.coerce.number().int().min(1).max(365).default(30),

  DEFAULT_COUNTRY_CODE: z.string().regex(/^\d{1,4}$/).default('972'),

  ALLOWED_ORIGINS: z.string().default('').transform(csv),
  ALLOWED_IPS: z.string().default('').transform(csv),
  TRUST_PROXY: z.coerce.number().int().min(0).max(10).default(1),
  BODY_LIMIT: z.string().default('32kb'),

  PUPPETEER_EXECUTABLE_PATH: z.string().default(''),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  const lines = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`);
  console.error(`invalid configuration:\n${lines.join('\n')}`);
  process.exit(1);
}

const raw = parsed.data;

if (raw.MESSAGE_DELAY_MAX_MS < raw.MESSAGE_DELAY_MIN_MS) {
  console.error('invalid configuration:\n  MESSAGE_DELAY_MAX_MS must be >= MESSAGE_DELAY_MIN_MS');
  process.exit(1);
}

export const config = Object.freeze({
  ...raw,
  isProduction: raw.NODE_ENV === 'production',
});

export type Config = typeof config;
