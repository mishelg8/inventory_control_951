/* Structured logs for the WhatsApp integration.
 *
 * Workers give us console.*, which Cloudflare collects; one JSON object per
 * line is what makes those lines searchable later. The reason this is a module
 * rather than a call to console.log at each site is the redaction: there is
 * exactly one function that turns a value into a log field, and it refuses to
 * print a token no matter who passes it one.
 */

import { maskPhone } from '../../public/lib/phone.js';

/* Anything whose name says secret is dropped before serialising, and any long
 * unbroken run of token-ish characters in a free-text field is replaced.
 * Both, because the first catches the field we named and the second catches
 * the one Meta echoed back inside a message string. */
const SECRET_KEY = /token|secret|authorization|password|signature|appsecret/i;
const SECRET_RUN = /\b[A-Za-z0-9_-]{40,}\b/g;

const scrub = (v) => {
  if (typeof v === 'string') return v.replace(SECRET_RUN, '…').slice(0, 500);
  if (v && typeof v === 'object') return redact(v);
  return v;
};

function redact(obj) {
  if (Array.isArray(obj)) return obj.slice(0, 20).map(scrub);
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SECRET_KEY.test(k)) { out[k] = '[redacted]'; continue; }
    out[k] = scrub(v);
  }
  return out;
}

/** Phone numbers in logs are masked, always — this app logs no one's number. */
export const logPhone = (e164) => maskPhone(e164);

function emit(level, event, fields) {
  const line = { at: new Date().toISOString(), level, ch: 'whatsapp', event, ...redact(fields || {}) };
  let text;
  try {
    text = JSON.stringify(line);
  } catch {
    text = JSON.stringify({ at: line.at, level, ch: 'whatsapp', event, note: 'unserialisable fields' });
  }
  if (level === 'error') console.error(text);
  else if (level === 'warn') console.warn(text);
  else console.log(text);
}

export const waLog = {
  info:  (event, fields) => emit('info', event, fields),
  warn:  (event, fields) => emit('warn', event, fields),
  error: (event, fields) => emit('error', event, fields),
};
