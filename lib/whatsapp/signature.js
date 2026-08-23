/* X-Hub-Signature-256.
 *
 * The webhook URL is public and its shape is documented by Meta, so anyone
 * can POST to it. The signature is the only thing that separates an event
 * Meta sent from an event someone made up, and a made-up event writes rows
 * into the database and can mark a message as read. It is checked before the
 * body is parsed, never after.
 *
 * The comparison is constant-time. A byte-at-a-time comparison leaks where
 * the first difference is, and a few thousand requests turn that into the
 * signature — the same reason the login path here compares its verifier the
 * same way.
 */

const enc = new TextEncoder();

const hex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * @param {string} rawBody  the body exactly as received — not re-serialised.
 *                          JSON.stringify(JSON.parse(x)) is not x, and the
 *                          signature is over the bytes Meta sent.
 * @param {string} header   the X-Hub-Signature-256 value, 'sha256=<hex>'
 * @param {string} appSecret
 */
export async function verifySignature(rawBody, header, appSecret) {
  if (!appSecret) return { ok: false, reason: 'no-secret' };
  if (typeof header !== 'string' || !header.startsWith('sha256=')) {
    return { ok: false, reason: 'no-signature' };
  }
  const given = header.slice('sha256='.length).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(given)) return { ok: false, reason: 'malformed' };

  const key = await crypto.subtle.importKey(
    'raw', enc.encode(appSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const mac = hex(await crypto.subtle.sign('HMAC', key, enc.encode(rawBody)));

  return timingSafeEqual(mac, given) ? { ok: true } : { ok: false, reason: 'mismatch' };
}

/** The verification handshake token, compared the same careful way. */
export const verifyTokenMatches = (given, expected) =>
  !!expected && timingSafeEqual(String(given || ''), String(expected));
