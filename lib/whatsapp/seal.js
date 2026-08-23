/* Sealing, on the server side, with the public half of the key.
 *
 * This mirrors seal()/sealBytes() in public/lib/crypto.js exactly — same
 * envelope, same field names — so a row written by the webhook opens in the
 * console with the same code that opens a record written by a soldier's phone.
 *
 * Worth being explicit about what this does and does not buy. The Worker
 * necessarily sees an inbound message in the clear for as long as it takes to
 * seal it: Meta sends plaintext and there is no arrangement under which it
 * does not. What sealing removes is the durable copy. Nothing personal is
 * ever written to D1 in the clear, so a database that leaks, a backup that
 * walks, or an administrator with console access still yields nothing without
 * a password that lives only in someone's head. The Worker cannot read back
 * what it wrote a moment ago, because it has never held the private key.
 */

const te = new TextEncoder();

function b64(buf) {
  const u = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

/** Import the RSA public key once per request, from the config row. */
export async function sealer(db) {
  const row = await db.prepare('SELECT pub FROM config WHERE id = 1').first();
  if (!row || !row.pub) return null;

  let jwk;
  try { jwk = JSON.parse(row.pub); } catch { return null; }

  const pub = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']
  );

  const sealBytes = async (bytes) => {
    const cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const ek = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' }, pub, await crypto.subtle.exportKey('raw', cek)
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek, bytes);
    return { ek: b64(ek), iv: b64(iv), ct: b64(ct) };
  };

  return {
    sealBytes,
    seal: (payload) => sealBytes(te.encode(JSON.stringify(payload))),
  };
}

/* The blind index a conversation is grouped by.
 *
 * Same construction as a record id: PBKDF2 over the shared id_salt, with a
 * domain prefix so a phone number can never collide with a personal number or
 * a serial. The salt is public — it is handed to every soldier's browser — so
 * this is not a secret, it is a speed limit: a phone number is a small space
 * and a fast hash of one is a lookup table.
 */
export async function phoneTag(e164, idSaltB64) {
  const salt = Uint8Array.from(atob(idSaltB64), (c) => c.charCodeAt(0));
  const km = await crypto.subtle.importKey('raw', te.encode(`wa:${e164}`), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 60000, hash: 'SHA-256' }, km, 256
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

export const rndId = () =>
  [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
