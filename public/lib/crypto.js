// The cryptography, and nothing else. Personal data is sealed here before it
// leaves the browser and opened here when it comes back; the server never
// sees any of it in the clear. See PLAN.md §4 for the design.
//
// Kept in its own file so the part that has to be right can be read in one
// sitting, without a console around it.

import { SERIAL_FIELDS } from './catalog.js';

const te = new TextEncoder();

const td = new TextDecoder();

function b64(buf) {
  const u = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < u.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function ub64(s) {
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

const hex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

// One PBKDF2 pass, split output: KEK (encryption half) + verifier (auth half).
async function deriveAuth(password, saltB64) {
  const km = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: ub64(saltB64), iterations: 310000, hash: 'SHA-256' }, km, 512
  ));
  const kek = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  const verifier = hex(await crypto.subtle.digest('SHA-256', bits.slice(32)));
  bits.fill(0);
  return { kek, verifier };
}

// Record identifier: slow-KDF mask of the personal number (§4.6).
async function deriveRid(pn, idSaltB64) {
  const km = await crypto.subtle.importKey('raw', te.encode(pn), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: ub64(idSaltB64), iterations: 60000, hash: 'SHA-256' }, km, 256
  );
  return hex(bits).slice(0, 32);
}

// Blind index of a serial number, so the server can refuse a duplicate it
// cannot read. Same construction and salt as the record id, with a domain
// prefix so a serial can never collide with a personal number.
const normSerial = (v) => String(v || '').trim().toLowerCase().replace(/[\s-]+/g, '');

const deriveSerialTag = (value, idSaltB64) => deriveRid(`serial:${normSerial(value)}`, idSaltB64);

// The tags for one submission: one per number the soldier actually filled in.
async function serialTags(d, idSaltB64) {
  const out = [];
  for (const [field] of SERIAL_FIELDS) {
    if (!normSerial(d[field])) continue;
    out.push({ tag: await deriveSerialTag(d[field], idSaltB64), field });
  }
  return out;
}

const importPubKey = (jwk) =>
  crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);

// Seal: fresh content key per write, wrapped under the public key (§4.4).
async function seal(pubKey, payload) {
  const cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const rawCek = await crypto.subtle.exportKey('raw', cek);
  const ek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, rawCek);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek, te.encode(JSON.stringify(payload)));
  return { ek: b64(ek), iv: b64(iv), ct: b64(ct) };
}

/* ── Trust boundary ────────────────────────────────────────────────────
   The RSA public key is public by design — that is what lets any soldier
   submit without an account. The consequence is that ANYONE can encrypt an
   arbitrary payload and POST it, so a decrypted record is untrusted input,
   not our own data. Everything below coerces a payload to the shape the UI
   expects: strings are capped, numbers are real finite numbers, ids are
   whitelisted. Without this, a crafted quantity like "<img …>" flows into
   innerHTML in the admin console — where the private key lives.
   ──────────────────────────────────────────────────────────────────── */

const rndId = () => hex(crypto.getRandomValues(new Uint8Array(8)));

// Open: admin only (§4.5). Throws on tampered ciphertext — caller counts it.
// `clean` is the schema guard above; never skip it for attacker-writable data.
// `clean` is the schema guard from clean.js and is NOT optional: a decrypted
// record is attacker-writable input, so opening one without saying how it is
// to be checked is a mistake, and a loud one rather than a silent skip.
//
// It used to default to cleanRecord, which was fine while everything lived in
// one file. Once this moved here that default referred to a name this module
// cannot see, so every call that relied on it threw — and the console, which
// catches a failure to open and marks the row, reported every record as
// damaged data on the server. The data was never touched.
async function openRecord(privKey, rec, clean) {
  if (typeof clean !== 'function') throw new Error('openRecord: missing schema guard');
  const rawCek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, ub64(rec.ek));
  const cek = await crypto.subtle.importKey('raw', rawCek, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(rec.iv) }, cek, ub64(rec.ct));
  return clean(JSON.parse(td.decode(pt)));
}

// Seals raw bytes rather than JSON — used for licence photos.
async function sealBytes(pubKey, bytes) {
  const cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const ek = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' }, pubKey, await crypto.subtle.exportKey('raw', cek)
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cek, bytes);
  return { ek: b64(ek), iv: b64(iv), ct: b64(ct) };
}

async function openBytes(privKey, rec) {
  const rawCek = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, ub64(rec.ek));
  const cek = await crypto.subtle.importKey('raw', rawCek, 'AES-GCM', false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(rec.iv) }, cek, ub64(rec.ct));
}

export {
  b64,
  deriveAuth,
  deriveRid,
  deriveSerialTag,
  hex,
  importPubKey,
  normSerial,
  openBytes,
  openRecord,
  rndId,
  seal,
  sealBytes,
  serialTags,
  td,
  te,
  ub64,
};
