/* The parts that can be wrong quietly.
 *
 * A wrong telephone number sends a soldier's business to a stranger. A wrong
 * signature string locks the console out of its own gateway. A rate limiter
 * that is off by one is the difference between a working account and a banned
 * one. None of those announce themselves at runtime, so they are tested.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'gw-units-'));
process.env.API_SECRET = 'x'.repeat(48);
process.env.DATABASE_PATH = join(dir, 'test.db');
process.env.SESSION_PATH = join(dir, 'session');
process.env.LOG_LEVEL = 'error';

const { normalizePhone, isValidPhone } = await import('../dist/utils/phone.js');
const { RateLimiter } = await import('../dist/services/queue/limiter.js');
const { render, isTemplate } = await import('../dist/services/messaging/templates.js');
const { sign, signingString } = await import('../dist/middleware/auth.js');
const { permitted } = await import('../dist/middleware/ipAllow.js');

test('a telephone number reaches WhatsApp form however it was written', () => {
  const forms = ['0501234567', '050-123-4567', '+972 50 123 4567', '00972501234567', '972501234567'];
  for (const f of forms) {
    assert.equal(normalizePhone(f).e164, '972501234567', `failed on ${f}`);
  }
  assert.equal(normalizePhone('0501234567').jid, '972501234567@c.us');
});

test('the home country claims a national number before any dialling code', () => {
  // Strip the trunk zero from 0501234567 and it is ten digits starting with
  // 1 — a perfectly good NANP number, and the wrong country entirely.
  assert.equal(normalizePhone('0501234567').country, '972');
  assert.equal(normalizePhone('+12125551234').country, '1');
  assert.equal(normalizePhone('+442071234567').country, '44');
});

test('a number that cannot be resolved is refused, never guessed', () => {
  for (const bad of ['', '   ', 'abc', '12', '05012345678901234', '+999123']) {
    assert.equal(isValidPhone(bad), false, `accepted ${JSON.stringify(bad)}`);
  }
  assert.throws(() => normalizePhone(null), /טלפון/);
});

test('every template signs itself and refuses parameters it does not fit', () => {
  const text = render('signature_request', { name: 'דניאל', items: ['קסדה', 'ווסט'] });
  assert.ok(text.includes('דניאל'));
  assert.ok(text.includes('• קסדה'));
  assert.ok(text.endsWith('— מסייעת 951'), 'a message went out unsigned');

  assert.throws(() => render('signature_request', { name: 'דניאל' }), /פרמטרים/);
  assert.throws(() => render('signature_request', { name: '', items: ['x'] }), /פרמטרים/);
  assert.equal(isTemplate('drop_tables'), false);
});

test('free text is capped and still carries the signature', () => {
  assert.throws(() => render('custom', { body: 'x'.repeat(5000) }), /פרמטרים|ארוכה/);
  assert.ok(render('custom', { body: 'שלום' }).endsWith('— מסייעת 951'));
});

test('the signature covers the method, the path and the body', () => {
  const secret = 'k'.repeat(48);
  const base = sign('100', 'POST', '/api/messages', '{"a":1}', secret);
  assert.notEqual(base, sign('101', 'POST', '/api/messages', '{"a":1}', secret), 'timestamp not covered');
  assert.notEqual(base, sign('100', 'GET', '/api/messages', '{"a":1}', secret), 'method not covered');
  assert.notEqual(base, sign('100', 'POST', '/api/logout', '{"a":1}', secret), 'path not covered');
  assert.notEqual(base, sign('100', 'POST', '/api/messages', '{"a":2}', secret), 'body not covered');
  assert.notEqual(base, sign('100', 'POST', '/api/messages', '{"a":1}', 'other'), 'secret not covered');
  assert.match(signingString('100', 'post', '/x', ''), /^100\nPOST\n\/x\n[0-9a-f]{64}$/);
});

test('an empty allowlist lets everything through, which is the documented default', () => {
  assert.equal(permitted('203.0.113.9'), true);
  assert.equal(permitted('::ffff:10.0.0.1'), true);
});

test('the limiter spaces sends and honours both windows', () => {
  const l = new RateLimiter({ perMinute: 3, perSecond: 1, delayMinMs: 1000, delayMaxMs: 1000 });
  const t0 = 1_000_000;

  assert.equal(l.delayFor(t0), 0);
  l.record(t0);
  assert.equal(l.delayFor(t0), 1000, 'no pause between messages');
  assert.equal(l.delayFor(t0 + 1000), 0);

  l.record(t0 + 2000);
  l.record(t0 + 4000);
  // Three in the last minute is the ceiling; the next one waits for the first
  // to fall out of the window rather than for the jitter.
  assert.equal(l.delayFor(t0 + 6000), 60_000 - 6000);
  assert.equal(l.delayFor(t0 + 61_000), 0);
});
