/* The promises the outbox makes.
 *
 * Exactly once, in order, and surviving a restart. Each of those is a property
 * of the SQL, not of the loop that calls it, so each is tested against a real
 * database file rather than a stub.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'gw-queue-'));
process.env.API_SECRET = 'x'.repeat(48);
process.env.DATABASE_PATH = join(dir, 'queue.db');
process.env.SESSION_PATH = join(dir, 'session');
process.env.LOG_LEVEL = 'error';
process.env.IDEMPOTENCY_TTL_SECONDS = '3600';

const messages = await import('../dist/repositories/messages.js');
const idempotency = await import('../dist/repositories/idempotency.js');
const numbers = await import('../dist/repositories/numbers.js');
const { db } = await import('../dist/db/index.js');

const reset = () => db.exec('DELETE FROM messages; DELETE FROM idempotency; DELETE FROM number_cache;');

test('a claimed message cannot be claimed again', () => {
  reset();
  messages.create({ phone: '972501234567', message: 'a', template: 'custom' });

  const first = messages.claimNext(Date.now());
  const second = messages.claimNext(Date.now());

  assert.ok(first, 'nothing was claimed');
  assert.equal(second, null, 'the same message was handed out twice');
  assert.equal(first.status, 'sending');
  assert.equal(first.attempts, 1);
});

test('the oldest due message goes first, and a future one waits', () => {
  reset();
  const now = Date.now();
  const later = messages.create({ phone: '972500000002', message: 'b', scheduledAt: now + 60_000 });
  const sooner = messages.create({ phone: '972500000001', message: 'a', scheduledAt: now - 1000 });

  assert.equal(messages.claimNext(now).id, sooner.id);
  assert.equal(messages.claimNext(now), null, 'a message scheduled for later was sent early');
  assert.equal(messages.claimNext(now + 61_000).id, later.id);
});

test('a process that died mid-send puts the message back, not the attempt', () => {
  reset();
  messages.create({ phone: '972501234567', message: 'a' });
  const claimed = messages.claimNext(Date.now());
  assert.equal(claimed.attempts, 1);

  // ...and here the process dies, leaving the row saying 'sending'.
  assert.equal(messages.recoverStuck(), 1);

  const again = messages.claimNext(Date.now());
  assert.equal(again.id, claimed.id);
  assert.equal(again.attempts, 2, 'a message that kills the process would retry forever');
});

test('a retry is rescheduled, a failure is final', () => {
  reset();
  const row = messages.create({ phone: '972501234567', message: 'a' });
  messages.claimNext(Date.now());

  messages.reschedule(row.id, Date.now() + 5000, 'MESSAGE_FAILED', 'נכשל');
  assert.equal(messages.get(row.id).status, 'queued');
  assert.equal(messages.claimNext(Date.now()), null, 'the backoff was not honoured');

  messages.markFailed(row.id, 'INVALID_PHONE', 'לא תקין');
  const failed = messages.get(row.id);
  assert.equal(failed.status, 'failed');
  assert.equal(messages.toView(failed).error.code, 'INVALID_PHONE');
});

test('a view never carries the body or the number', () => {
  reset();
  const row = messages.create({ phone: '972501234567', message: 'סוד', template: 'custom' });
  const view = messages.toView(row);
  const json = JSON.stringify(view);
  assert.ok(!json.includes('סוד'), 'the message body is being handed back out');
  assert.ok(!json.includes('972501234567'), 'the telephone number is being handed back out');
  assert.equal(view.status, 'queued');
});

test('the same idempotency key yields one message', () => {
  reset();
  const a = messages.create({ phone: '972501234567', message: 'a' });
  const b = messages.create({ phone: '972501234567', message: 'a' });

  assert.equal(idempotency.claim('key-abcdefgh', a.id), null, 'the first claim should win');
  assert.equal(idempotency.claim('key-abcdefgh', b.id), a.id, 'the second claim took the key');
  assert.equal(idempotency.lookup('key-abcdefgh'), a.id);
});

test('an expired key is reusable, and a swept one is gone', () => {
  reset();
  const a = messages.create({ phone: '972501234567', message: 'a' });
  const past = Date.now() - 10 * 3600 * 1000;
  idempotency.claim('key-oldoldold', a.id, past);

  const b = messages.create({ phone: '972501234567', message: 'b' });
  assert.equal(idempotency.claim('key-oldoldold', b.id), null, 'an expired key still blocked a fresh request');
  assert.equal(idempotency.sweep(Date.now() + 10 * 3600 * 1000), 1);
});

test('delivered bodies are wiped before the rows are', () => {
  reset();
  const row = messages.create({ phone: '972501234567', message: 'סוד' });
  messages.claimNext(Date.now());
  messages.markSent(row.id, 'wa-1');

  assert.equal(messages.scrubBodies(Date.now() + 1000), 1);
  assert.equal(messages.get(row.id).message, '', 'the body survived the scrub');
  assert.equal(messages.get(row.id).status, 'sent', 'the row should outlive its body');

  assert.equal(messages.purge(Date.now() + 1000), 1);
  assert.equal(messages.get(row.id), undefined);
});

test('a cached number answer expires rather than hardening', () => {
  reset();
  const now = Date.now();
  numbers.put('972501234567', false, now);
  assert.equal(numbers.get('972501234567', 1000, now + 500), false);
  assert.equal(numbers.get('972501234567', 1000, now + 5000), null, 'a stale answer was reused');
  assert.equal(numbers.get('972509999999', 1000, now), null);
});

test('counts and pending agree with the rows', () => {
  reset();
  messages.create({ phone: '972500000001', message: 'a' });
  messages.create({ phone: '972500000002', message: 'b' });
  const claimed = messages.claimNext(Date.now());
  messages.markSent(claimed.id, null);

  assert.deepEqual(messages.counts(), { queued: 1, sending: 0, sent: 1, failed: 0 });
  assert.equal(messages.pending(), 1);
});
