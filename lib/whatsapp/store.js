/* Persistence. Every write in here is safe to perform twice.
 *
 * Meta retries a webhook it did not get a prompt 200 for, and it retries the
 * whole delivery — so the same message and the same status arrive again, and
 * "again" must be a no-op rather than a second row or a second notification.
 * Two mechanisms do that work:
 *
 *   the events ledger  one row per event actually applied, claimed with an
 *                      INSERT that either wins or does not. The claim is the
 *                      lock; whoever wins does the work.
 *
 *   monotonic status   sent → delivered → read only ever moves forward, so a
 *                      redelivered 'sent' after a 'read' changes nothing even
 *                      if it slips past the ledger.
 */

import { rndId } from './seal.js';

/* A status that has already happened cannot un-happen. Meta does not promise
 * ordering, and a delivered arriving after a read is a normal Tuesday. */
const RANK = { queued: 0, accepted: 1, sent: 2, delivered: 3, read: 4, received: 4, failed: 5 };
const rank = (s) => (RANK[s] == null ? -1 : RANK[s]);

const EVENT_TTL_MS = 3 * 24 * 60 * 60 * 1000;
const WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Claim an event key. True means "you are the first, do the work"; false
 * means someone already did, and this is a retry.
 */
export async function claimEvent(db, key, now) {
  const r = await db
    .prepare('INSERT INTO wa_events (k, at) VALUES (?1, ?2) ON CONFLICT(k) DO NOTHING RETURNING k')
    .bind(key, now)
    .first()
    .catch(() => null);
  return !!r;
}

/** Old ledger rows answer a question nobody is asking any more. */
export const sweepEvents = (db, now) =>
  db.prepare('DELETE FROM wa_events WHERE at < ?1').bind(now - EVENT_TTL_MS).run().catch(() => {});

/**
 * The person, sealed. Re-sealed on every sighting so a changed profile name
 * is not stale for ever — the row is small and the write is cheap.
 */
export async function upsertContact(db, sealer, tag, phone, profileName, now) {
  const sealed = await sealer.seal({ phone, profileName: profileName || '' });
  await db
    .prepare(
      `INSERT INTO wa_contacts (tag, ek, iv, ct, first_seen, last_seen)
       VALUES (?1, ?2, ?3, ?4, ?5, ?5)
       ON CONFLICT(tag) DO UPDATE SET ek = ?2, iv = ?3, ct = ?4, last_seen = ?5`
    )
    .bind(tag, sealed.ek, sealed.iv, sealed.ct, now)
    .run();
}

/** The thread, created on first contact in either direction. */
export async function ensureConversation(db, tag, phoneNumberId, now) {
  const found = await db
    .prepare('SELECT id FROM wa_conversations WHERE contact_tag = ?1 AND phone_number_id = ?2')
    .bind(tag, phoneNumberId)
    .first();
  if (found) return found.id;

  const id = rndId();
  await db
    .prepare(
      `INSERT INTO wa_conversations (id, contact_tag, phone_number_id, created_at, last_message_at)
       VALUES (?1, ?2, ?3, ?4, ?4)
       ON CONFLICT(contact_tag, phone_number_id) DO NOTHING`
    )
    .bind(id, tag, phoneNumberId, now)
    .run();

  const row = await db
    .prepare('SELECT id FROM wa_conversations WHERE contact_tag = ?1 AND phone_number_id = ?2')
    .bind(tag, phoneNumberId)
    .first();
  return (row && row.id) || id;
}

/**
 * An inbound message. Also opens the 24-hour service window, which is the
 * only thing that makes a free-text reply legal — see the service layer.
 */
export async function insertInbound(db, sealer, conv, msg, now) {
  const sealed = await sealer.seal({
    text: msg.text,
    caption: msg.caption,
    filename: msg.filename,
    mimeType: msg.mimeType,
    interactive: msg.interactive,
    extra: msg.extra,
    from: msg.from,
    profileName: msg.profileName,
  });

  await db
    .prepare(
      `INSERT INTO wa_messages
         (id, conv, wamid, direction, type, status, ek, iv, ct, media_id, created_at, updated_at)
       VALUES (?1, ?2, ?3, 'in', ?4, 'received', ?5, ?6, ?7, ?8, ?9, ?9)
       ON CONFLICT(wamid) DO NOTHING`
    )
    .bind(rndId(), conv, msg.wamid, msg.type, sealed.ek, sealed.iv, sealed.ct, msg.mediaId, msg.timestamp)
    .run();

  await db
    .prepare(
      `UPDATE wa_conversations
          SET last_inbound_at = ?2,
              last_message_at = MAX(COALESCE(last_message_at, 0), ?2),
              window_expires  = MAX(window_expires, ?3),
              unread          = unread + 1
        WHERE id = ?1`
    )
    .bind(conv, msg.timestamp, msg.timestamp + WINDOW_MS)
    .run();
}

/**
 * An outbound message, written before it is sent.
 *
 * A row that exists in 'queued' and never moves on is a message that left the
 * console and vanished, and that is a thing worth being able to see. Writing
 * only on success would make those invisible.
 */
export async function insertOutbound(db, sealer, conv, { type, body, template }, now) {
  const id = rndId();
  const sealed = await sealer.seal(body);
  await db
    .prepare(
      `INSERT INTO wa_messages
         (id, conv, direction, type, status, ek, iv, ct, template, created_at, updated_at)
       VALUES (?1, ?2, 'out', ?3, 'queued', ?4, ?5, ?6, ?7, ?8, ?8)`
    )
    .bind(id, conv, type, sealed.ek, sealed.iv, sealed.ct, template || null, now)
    .run();

  await db
    .prepare('UPDATE wa_conversations SET last_message_at = MAX(COALESCE(last_message_at, 0), ?2) WHERE id = ?1')
    .bind(conv, now)
    .run();

  return id;
}

/** Meta took it, and gave us the id every later status will refer to. */
export const markAccepted = (db, id, wamid, now) =>
  db
    .prepare(`UPDATE wa_messages SET wamid = ?2, status = 'accepted', updated_at = ?3 WHERE id = ?1`)
    .bind(id, wamid, now)
    .run();

/** Meta refused it. The diagnosis is kept; the screen gets a sentence. */
export const markFailed = (db, id, err, now) =>
  db
    .prepare(
      `UPDATE wa_messages
          SET status = 'failed', err_code = ?2, err_subcode = ?3, err_title = ?4,
              err_detail = ?5, err_trace = ?6, updated_at = ?7
        WHERE id = ?1`
    )
    .bind(id, (err && err.code) || null, (err && err.subcode) || null,
          (err && err.title) || null, (err && err.detail) || null, (err && err.trace) || null, now)
    .run();

/**
 * A status callback. Moves the existing row forward, never backward, and
 * never creates one: a status for a message we have no record of is a status
 * for somebody else's message.
 */
export async function applyStatus(db, st, now) {
  const row = await db
    .prepare('SELECT id, status FROM wa_messages WHERE wamid = ?1')
    .bind(st.wamid)
    .first();
  if (!row) return { applied: false, reason: 'unknown-message' };

  const next = st.status === 'warning' || st.status === 'deleted' ? row.status : st.status;
  if (rank(next) <= rank(row.status)) return { applied: false, reason: 'not-newer' };

  /* Which timestamp column this status fills, if any. 'failed' fills none,
     and that is exactly where this went wrong the first time: the SET clause
     was assembled with a conditional fragment while the bound values were
     assembled separately, so dropping the fragment shifted every placeholder
     after it by one. The UPDATE threw, the webhook had already answered 200,
     and the failure was invisible outside a log line. Numbering is derived
     from the values now, so the two cannot disagree. */
  const stamp =
    next === 'sent' ? 'sent_at' : next === 'delivered' ? 'delivered_at' : next === 'read' ? 'read_at' : null;

  const values = [row.id, next];
  const at = (v) => { values.push(v); return `?${values.length}`; };

  let sets = 'status = ?2';
  if (stamp) sets += `, ${stamp} = ${at(st.timestamp)}`;
  sets += `, err_code = COALESCE(${at((st.error && st.error.code) || null)}, err_code)`;
  sets += `, err_title = COALESCE(${at((st.error && st.error.title) || null)}, err_title)`;
  sets += `, err_detail = COALESCE(${at((st.error && st.error.detail) || null)}, err_detail)`;
  sets += `, updated_at = ${at(now)}`;

  await db.prepare(`UPDATE wa_messages SET ${sets} WHERE id = ?1`).bind(...values).run();

  return { applied: true, id: row.id, from: row.status, to: next };
}

/** Media, sealed, kept once. A second message quoting the same id is free. */
export async function saveMedia(db, sealer, mediaId, mime, bytes, now) {
  const sealed = await sealer.sealBytes(bytes);
  await db
    .prepare(
      `INSERT INTO wa_media (media_id, mime, bytes, ek, iv, ct, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
       ON CONFLICT(media_id) DO NOTHING`
    )
    .bind(mediaId, mime || 'application/octet-stream', bytes.length, sealed.ek, sealed.iv, sealed.ct, now)
    .run();
}

export const hasMedia = (db, mediaId) =>
  db.prepare('SELECT 1 AS x FROM wa_media WHERE media_id = ?1').bind(mediaId).first();

export const getMediaRow = (db, mediaId) =>
  db.prepare('SELECT media_id, mime, bytes, ek, iv, ct FROM wa_media WHERE media_id = ?1').bind(mediaId).first();

/* ── reads for the console ─────────────────────────────────────────── */

export const listConversations = (db, limit = 60) =>
  db
    .prepare(
      `SELECT c.id, c.contact_tag, c.phone_number_id, c.window_expires, c.last_inbound_at,
              c.last_message_at, c.unread, c.created_at,
              ct.ek AS c_ek, ct.iv AS c_iv, ct.ct AS c_ct
         FROM wa_conversations c
         LEFT JOIN wa_contacts ct ON ct.tag = c.contact_tag
        ORDER BY COALESCE(c.last_message_at, c.created_at) DESC
        LIMIT ?1`
    )
    .bind(limit)
    .all();

export const listMessages = (db, conv, limit = 200) =>
  db
    .prepare(
      `SELECT id, wamid, direction, type, status, ek, iv, ct, media_id, template,
              err_code, err_title, err_detail, created_at, sent_at, delivered_at, read_at
         FROM wa_messages
        WHERE conv = ?1
        ORDER BY created_at ASC
        LIMIT ?2`
    )
    .bind(conv, limit)
    .all();

export const getConversation = (db, conv) =>
  db.prepare('SELECT * FROM wa_conversations WHERE id = ?1').bind(conv).first();

export const clearUnread = (db, conv) =>
  db.prepare('UPDATE wa_conversations SET unread = 0 WHERE id = ?1').bind(conv).run();

export { WINDOW_MS };
