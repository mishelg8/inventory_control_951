/* Meta's webhook payload in, our own shape out.
 *
 * Nothing downstream of this file knows what Meta's JSON looks like. That is
 * deliberate: the payload is versioned by someone else and has grown a new
 * message type roughly every release, and the cost of that should be one
 * function here rather than a `value.messages[0].image.id` in the store, in
 * the service and in the UI.
 *
 * This is also a trust boundary. The body arrived over the internet; the
 * signature says Meta sent it, not that it is well-formed. Every field is
 * read defensively, every string is capped, and an entry that makes no sense
 * is dropped rather than thrown — one malformed change must not cost us the
 * other four in the same delivery.
 */

import { fromWaId } from '../../public/lib/phone.js';

const str = (v, max = 4096) => (typeof v === 'string' ? v.slice(0, max) : '');
const arr = (v) => (Array.isArray(v) ? v : []);
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

/* Meta sends unix seconds as a string. Everything in this codebase is
 * milliseconds since the epoch, and a webhook is no place to start a second
 * convention. A missing or silly timestamp becomes "now" rather than 1970. */
function ts(v, now) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return now;
  return n < 1e12 ? Math.round(n * 1000) : Math.round(n);
}

/* The media-bearing types all carry the same three fields under a different
 * key, which is the sort of thing that produces four nearly identical
 * branches. One table instead. */
const MEDIA_TYPES = ['image', 'document', 'audio', 'video', 'sticker'];

const STATUSES = new Set(['sent', 'delivered', 'read', 'failed', 'deleted', 'warning']);

function normalizeMessage(m, meta, contacts, now) {
  const wamid = str(m.id, 200);
  if (!wamid) return null;

  const from = fromWaId(str(m.from, 20));
  if (!from) return null;

  const type = str(m.type, 40) || 'unknown';
  const contact = contacts[str(m.from, 20)] || {};

  const out = {
    wamid,
    from,
    phoneNumberId: meta.phoneNumberId,
    displayPhoneNumber: meta.displayPhoneNumber,
    timestamp: ts(m.timestamp, now),
    type,
    profileName: str(contact.name, 120),
    // Set when the sender replied to a specific message of ours; this is what
    // turns "ok" into "ok, about the rifle" without asking anyone.
    contextWamid: str(obj(m.context).id, 200) || null,
    text: '',
    caption: '',
    mediaId: null,
    mimeType: '',
    filename: '',
    interactive: null,
    // Anything we did not model, kept small and kept away from the UI. Useful
    // exactly once, at three in the morning, when a type nobody planned for
    // starts arriving.
    extra: null,
  };

  if (type === 'text') {
    out.text = str(obj(m.text).body);
  } else if (MEDIA_TYPES.includes(type)) {
    const media = obj(m[type]);
    out.mediaId = str(media.id, 200) || null;
    out.mimeType = str(media.mime_type, 120);
    out.caption = str(media.caption, 1024);
    out.filename = str(media.filename, 200);
  } else if (type === 'interactive') {
    const it = obj(m.interactive);
    const kind = str(it.type, 40);
    const reply = obj(it[kind]);
    out.interactive = {
      kind,
      id: str(reply.id, 200),
      title: str(reply.title, 200),
      description: str(reply.description, 400),
    };
    out.text = out.interactive.title;
  } else if (type === 'button') {
    // A quick-reply button on a template we sent.
    const b = obj(m.button);
    out.interactive = { kind: 'button', id: str(b.payload, 200), title: str(b.text, 200), description: '' };
    out.text = out.interactive.title;
  } else if (type === 'reaction') {
    const r = obj(m.reaction);
    out.text = str(r.emoji, 16);
    out.contextWamid = str(r.message_id, 200) || out.contextWamid;
  } else if (type === 'location') {
    const l = obj(m.location);
    out.extra = {
      latitude: Number(l.latitude) || null,
      longitude: Number(l.longitude) || null,
      name: str(l.name, 200),
      address: str(l.address, 300),
    };
  } else if (type === 'unsupported' || type === 'system' || type === 'order' || type === 'contacts') {
    out.extra = { note: type };
  } else {
    out.extra = { note: 'unmodelled', type };
  }

  return out;
}

function normalizeStatus(s, meta, now) {
  const wamid = str(s.id, 200);
  const status = str(s.status, 40);
  if (!wamid || !STATUSES.has(status)) return null;

  const e = arr(s.errors)[0];
  const data = obj(e && e.error_data);

  return {
    wamid,
    status,
    recipient: fromWaId(str(s.recipient_id, 20)),
    phoneNumberId: meta.phoneNumberId,
    timestamp: ts(s.timestamp, now),
    // Present only on 'failed'; this is the half that explains why.
    error: e
      ? {
          code: Number.isFinite(e.code) ? e.code : null,
          title: str(e.title, 200) || str(e.message, 200),
          detail: str(data.details, 300),
          trace: null,
          subcode: null,
          status: 0,
        }
      : null,
    // Meta's conversation/pricing block: which category was billed. No
    // personal content, and the only place the 24-hour window is visible
    // from the outside.
    conversationId: str(obj(s.conversation).id, 200) || null,
    category: str(obj(s.pricing).category, 60) || str(obj(obj(s.conversation).origin).type, 60),
  };
}

/**
 * @returns {{ ok: boolean, reason?: string, wabaId: string, batches: Array }}
 */
export function normalizeWebhook(payload, now = Date.now()) {
  const body = obj(payload);
  if (body.object !== 'whatsapp_business_account') {
    return { ok: false, reason: 'not-a-waba-event', wabaId: '', batches: [] };
  }

  const batches = [];
  let wabaId = '';

  for (const entry of arr(body.entry)) {
    const e = obj(entry);
    wabaId = str(e.id, 60) || wabaId;

    for (const change of arr(e.changes)) {
      const c = obj(change);
      if (str(c.field, 40) !== 'messages') continue;   // we subscribe to one field

      const value = obj(c.value);
      const md = obj(value.metadata);
      const meta = {
        phoneNumberId: str(md.phone_number_id, 60),
        displayPhoneNumber: str(md.display_phone_number, 40),
      };
      if (!meta.phoneNumberId) continue;

      // wa_id → profile, so a message can carry the sender's display name
      // without a second lookup.
      const contacts = {};
      for (const ct of arr(value.contacts)) {
        const id = str(obj(ct).wa_id, 20);
        if (id) contacts[id] = { name: str(obj(obj(ct).profile).name, 120) };
      }

      batches.push({
        wabaId,
        meta,
        messages: arr(value.messages).map((m) => normalizeMessage(obj(m), meta, contacts, now)).filter(Boolean),
        statuses: arr(value.statuses).map((s) => normalizeStatus(obj(s), meta, now)).filter(Boolean),
      });
    }
  }

  return { ok: true, wabaId, batches };
}
