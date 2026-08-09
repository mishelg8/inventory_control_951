/* Accepting a message, and answering questions about one already accepted.
 *
 * POST /messages returns as soon as the row is written. It does not wait for
 * WhatsApp, and it does not fail because WhatsApp is mid-reconnect — the
 * console gets an id and the queue gets on with it. The only failures here are
 * the ones that would still be failures in an hour: a number that is not a
 * number, a template that does not exist, a body too long to send.
 */
import { Router } from 'express';
import type { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { AppError, ErrorCode } from '../utils/errors.js';
import { normalizePhone } from '../utils/phone.js';
import { log } from '../utils/logger.js';
import * as messages from '../repositories/messages.js';
import * as idempotency from '../repositories/idempotency.js';
import * as numbers from '../repositories/numbers.js';
import { whatsapp } from '../services/whatsapp/client.js';
import { render, isTemplate, TEMPLATE_NAMES, MAX_BODY_CHARS } from '../services/messaging/templates.js';

export const messageRoutes = Router();

const sendSchema = z.object({
  to: z.string().min(1, 'נדרש מספר טלפון'),
  template: z.string().optional(),
  params: z.record(z.unknown()).optional(),
  message: z.string().trim().min(1).max(MAX_BODY_CHARS).optional(),
  idempotencyKey: z.string().trim().min(8).max(128).optional(),
  /* Ask WhatsApp whether the number exists before queueing. Costs a round trip
     through the live session, so it is the caller's choice, not the default. */
  verify: z.boolean().optional(),
});

messageRoutes.post('/messages', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const input = sendSchema.parse(req.body);

    if (!input.template && !input.message) {
      throw new AppError(ErrorCode.VALIDATION_FAILED, 'נדרשת תבנית או טקסט הודעה');
    }
    if (input.template && !isTemplate(input.template)) {
      throw new AppError(ErrorCode.VALIDATION_FAILED, 'תבנית לא מוכרת', { allowed: TEMPLATE_NAMES });
    }

    const phone = normalizePhone(input.to);
    const template = input.template && isTemplate(input.template) ? input.template : 'custom';
    const body = input.template
      ? render(template, input.params ?? {})
      : render('custom', { body: input.message });

    /* The key is bound before the row is sendable, so two identical requests
       racing each other produce one message and one answer, not two. */
    const key = input.idempotencyKey;
    if (key) {
      const seen = idempotency.lookup(key);
      if (seen) {
        const existing = messages.get(seen);
        if (existing) {
          res.status(200).json({ success: true, duplicate: true, message: messages.toView(existing) });
          return;
        }
      }
    }

    if (input.verify) {
      const cached = numbers.get(phone.e164);
      const registered = cached ?? (await whatsapp.isRegistered(phone.e164));
      if (cached === null) numbers.put(phone.e164, registered);
      if (!registered) {
        throw new AppError(ErrorCode.NUMBER_NOT_REGISTERED, 'המספר אינו רשום בוואטסאפ');
      }
    }

    const row = messages.create({ phone: phone.e164, message: body, template });

    if (key) {
      const other = idempotency.claim(key, row.id);
      if (other && other !== row.id) {
        /* Lost the race. Drop the row we just made and answer with the winner,
           so the caller sees one message however many times it asked. */
        messages.markFailed(row.id, ErrorCode.DUPLICATE_REQUEST, 'בקשה כפולה');
        const winner = messages.get(other);
        if (winner) {
          res.status(200).json({ success: true, duplicate: true, message: messages.toView(winner) });
          return;
        }
      }
    }

    log.info('message.queued', { id: row.id, phone: row.phone, template });
    res.status(202).json({ success: true, message: messages.toView(row) });
  } catch (e) {
    next(e);
  }
});

messageRoutes.get('/messages/:id', (req: Request, res: Response, next: NextFunction) => {
  const row = messages.get(String(req.params.id));
  if (!row) {
    next(new AppError(ErrorCode.NOT_FOUND, 'ההודעה אינה קיימת'));
    return;
  }
  res.json({ success: true, message: messages.toView(row) });
});

const listSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/* Bodies and telephone numbers are not in the view. The console already knows
   both — it composed them — and the history endpoint has no business handing
   them back out. */
messageRoutes.get('/messages', (req: Request, res: Response, next: NextFunction) => {
  try {
    const { limit, offset } = listSchema.parse(req.query);
    res.json({
      success: true,
      counts: messages.counts(),
      messages: messages.recent(limit, offset).map(messages.toView),
    });
  } catch (e) {
    next(e);
  }
});

const checkSchema = z.object({ phone: z.string().min(1) });

messageRoutes.post('/check-number', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { phone } = checkSchema.parse(req.body);
    const normalized = normalizePhone(phone);
    const cached = numbers.get(normalized.e164);
    if (cached !== null) {
      res.json({ success: true, e164: normalized.e164, registered: cached, cached: true });
      return;
    }
    const registered = await whatsapp.isRegistered(normalized.e164);
    numbers.put(normalized.e164, registered);
    res.json({ success: true, e164: normalized.e164, registered, cached: false });
  } catch (e) {
    next(e);
  }
});
