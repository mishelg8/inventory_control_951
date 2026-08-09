/* The messages the gateway is willing to send.
 *
 * A relay that will send any text to any number is a spam service with a
 * password on it. The templates are the answer: a caller names one and fills
 * its blanks, and the wording — including the line that says who this is and
 * why they got it — is fixed here, in the repository, under review.
 *
 * `custom` exists because the console has a free-text box and taking it away
 * would be a regression. It is capped, it is logged as custom, and it still
 * carries the signature line.
 */
import { z } from 'zod';
import { AppError, ErrorCode } from '../../utils/errors.js';

export const MAX_BODY_CHARS = 1200;

/** Appended to everything, so no message is ever anonymous to the recipient. */
const SIGNATURE = '\n\n— מסייעת 951';

const name = z.string().trim().min(1).max(60);
const item = z.string().trim().min(1).max(120);
const items = z.array(item).min(1).max(30);
const note = z.string().trim().max(400).optional();

const list = (rows: string[]) => rows.map((r) => `• ${r}`).join('\n');

const TEMPLATES = {
  /* Asked to come and sign for equipment that is waiting for them. */
  signature_request: {
    schema: z.object({ name, items, note }),
    render: (p: { name: string; items: string[]; note?: string }) =>
      `שלום ${p.name},\n\nממתין לך ציוד לחתימה:\n${list(p.items)}` +
      (p.note ? `\n\n${p.note}` : ''),
  },

  /* Asked to bring equipment back. */
  return_request: {
    schema: z.object({ name, items, due: z.string().trim().max(40).optional(), note }),
    render: (p: { name: string; items: string[]; due?: string; note?: string }) =>
      `שלום ${p.name},\n\nנא להחזיר את הציוד הבא:\n${list(p.items)}` +
      (p.due ? `\n\nעד: ${p.due}` : '') +
      (p.note ? `\n\n${p.note}` : ''),
  },

  /* Second and later asks. Same content, different opening, so the recipient
     can tell a reminder from the first request. */
  reminder: {
    schema: z.object({ name, items, note }),
    render: (p: { name: string; items: string[]; note?: string }) =>
      `שלום ${p.name},\n\nתזכורת — הציוד הבא עדיין רשום עליך:\n${list(p.items)}` +
      (p.note ? `\n\n${p.note}` : ''),
  },

  /* The registration went through. Nothing is asked of them. */
  registration_approved: {
    schema: z.object({ name, items: items.optional(), note }),
    render: (p: { name: string; items?: string[]; note?: string }) =>
      `שלום ${p.name},\n\nהרישום שלך התקבל ואושר.` +
      (p.items?.length ? `\n\nהציוד הרשום עליך:\n${list(p.items)}` : '') +
      (p.note ? `\n\n${p.note}` : ''),
  },

  custom: {
    schema: z.object({ body: z.string().trim().min(1).max(MAX_BODY_CHARS) }),
    render: (p: { body: string }) => p.body,
  },
} as const;

export type TemplateName = keyof typeof TEMPLATES;

export const TEMPLATE_NAMES = Object.keys(TEMPLATES) as TemplateName[];

export const isTemplate = (v: unknown): v is TemplateName =>
  typeof v === 'string' && Object.prototype.hasOwnProperty.call(TEMPLATES, v);

/**
 * Turn a template name and its parameters into the text that will be sent.
 * @throws AppError(VALIDATION_FAILED) when the parameters do not fit the template.
 */
export function render(template: TemplateName, params: unknown): string {
  const def = TEMPLATES[template];
  const parsed = def.schema.safeParse(params ?? {});
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.') || 'params'}: ${i.message}`);
    throw new AppError(ErrorCode.VALIDATION_FAILED, 'פרמטרים שגויים לתבנית', { issues });
  }

  // The schemas are per-template; the union confuses the compiler, not us.
  const body = (def.render as (p: unknown) => string)(parsed.data);
  const full = `${body}${SIGNATURE}`;

  if (full.length > MAX_BODY_CHARS + SIGNATURE.length) {
    throw new AppError(ErrorCode.VALIDATION_FAILED, 'ההודעה ארוכה מדי');
  }
  return full;
}
