/* One error shape for the whole API.
 *
 * A caller gets a code it can branch on and a sentence it can show a person.
 * It never gets a stack trace, a file path, or the text of a Chromium
 * exception — those go to the log, where they are useful and not public.
 */
export const ErrorCode = {
  WHATSAPP_NOT_CONNECTED: 'WHATSAPP_NOT_CONNECTED',
  INVALID_PHONE: 'INVALID_PHONE',
  NUMBER_NOT_REGISTERED: 'NUMBER_NOT_REGISTERED',
  MESSAGE_FAILED: 'MESSAGE_FAILED',
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  RATE_LIMITED: 'RATE_LIMITED',
  DUPLICATE_REQUEST: 'DUPLICATE_REQUEST',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  NOT_FOUND: 'NOT_FOUND',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;

export type ErrorCodeName = (typeof ErrorCode)[keyof typeof ErrorCode];

const STATUS: Record<ErrorCodeName, number> = {
  WHATSAPP_NOT_CONNECTED: 503,
  INVALID_PHONE: 400,
  NUMBER_NOT_REGISTERED: 422,
  MESSAGE_FAILED: 502,
  AUTH_REQUIRED: 401,
  RATE_LIMITED: 429,
  DUPLICATE_REQUEST: 409,
  SESSION_EXPIRED: 401,
  VALIDATION_FAILED: 400,
  NOT_FOUND: 404,
  INTERNAL_ERROR: 500,
};

/* Whether trying the same thing again could plausibly work. The queue reads
   this: a disconnected client is worth waiting for, a malformed telephone
   number will be just as malformed in sixty seconds. */
const TRANSIENT: ReadonlySet<ErrorCodeName> = new Set([
  ErrorCode.WHATSAPP_NOT_CONNECTED,
  ErrorCode.MESSAGE_FAILED,
  ErrorCode.RATE_LIMITED,
  ErrorCode.INTERNAL_ERROR,
]);

export class AppError extends Error {
  readonly code: ErrorCodeName;
  readonly status: number;
  readonly details?: unknown;

  constructor(code: ErrorCodeName, message: string, details?: unknown) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = STATUS[code];
    this.details = details;
  }

  get transient(): boolean {
    return TRANSIENT.has(this.code);
  }

  toJSON() {
    return { success: false as const, error: { code: this.code, message: this.message } };
  }
}

export const isTransient = (err: unknown): boolean =>
  err instanceof AppError ? err.transient : true;

export const codeOf = (err: unknown): ErrorCodeName =>
  err instanceof AppError ? err.code : ErrorCode.INTERNAL_ERROR;
