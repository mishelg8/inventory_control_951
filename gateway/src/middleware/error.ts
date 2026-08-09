/* The last thing that runs, and the only thing that decides what a caller sees.
 *
 * Two audiences with opposite needs: the log wants the stack, the cause and
 * the Chromium message; the caller wants a code and one sentence in Hebrew. A
 * single place to split them is the only way that stays true as routes get
 * added.
 */
import type { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { AppError, ErrorCode } from '../utils/errors.js';
import { log } from '../utils/logger.js';

export function notFound(_req: Request, _res: Response, next: NextFunction): void {
  next(new AppError(ErrorCode.NOT_FOUND, 'הנתיב אינו קיים'));
}

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  const app =
    err instanceof AppError
      ? err
      : err instanceof ZodError
        ? new AppError(ErrorCode.VALIDATION_FAILED, 'בקשה שגויה', {
            issues: err.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`),
          })
        : null;

  if (app) {
    /* Failed authentication is worth a line — it is either a misconfigured
       Worker or somebody knocking. Everything else at this level is ordinary. */
    const level = app.code === ErrorCode.AUTH_REQUIRED ? 'warn' : 'debug';
    log[level]('http.error', { code: app.code, path: req.path, method: req.method, ip: req.ip });
    res.status(app.status).json(app.toJSON());
    return;
  }

  /* Anything reaching here is a bug, and the details are ours alone. Express's
     own body-parser errors land here too, which is why the caller is told
     "internal error" and not shown a parser message quoting their payload. */
  const message = err instanceof Error ? err.message : String(err);
  const stack = err instanceof Error ? err.stack : undefined;
  log.error('http.unhandled', { path: req.path, method: req.method, error: message, stack });

  res.status(500).json({
    success: false,
    error: { code: ErrorCode.INTERNAL_ERROR, message: 'שגיאה פנימית בשער' },
  });
}
