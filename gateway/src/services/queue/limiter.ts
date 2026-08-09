/* How fast the gateway is allowed to talk.
 *
 * WhatsApp does not publish a rate limit; it publishes a ban. So the shape of
 * the traffic matters as much as the volume: a burst of twelve identical
 * messages in two seconds looks like software, and twelve messages spread over
 * a minute with uneven gaps looks like a person with a task to finish.
 *
 * Two sliding windows and a random pause. All three have to agree before a
 * message goes out.
 */
export interface LimiterOptions {
  perMinute: number;
  perSecond: number;
  delayMinMs: number;
  delayMaxMs: number;
}

export class RateLimiter {
  private readonly opts: LimiterOptions;
  private sends: number[] = [];
  private notBefore = 0;

  constructor(opts: LimiterOptions) {
    this.opts = opts;
  }

  /** Milliseconds to wait before the next send may start. 0 means now. */
  delayFor(now = Date.now()): number {
    this.forget(now);
    const waits = [this.notBefore - now];

    const minuteAgo = now - 60_000;
    const inMinute = this.sends.filter((t) => t > minuteAgo);
    if (inMinute.length >= this.opts.perMinute) {
      waits.push(inMinute[inMinute.length - this.opts.perMinute]! + 60_000 - now);
    }

    const secondAgo = now - 1_000;
    const inSecond = this.sends.filter((t) => t > secondAgo);
    if (inSecond.length >= this.opts.perSecond) {
      waits.push(inSecond[inSecond.length - this.opts.perSecond]! + 1_000 - now);
    }

    return Math.max(0, ...waits);
  }

  /** Called once a message has actually gone out. */
  record(now = Date.now()): void {
    this.sends.push(now);
    this.forget(now);
    const { delayMinMs, delayMaxMs } = this.opts;
    const jitter = delayMinMs + Math.floor(Math.random() * (delayMaxMs - delayMinMs + 1));
    this.notBefore = now + jitter;
  }

  private forget(now: number) {
    const cutoff = now - 60_000;
    if (this.sends.length && this.sends[0]! <= cutoff) {
      this.sends = this.sends.filter((t) => t > cutoff);
    }
  }
}
