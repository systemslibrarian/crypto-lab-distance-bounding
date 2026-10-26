/**
 * Exact rational arithmetic over BigInt.
 *
 * Every acceptance verdict and every attack probability in this lesson is
 * computed here. Nothing in the security path is a JavaScript `number`: a
 * float comparison at the acceptance boundary is exactly the place where a
 * distance-bounding verdict would silently stop meaning what it says, and the
 * pinned boundary case (T = 22 accepts, T = 23 rejects at v = 1, R = 10,
 * delta_lb = 2) is checked on these values rather than on decimals.
 *
 * Decimal rendering exists for display only and is never fed back into a
 * comparison.
 */

/** A rational number n/d, always reduced, with d > 0. */
export interface Exact {
  readonly n: bigint;
  readonly d: bigint;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
}

/** Build a reduced rational. Throws on a zero denominator rather than ranking. */
export function exact(n: bigint, d: bigint = 1n): Exact {
  if (d === 0n) throw new RangeError("exact: zero denominator");
  const sign = d < 0n ? -1n : 1n;
  const sn = n * sign;
  const sd = d * sign;
  const g = gcd(sn, sd);
  if (g === 0n) return { n: 0n, d: 1n };
  return { n: sn / g, d: sd / g };
}

export const ZERO: Exact = { n: 0n, d: 1n };
export const ONE: Exact = { n: 1n, d: 1n };

export function fromInt(value: number | bigint): Exact {
  const n = typeof value === "bigint" ? value : BigInt(Math.trunc(value));
  if (typeof value === "number" && !Number.isInteger(value)) {
    throw new RangeError("fromInt: not an integer");
  }
  return { n, d: 1n };
}

export function add(a: Exact, b: Exact): Exact {
  return exact(a.n * b.d + b.n * a.d, a.d * b.d);
}

export function sub(a: Exact, b: Exact): Exact {
  return exact(a.n * b.d - b.n * a.d, a.d * b.d);
}

export function mul(a: Exact, b: Exact): Exact {
  return exact(a.n * b.n, a.d * b.d);
}

export function div(a: Exact, b: Exact): Exact {
  if (b.n === 0n) throw new RangeError("div: division by zero");
  return exact(a.n * b.d, a.d * b.n);
}

/** -1, 0 or 1. Exact: no epsilon, no float widening. */
export function cmp(a: Exact, b: Exact): -1 | 0 | 1 {
  const left = a.n * b.d;
  const right = b.n * a.d;
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

export const lte = (a: Exact, b: Exact): boolean => cmp(a, b) <= 0;
export const lt = (a: Exact, b: Exact): boolean => cmp(a, b) < 0;
export const gte = (a: Exact, b: Exact): boolean => cmp(a, b) >= 0;
export const gt = (a: Exact, b: Exact): boolean => cmp(a, b) > 0;
export const eq = (a: Exact, b: Exact): boolean => cmp(a, b) === 0;
export const isPositive = (a: Exact): boolean => a.n > 0n;
export const isNonNegative = (a: Exact): boolean => a.n >= 0n;

/** Exact `n/d` form, the canonical rendering used in evidence tables. */
export function toFraction(a: Exact): string {
  return a.d === 1n ? `${a.n}` : `${a.n}/${a.d}`;
}

/**
 * Truncated decimal, for display beside the exact fraction and never instead
 * of it. Truncation rather than rounding keeps a displayed probability from
 * ever reading higher than the exact value it accompanies.
 */
export function toDecimal(a: Exact, places = 12): string {
  if (places < 0 || !Number.isInteger(places)) {
    throw new RangeError("toDecimal: places must be a non-negative integer");
  }
  const negative = a.n < 0n;
  const n = negative ? -a.n : a.n;
  const whole = n / a.d;
  const sign = negative ? "-" : "";
  if (places === 0) return `${sign}${whole}`;
  const scaled = ((n % a.d) * 10n ** BigInt(places)) / a.d;
  return `${sign}${whole}.${scaled.toString().padStart(places, "0")}`;
}

/** Binomial coefficient C(n, k), exact. */
export function binomial(n: number, k: number): bigint {
  if (!Number.isInteger(n) || !Number.isInteger(k) || n < 0) {
    throw new RangeError("binomial: n must be a non-negative integer");
  }
  if (k < 0 || k > n) return 0n;
  const kk = BigInt(Math.min(k, n - k));
  let result = 1n;
  const bn = BigInt(n);
  for (let i = 0n; i < kk; i += 1n) {
    result = (result * (bn - i)) / (i + 1n);
  }
  return result;
}

/** Exact integer power. */
export function ipow(base: bigint, exponent: number): bigint {
  if (!Number.isInteger(exponent) || exponent < 0) {
    throw new RangeError("ipow: exponent must be a non-negative integer");
  }
  return base ** BigInt(exponent);
}

/** Exact rational power with a non-negative integer exponent. */
export function pow(a: Exact, exponent: number): Exact {
  if (!Number.isInteger(exponent) || exponent < 0) {
    throw new RangeError("pow: exponent must be a non-negative integer");
  }
  return exact(ipow(a.n, exponent), ipow(a.d, exponent));
}

/** Parse a decimal or `n/d` string into an exact rational. */
export function parseExact(text: string): Exact {
  const trimmed = text.trim();
  const fraction = /^(-?\d+)\s*\/\s*(\d+)$/.exec(trimmed);
  if (fraction) return exact(BigInt(fraction[1]), BigInt(fraction[2]));
  const decimal = /^(-?)(\d+)(?:\.(\d+))?$/.exec(trimmed);
  if (!decimal) throw new SyntaxError(`not an exact value: ${text}`);
  const sign = decimal[1] === "-" ? -1n : 1n;
  const whole = BigInt(decimal[2]);
  const frac = decimal[3] ?? "";
  const scale = 10n ** BigInt(frac.length);
  const numerator = whole * scale + (frac === "" ? 0n : BigInt(frac));
  return exact(sign * numerator, scale);
}
