/**
 * Exact attack and error probabilities, as BigInt rationals.
 *
 * Every figure here is exact. Decimals are produced only for display, beside
 * the fraction and never instead of it.
 *
 * RELATION TO THE PAPER. Hancke & Kuhn 2005 §3.4, p. 70 writes its two
 * formulas in terms of k, the minimum number of CORRECT responses:
 *
 *     p_FA = Σ_{i=k..n} C(n,i) (3/4)^i (1/4)^(n-i)
 *     p_FR = Σ_{i=0..k-1} C(n,i) (1-ε)^i ε^(n-i)
 *
 * This module is parameterised by x, the number of TOLERATED ERRORS, with
 * x = n − k. Substituting i = n − e turns the first into
 * 4^(-n) Σ_{e=0..x} C(n,e) 3^(n-e) and the second into
 * Σ_{e=x+1..n} C(n,e) ε^e (1-ε)^(n-e). They are the same statements; a unit
 * test checks both parameterisations against each other and against
 * exhaustive enumeration.
 *
 * WHAT THE EXACT NUMBERS ASSUME. Independent uniform PRF output bits, a fresh
 * unpredictable verifier nonce, and challenge bits the attacker cannot
 * predict. Where the lesson breaks one of those, it stops quoting these
 * formulas and says why, rather than printing a number that no longer applies.
 */
import {
  type Exact,
  add,
  binomial,
  exact,
  ipow,
  mul,
  ONE,
  pow,
  sub,
  ZERO,
} from "./exact";

function assertCounts(n: number, x: number): void {
  if (!Number.isInteger(n) || n < 0) {
    throw new RangeError("n must be a non-negative integer");
  }
  if (!Number.isInteger(x) || x < 0) {
    throw new RangeError("tolerated errors x must be a non-negative integer");
  }
}

/**
 * Mafia fraud by pre-asking, with up to x wrong responses tolerated.
 *
 *     P = 4^(-n) · Σ_{e=0..x} C(n,e) · 3^(n-e)
 *
 * The 3/4 is the paper's, §3.1 p. 69: the attacker guesses Cᵢ′ in advance, is
 * right half the time and then holds the correct Rᵢ^{Cᵢ}; when wrong it has
 * destroyed the needed value and guesses, right half of that half.
 */
export function mafiaSuccess(n: number, x: number): Exact {
  assertCounts(n, x);
  let numerator = 0n;
  for (let e = 0; e <= Math.min(x, n); e += 1) {
    numerator += binomial(n, e) * ipow(3n, n - e);
  }
  return exact(numerator, ipow(4n, n));
}

/**
 * A responder with no information at all, guessing every bit.
 *
 *     P = 2^(-n) · Σ_{e=0..x} C(n,e)
 */
export function blindSuccess(n: number, x: number): Exact {
  assertCounts(n, x);
  let numerator = 0n;
  for (let e = 0; e <= Math.min(x, n); e += 1) numerator += binomial(n, e);
  return exact(numerator, ipow(2n, n));
}

/**
 * The exact convolution for a partial pre-ask: g rounds the attacker pre-asked
 * (per-round success 3/4) and n − g rounds it answers blind (per-round success
 * 1/2), with up to x errors tolerated across the whole session.
 *
 *     P = Σ_{e=0..x} Σ_{a+b=e} C(g,a)·3^(g-a)·4^(-g) · C(n-g,b)·2^(-(n-g))
 *
 * This is a genuine convolution over the two error counts, not a product of
 * two independent tolerances. Tolerating x errors overall is strictly weaker
 * for the defender than tolerating x in each part, and a mutation that
 * replaces the convolution with a product is caught by its owning test.
 */
export function partialPreAskSuccess(n: number, g: number, x: number): Exact {
  assertCounts(n, x);
  if (!Number.isInteger(g) || g < 0 || g > n) {
    throw new RangeError("pre-asked rounds g must be an integer in 0..n");
  }
  const blind = n - g;
  let numerator = 0n;
  for (let e = 0; e <= Math.min(x, n); e += 1) {
    for (let a = 0; a <= Math.min(e, g); a += 1) {
      const b = e - a;
      if (b > blind) continue;
      // C(g,a)·3^(g-a) counts pre-asked outcomes with a errors out of 4^g;
      // C(blind,b) counts blind outcomes with b errors out of 2^blind.
      numerator +=
        binomial(g, a) * ipow(3n, g - a) * binomial(blind, b) * ipow(2n, blind);
    }
  }
  // Common denominator 4^g · 2^blind · 2^blind = 4^g · 4^blind = 4^n.
  return exact(numerator, ipow(4n, n));
}

/**
 * Distance fraud against a REALIZED response table.
 *
 * A dishonest distant key holder commits to a response before seeing the
 * challenge, then starts the return transmission when it arrives. In a round
 * where R0ᵢ = R1ᵢ it is right whatever Cᵢ turns out to be; only the
 * h = HammingDistance(R0, R1) positions where they differ are a coin flip.
 *
 *     P = 2^(-h) · Σ_{e=0..min(x,h)} C(h,e)
 *
 * Note the parameter is h, not n. Conditioning on the realized table is the
 * point: a session that happens to draw a small h is a weak session, and
 * hiding it behind the ensemble average is what `distanceFraudEnsemble` exists
 * to be shown BESIDE, never instead of.
 */
export function distanceFraudSuccess(h: number, x: number): Exact {
  if (!Number.isInteger(h) || h < 0) {
    throw new RangeError("register distance h must be a non-negative integer");
  }
  assertCounts(h, x);
  let numerator = 0n;
  for (let e = 0; e <= Math.min(x, h); e += 1) numerator += binomial(h, e);
  return exact(numerator, ipow(2n, h));
}

/**
 * The ideal ensemble average over h ~ Binomial(n, 1/2).
 *
 *     P = Σ_{h=0..n} C(n,h)·2^(-n) · distanceFraudSuccess(h, x)
 *
 * Displayed ALONGSIDE the realized figure. An average cannot tell a learner
 * whether the session in front of them is the weak one.
 */
export function distanceFraudEnsemble(n: number, x: number): Exact {
  assertCounts(n, x);
  let total: Exact = ZERO;
  for (let h = 0; h <= n; h += 1) {
    const weight = exact(binomial(n, h), ipow(2n, n));
    total = add(total, mul(weight, distanceFraudSuccess(h, x)));
  }
  return total;
}

/**
 * An honest prover's session is rejected when independent per-bit corruption
 * ε produces more than x errors.
 *
 *     P_false_reject = Σ_{e=x+1..n} C(n,e) ε^e (1-ε)^(n-e)
 */
export function falseRejection(n: number, x: number, epsilon: Exact): Exact {
  assertCounts(n, x);
  assertProbability(epsilon, "epsilon");
  const keep = sub(ONE, epsilon);
  let total: Exact = ZERO;
  for (let e = x + 1; e <= n; e += 1) {
    total = add(
      total,
      mul(mul(exact(binomial(n, e)), pow(epsilon, e)), pow(keep, n - e)),
    );
  }
  return total;
}

/** The complement: an honest session accepted despite independent noise. */
export function honestAcceptance(n: number, x: number, epsilon: Exact): Exact {
  return sub(ONE, falseRejection(n, x, epsilon));
}

/**
 * q independent attempts, each with a FRESH verifier nonce.
 *
 *     P = 1 − (1 − p)^q
 *
 * THIS FORMULA DOES NOT APPLY WHEN A NONCE IS REUSED. Reuse makes the attempts
 * dependent — the same response table answers both — which is the whole point
 * of the nonce-reuse experiment, and calling the attempts independent there
 * would understate the attacker badly. `repeatedAttempts` refuses to be used
 * that way by taking the independence as an explicit argument.
 */
export function repeatedAttempts(
  perAttempt: Exact,
  q: number,
  freshNoncePerAttempt: boolean,
): Exact {
  if (!Number.isInteger(q) || q < 0) {
    throw new RangeError("attempt count q must be a non-negative integer");
  }
  assertProbability(perAttempt, "per-attempt probability");
  if (!freshNoncePerAttempt) {
    throw new RangeError(
      "repeatedAttempts: attempts are not independent when the verifier nonce " +
        "is reused, so 1-(1-p)^q does not apply",
    );
  }
  return sub(ONE, pow(sub(ONE, perAttempt), q));
}

export function assertProbability(value: Exact, label: string): void {
  if (value.n < 0n || value.n > value.d) {
    throw new RangeError(`${label} must lie in [0, 1]`);
  }
}
