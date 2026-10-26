/**
 * Modeled round-trip timing and the acceptance boundary.
 *
 * NO BROWSER OR MACHINE CLOCK REACHES A VERDICT. `Date.now`,
 * `performance.now`, animation duration and real network latency are not read
 * anywhere in this module or anywhere else under `src/db/`. Every quantity
 * below is an exact rational supplied by the scenario, and a unit test reads
 * this directory's source to prove the clock APIs are absent. A lesson about
 * nanosecond propagation that quietly graded itself on JavaScript wall-clock
 * jitter would be teaching the opposite of its subject.
 *
 * Grounding, Hancke & Kuhn 2005 §2, p. 68, equations (1) and (2):
 *
 *     (1)  d   = c · (t_m − t_d) / 2
 *     (2)  t_m = 2 · t_p + t_d
 *
 * where c is the propagation speed, t_p the one-way propagation time, t_m the
 * measured round-trip time and t_d the processing delay at the remote device.
 * This module writes c as `v`, t_m as `T`, and uses a TRUSTED LOWER BOUND
 * `deltaLb` wherever the verifier must stand in for the unknown t_d.
 *
 * UNITS are declared by the scenario and are abstract: `v` is distance units
 * per time unit, `range` is distance units, every delay is time units. The
 * lesson's default profile uses v = 1 so that one distance unit is one
 * light-time unit, which makes the pinned boundary case readable:
 * v = 1, R = 10, deltaLb = 2 gives Theta = 22, so T = 22 accepts and
 * T = 23 rejects.
 */
import {
  type Exact,
  add,
  div,
  exact,
  fromInt,
  isPositive,
  isNonNegative,
  lte,
  mul,
  sub,
} from "./exact";

export interface TimingProfile {
  /** Propagation speed, distance units per time unit. Must be positive. */
  readonly v: Exact;
  /** The accepted modeled range R, in distance units. Must be non-negative. */
  readonly range: Exact;
  /**
   * The trusted lower bound on the prover's processing delay, in time units.
   * The verifier cannot know the true delta_P, so it subtracts only what it is
   * willing to trust. Setting this ABOVE the prover's real floor is the unsafe
   * direction and has its own negative control.
   */
  readonly deltaLb: Exact;
}

export interface RoundTrip {
  /** Verifier to prover leg. */
  readonly tauOut: Exact;
  /** Processing delay actually taken by whoever answered. */
  readonly deltaP: Exact;
  /** Answering party back to verifier leg. */
  readonly tauReturn: Exact;
  /** The measured total, tauOut + deltaP + tauReturn. */
  readonly total: Exact;
}

export function assertProfile(profile: TimingProfile): void {
  if (!isPositive(profile.v)) {
    throw new RangeError("timing profile: propagation speed v must be > 0");
  }
  if (!isNonNegative(profile.range)) {
    throw new RangeError("timing profile: accepted range R must be >= 0");
  }
  if (!isNonNegative(profile.deltaLb)) {
    throw new RangeError("timing profile: delta_lb must be >= 0");
  }
}

/** T = tau_out + delta_P + tau_return. */
export function roundTrip(
  tauOut: Exact,
  deltaP: Exact,
  tauReturn: Exact,
): RoundTrip {
  return {
    tauOut,
    deltaP,
    tauReturn,
    total: add(add(tauOut, deltaP), tauReturn),
  };
}

/**
 * The symmetric direct path of equation (2): a party at distance D answering
 * after its own delay, with both legs travelling the same distance.
 *
 *     T = 2D/v + delta_P
 */
export function symmetricRoundTrip(
  distance: Exact,
  v: Exact,
  deltaP: Exact,
): RoundTrip {
  const leg = div(distance, v);
  return roundTrip(leg, deltaP, leg);
}

/** Theta = 2R/v + delta_lb, the largest round trip the verifier will accept. */
export function threshold(profile: TimingProfile): Exact {
  assertProfile(profile);
  return add(div(mul(fromInt(2), profile.range), profile.v), profile.deltaLb);
}

/**
 * Accept a round only when T <= Theta.
 *
 * Exact comparison. The boundary is inclusive: a round trip of exactly Theta
 * is inside the accepted range, and one time unit more is not.
 */
export function withinThreshold(total: Exact, profile: TimingProfile): boolean {
  return lte(total, threshold(profile));
}

/**
 * The displayed distance upper bound, equation (1) with the trusted lower
 * bound standing in for the unknown processing delay:
 *
 *     D_hat = v · (T − delta_lb) / 2
 *
 * THIS BOUND IS ONLY SAFE WHILE THE PROVER CANNOT ANSWER FASTER THAN
 * delta_lb. If it can, the verifier has subtracted more delay than really
 * occurred, and D_hat understates the true distance: the prover looks nearer
 * than it is. `distanceFraudGain` quantifies that, and an executable negative
 * control drives it.
 */
export function distanceUpperBound(
  total: Exact,
  profile: TimingProfile,
): Exact {
  assertProfile(profile);
  return div(mul(profile.v, sub(total, profile.deltaLb)), fromInt(2));
}

/**
 * How much nearer a prover appears when it answers in `actualDelay` while the
 * verifier credits it with `deltaLb`. Positive means the displayed bound is
 * too small, which is the unsafe direction.
 *
 *     gain = v · (delta_lb − delta_actual) / 2
 */
export function distanceFraudGain(
  profile: TimingProfile,
  actualDelay: Exact,
): Exact {
  assertProfile(profile);
  return div(mul(profile.v, sub(profile.deltaLb, actualDelay)), fromInt(2));
}

/** The true distance implied by a symmetric round trip and a known delay. */
export function trueDistance(
  total: Exact,
  v: Exact,
  actualDelay: Exact,
): Exact {
  return div(mul(v, sub(total, actualDelay)), fromInt(2));
}

/** The reference profile used by the lesson and pinned by the boundary test. */
export const DEFAULT_PROFILE: TimingProfile = {
  v: exact(1n),
  range: exact(10n),
  deltaLb: exact(2n),
};
