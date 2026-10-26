/**
 * The Hancke-Kuhn rapid-bit-exchange protocol and its verification rule.
 *
 * PROFILE: the original one-nonce, verifier-nonce protocol of Hancke & Kuhn
 * 2005 §3.1, p. 69. The verifier sends an unpredictable N_V that is never
 * reused; both sides compute R0‖R1 := h(K, N_V); then for i = 1..n the
 * verifier sends an unpredictable challenge bit C_i and the prover returns
 * R_i^{C_i} immediately.
 *
 * The paper's §3.1 also sketches an OPTIONAL prover-nonce variant, where both
 * sides send a nonce and the registers come from h(K, N_V, N_P), so that
 * neither nonce need be unpredictable. That variant is NOT implemented here;
 * it is named in the lesson as the paper's own alternative, and the
 * prover-nonce grinding risk it introduces is listed among the limitations.
 */
import { type Exact } from "./exact";
import {
  type Bit,
  type Registers,
  assertRounds,
  deriveRegisters,
  registerDistance,
  response,
} from "./prf";
import {
  type RoundTrip,
  type TimingProfile,
  assertProfile,
  distanceUpperBound,
  threshold,
  withinThreshold,
} from "./timing";

/** What an answering party did in one rapid round. */
export interface RoundRecord {
  readonly round: number;
  readonly challenge: Bit;
  /** The bit the verifier received, or null when nothing arrived at all. */
  readonly received: Bit | null;
  /** The bit an honest holder of the registers would have returned. */
  readonly expected: Bit;
  readonly trip: RoundTrip;
}

export type RoundOutcome = "accepted" | "content-error" | "late" | "missing";

export interface RoundVerdict {
  readonly round: number;
  readonly outcome: RoundOutcome;
  readonly timingOk: boolean;
  readonly contentOk: boolean;
  readonly total: Exact;
  /** v·(T − delta_lb)/2, the displayed bound. Null when nothing arrived. */
  readonly distanceBound: Exact | null;
}

export interface SessionVerdict {
  readonly accepted: boolean;
  readonly rounds: readonly RoundVerdict[];
  readonly threshold: Exact;
  /** Rounds that arrived in time but carried the wrong bit. */
  readonly contentErrors: number;
  /** Rounds that arrived too late. */
  readonly lateRounds: number;
  /** Rounds where nothing arrived at all. */
  readonly missingRounds: number;
  readonly toleratedErrors: number;
  /** A human-readable reason, always present, naming the first failing rule. */
  readonly reason: string;
}

export interface SessionParameters {
  readonly rounds: number;
  /** x, the number of content errors the verifier will tolerate. */
  readonly toleratedErrors: number;
  readonly profile: TimingProfile;
  /** When false, the verifier ignores timing entirely: a broken control. */
  readonly timingEnforced: boolean;
}

export function assertSessionParameters(parameters: SessionParameters): void {
  assertRounds(parameters.rounds);
  assertProfile(parameters.profile);
  const { toleratedErrors, rounds } = parameters;
  if (
    !Number.isInteger(toleratedErrors) ||
    toleratedErrors < 0 ||
    toleratedErrors > rounds
  ) {
    throw new RangeError("tolerated errors x must be an integer in 0..n");
  }
}

/**
 * Verify a completed session.
 *
 * THE RULE THE LESSON TURNS ON: timing and content are checked SEPARATELY, and
 * a late or missing answer can never be absorbed by the content allowance x.
 * A round that arrives after Theta fails on timing whatever bit it carried,
 * and any such round rejects the session even when x > 0. Letting a late
 * answer spend an error allowance would convert a distance-bounding protocol
 * back into an ordinary authentication protocol with extra steps, which is
 * precisely the confusion this lab exists to undo. A mutation that allows it
 * is caught by its own named assertion.
 */
export function verifySession(
  records: readonly RoundRecord[],
  parameters: SessionParameters,
): SessionVerdict {
  assertSessionParameters(parameters);
  if (records.length !== parameters.rounds) {
    throw new RangeError(
      `expected ${parameters.rounds} round records, received ${records.length}`,
    );
  }
  const limit = threshold(parameters.profile);
  const verdicts: RoundVerdict[] = [];
  let contentErrors = 0;
  let lateRounds = 0;
  let missingRounds = 0;

  for (const record of records) {
    const arrived = record.received !== null;
    const timingOk = !parameters.timingEnforced
      ? true
      : arrived && withinThreshold(record.trip.total, parameters.profile);
    const contentOk = arrived && record.received === record.expected;

    let outcome: RoundOutcome;
    if (!arrived) {
      outcome = "missing";
      missingRounds += 1;
    } else if (!timingOk) {
      // Counted as late and NOT as a content error, so it cannot consume x.
      outcome = "late";
      lateRounds += 1;
    } else if (!contentOk) {
      outcome = "content-error";
      contentErrors += 1;
    } else {
      outcome = "accepted";
    }

    verdicts.push({
      round: record.round,
      outcome,
      timingOk,
      contentOk,
      total: record.trip.total,
      distanceBound: arrived
        ? distanceUpperBound(record.trip.total, parameters.profile)
        : null,
    });
  }

  const timingFailures = lateRounds + missingRounds;
  const accepted =
    timingFailures === 0 && contentErrors <= parameters.toleratedErrors;

  let reason: string;
  if (missingRounds > 0) {
    reason = `${missingRounds} round(s) returned nothing; a missing answer fails timing and cannot use the error allowance`;
  } else if (lateRounds > 0) {
    reason = `${lateRounds} round(s) exceeded the modeled threshold; a late answer fails timing and cannot use the error allowance`;
  } else if (contentErrors > parameters.toleratedErrors) {
    reason = `${contentErrors} content error(s) exceed the tolerated ${parameters.toleratedErrors}`;
  } else {
    reason = `every round arrived within the modeled threshold and content errors (${contentErrors}) are within the tolerated ${parameters.toleratedErrors}`;
  }

  return {
    accepted,
    rounds: verdicts,
    threshold: limit,
    contentErrors,
    lateRounds,
    missingRounds,
    toleratedErrors: parameters.toleratedErrors,
    reason,
  };
}

/** The verifier's and the honest prover's shared derivation. */
export function sessionRegisters(
  key: Uint8Array,
  nonce: Uint8Array,
  rounds: number,
): Registers {
  return deriveRegisters(key, nonce, rounds);
}

export { registerDistance, response };

/** Everything a round needs from whoever answered, with no key in sight. */
export interface Answer {
  readonly bit: Bit | null;
  readonly trip: RoundTrip;
}

/** Build the verifier's record of a round from the expected bit and the answer. */
export function recordRound(
  round: number,
  challenge: Bit,
  expected: Bit,
  answer: Answer,
): RoundRecord {
  return {
    round,
    challenge,
    received: answer.bit,
    expected,
    trip: answer.trip,
  };
}
