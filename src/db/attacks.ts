/**
 * The actor views: who answers, with what knowledge, and what the modeled
 * round trip costs them.
 *
 * THE ATTACKER KNOWLEDGE BOUNDARY IS STRUCTURAL, NOT A COMMENT. The relay and
 * mafia-fraud actors in this file receive a `ProverOracle` — a function that
 * answers one challenge in one round — and nothing else. They are never passed
 * the key, the registers, or the verifier's expected bits, and there is no
 * module-level state holding any of those for them to reach. A unit test reads
 * this file's own source to confirm it never imports a register derivation,
 * and a separate test runs the full mafia attack against an oracle built from
 * a key the attack code never sees.
 *
 * DISTANCE FRAUD IS DIFFERENT AND IS KEPT SEPARATE ON PURPOSE. A distance-
 * fraud actor IS the legitimate key holder, behaving dishonestly at a distance.
 * It is not a relay, there is no third party, and calling it mafia fraud —
 * which several informal accounts do — would misdescribe both the attacker and
 * the defence. It lives in `DishonestProver`, which does hold registers, and
 * the type system keeps the two apart.
 */
import { type Exact, add, div, fromInt, mul, sub } from "./exact";
import { type Bit, type Registers, response } from "./prf";
import { type Answer } from "./protocol";
import { type RoundTrip, roundTrip, symmetricRoundTrip } from "./timing";

/** The ONLY interface an attacker has to an honest prover. */
export type ProverOracle = (round: number, challenge: Bit) => Bit;

/** Build an oracle over a key holder's registers. The attacker gets the result. */
export function proverOracle(registers: Registers): ProverOracle {
  return (round, challenge) => response(registers, round, challenge);
}

/* ------------------------------------------------------------------ */
/* Honest prover                                                        */
/* ------------------------------------------------------------------ */

export interface HonestProverModel {
  readonly distance: Exact;
  readonly processingDelay: Exact;
}

export function honestAnswer(
  registers: Registers,
  round: number,
  challenge: Bit,
  model: HonestProverModel,
  v: Exact,
): Answer {
  return {
    bit: response(registers, round, challenge),
    trip: symmetricRoundTrip(model.distance, v, model.processingDelay),
  };
}

/* ------------------------------------------------------------------ */
/* Relay                                                                */
/* ------------------------------------------------------------------ */

/**
 * A relay inserts two proxies and a link. The complete path is charged to the
 * round trip, which is the only reason the attack is detectable at all: every
 * bit it returns is correct.
 */
export interface RelayPath {
  /** Verifier to the proxy token standing next to it. */
  readonly verifierToProxyToken: Exact;
  /** The attacker's own link between the two proxies. */
  readonly relayLink: Exact;
  /** Proxy reader to the genuine remote prover. */
  readonly proxyReaderToProver: Exact;
  /** The genuine prover's own processing delay. */
  readonly proverDelay: Exact;
  /** Delay the attacker's own equipment adds, over and above propagation. */
  readonly relayDelay: Exact;
}

export function relayRoundTrip(path: RelayPath, v: Exact): RoundTrip {
  const oneWay = add(
    add(path.verifierToProxyToken, path.relayLink),
    path.proxyReaderToProver,
  );
  const leg = div(oneWay, v);
  return roundTrip(leg, add(path.proverDelay, path.relayDelay), leg);
}

/**
 * An online relay: correct bits, full path charged.
 *
 * The attacker holds no key. It forwards the challenge to the real prover
 * through the oracle and forwards the answer back, so every content check
 * passes and only timing can refuse it.
 */
export function relayAnswer(
  oracle: ProverOracle,
  round: number,
  challenge: Bit,
  path: RelayPath,
  v: Exact,
): Answer {
  return { bit: oracle(round, challenge), trip: relayRoundTrip(path, v) };
}

/* ------------------------------------------------------------------ */
/* Mafia fraud by pre-asking                                            */
/* ------------------------------------------------------------------ */

/**
 * A nearby attacker that pre-queries a genuine remote prover with GUESSED
 * challenges, then answers the verifier locally and quickly from memory.
 *
 * Hancke & Kuhn §3.1, p. 69: "In half of all cases, the attacker will have
 * guessed the challenge bit correctly … In the other half of all cases … the
 * attacker will have irrevocably destroyed the correct answer … Therefore, for
 * each challenge Cᵢ, the attacker has only a 3/4 probability of replying
 * correctly."
 *
 * The pre-ask happens in the constructor, BEFORE any real challenge exists.
 * `answer` is the only method that sees a real challenge, and by then the
 * oracle is gone. That ordering is the attack, and making it a constructor
 * boundary rather than a comment is what keeps the model honest.
 */
export class MafiaPreAskAttacker {
  readonly #stored = new Map<number, { guess: Bit; answer: Bit }>();
  readonly #fallback: readonly Bit[];
  readonly #rounds: number;
  #fallbackIndex = 0;

  /**
   * @param rounds        n
   * @param oracle        the genuine prover, reachable only through this
   * @param guesses       C′ᵢ, the attacker's guessed challenges
   * @param fallback      bits the attacker will guess with when its pre-ask missed
   * @param preAskRounds  g, how many rounds it managed to pre-ask
   */
  constructor(
    rounds: number,
    oracle: ProverOracle,
    guesses: readonly Bit[],
    fallback: readonly Bit[],
    preAskRounds: number = rounds,
  ) {
    if (
      !Number.isInteger(preAskRounds) ||
      preAskRounds < 0 ||
      preAskRounds > rounds
    ) {
      throw new RangeError("pre-asked rounds g must be an integer in 0..n");
    }
    if (guesses.length < preAskRounds) {
      throw new RangeError("not enough guessed challenges for the pre-ask");
    }
    this.#rounds = rounds;
    this.#fallback = fallback;
    for (let round = 1; round <= preAskRounds; round += 1) {
      const guess = guesses[round - 1];
      // Asking destroys the other value: the prover discards it, so the
      // attacker can never obtain both halves of a round under one nonce.
      this.#stored.set(round, { guess, answer: oracle(round, guess) });
    }
  }

  /** Rounds the attacker actually pre-asked. */
  get preAsked(): number {
    return this.#stored.size;
  }

  /** Answer the verifier locally. The oracle is unreachable from here. */
  answer(round: number, challenge: Bit, trip: RoundTrip): Answer {
    if (round < 1 || round > this.#rounds) {
      throw new RangeError(`round ${round} is outside the session`);
    }
    const held = this.#stored.get(round);
    if (held && held.guess === challenge) {
      return { bit: held.answer, trip };
    }
    const guess = this.#fallback[this.#fallbackIndex % this.#fallback.length];
    this.#fallbackIndex += 1;
    return { bit: guess, trip };
  }
}

/** Where a nearby mafia attacker stands, and how fast its own hardware is. */
export interface MafiaPosition {
  readonly distance: Exact;
  readonly processingDelay: Exact;
}

export function mafiaRoundTrip(position: MafiaPosition, v: Exact): RoundTrip {
  return symmetricRoundTrip(position.distance, v, position.processingDelay);
}

/* ------------------------------------------------------------------ */
/* Distance fraud                                                       */
/* ------------------------------------------------------------------ */

/**
 * A dishonest DISTANT KEY HOLDER answering early.
 *
 * THIS IS NOT A RELAY AND NOT MAFIA FRAUD. There is no third party and nothing
 * is forwarded. The legitimate prover simply answers before the challenge
 * reaches it, so the verifier subtracts a processing delay that never happened
 * and credits the prover with a shorter distance than it has.
 *
 * It must commit to a bit without knowing Cᵢ. Where R0ᵢ = R1ᵢ it is right
 * whatever the challenge is; elsewhere it is a coin flip. That is why the
 * realized Hamming distance between the registers, not n, is what
 * `distanceFraudSuccess` conditions on.
 */
export class DishonestProver {
  readonly #registers: Registers;
  readonly #choices: readonly Bit[];
  #choiceIndex = 0;

  constructor(registers: Registers, choices: readonly Bit[]) {
    this.#registers = registers;
    this.#choices = choices;
  }

  /**
   * Answer early, without the challenge.
   *
   * @param actualDelay the delay it really took, which may be below the
   *                    verifier's trusted lower bound: that is the fraud.
   */
  answerEarly(
    round: number,
    distance: Exact,
    actualDelay: Exact,
    v: Exact,
  ): Answer {
    const zero = this.#registers.r0[round - 1];
    const one = this.#registers.r1[round - 1];
    let bit: Bit;
    if (zero === one) {
      bit = zero;
    } else {
      bit = this.#choices[this.#choiceIndex % this.#choices.length];
      this.#choiceIndex += 1;
    }
    return { bit, trip: symmetricRoundTrip(distance, v, actualDelay) };
  }
}

/* ------------------------------------------------------------------ */
/* Honest noise                                                         */
/* ------------------------------------------------------------------ */

/**
 * An independent per-response-bit error model.
 *
 * DELIBERATELY SIMPLE AND DELIBERATELY NOT RF. Each returned bit flips
 * independently with probability epsilon, drawn from the deterministic bit
 * source so the session replays. Real radio errors are correlated, bursty,
 * direction-dependent and shaped by multipath, interference and capture; none
 * of that is modeled, and the lesson says so where the number is displayed.
 *
 * `threshold` is the integer `floor(epsilon · 2^precision)`: a drawn
 * `precision`-bit value strictly below it counts as a corruption, which makes
 * the realized error frequency exact and replayable rather than approximate.
 */
export interface NoiseModel {
  readonly epsilon: Exact;
  readonly precision: number;
}

export function corruptionThreshold(model: NoiseModel): bigint {
  if (
    !Number.isInteger(model.precision) ||
    model.precision < 1 ||
    model.precision > 32
  ) {
    throw new RangeError("noise precision must be an integer in 1..32");
  }
  if (model.epsilon.n < 0n || model.epsilon.n > model.epsilon.d) {
    throw new RangeError("epsilon must lie in [0, 1]");
  }
  return (model.epsilon.n * (1n << BigInt(model.precision))) / model.epsilon.d;
}

/** Flip `bit` when the drawn value falls below the corruption threshold. */
export function applyNoise(bit: Bit, drawn: bigint, threshold: bigint): Bit {
  return drawn < threshold ? ((1 - bit) as Bit) : bit;
}

/* ------------------------------------------------------------------ */
/* Ordinary authenticated exchange, for contrast                        */
/* ------------------------------------------------------------------ */

/**
 * A conventional authenticated challenge-response, relayed.
 *
 * There are no rapid bit rounds and no timing check at all: the verifier
 * learns only that somebody holding the key answered. Relaying it succeeds
 * completely, however far away the real prover is. This is the contrast the
 * whole lesson rests on — authentication and proximity are different
 * properties — and it is modeled rather than asserted.
 */
export interface AuthenticatedRelayResult {
  readonly authenticated: boolean;
  readonly provedProximity: boolean;
  readonly provedDistance: Exact | null;
  readonly note: string;
}

export function ordinaryAuthenticatedRelay(
  oracle: ProverOracle,
  rounds: number,
  challenges: readonly Bit[],
): AuthenticatedRelayResult {
  // The relay forwards every challenge and every answer unchanged, so the
  // transcript is exactly the genuine prover's.
  let allCorrect = true;
  for (let round = 1; round <= rounds; round += 1) {
    const challenge = challenges[round - 1];
    if (oracle(round, challenge) !== oracle(round, challenge))
      allCorrect = false;
  }
  return {
    authenticated: allCorrect,
    provedProximity: false,
    provedDistance: null,
    note:
      "The exchange authenticates: the answers came from the key holder. It " +
      "establishes no upper bound on distance, because nothing in it is timed. " +
      "A relay therefore succeeds at any separation.",
  };
}

/** Distance implied by a relay path, for the teaching view only. */
export function relayPathLength(path: RelayPath): Exact {
  return add(
    add(path.verifierToProxyToken, path.relayLink),
    path.proxyReaderToProver,
  );
}

/** How far outside the accepted range a relay's extra path pushes the trip. */
export function relayOverrun(
  path: RelayPath,
  v: Exact,
  thresholdValue: Exact,
): Exact {
  return sub(
    add(
      mul(fromInt(2), div(relayPathLength(path), v)),
      add(path.proverDelay, path.relayDelay),
    ),
    thresholdValue,
  );
}
