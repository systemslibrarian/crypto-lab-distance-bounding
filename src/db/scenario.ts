/**
 * Deterministic scenarios: who answers, under which broken or intact control,
 * and what the verifier concludes.
 *
 * Every scenario replays exactly from its seed. Nothing here reads a clock.
 */
import { type Exact, exact, toFraction } from "./exact";
import {
  type Bit,
  type Registers,
  BitSource,
  assertRounds,
  deriveRegisters,
  registerDistance,
  response,
} from "./prf";
import {
  type RoundRecord,
  type SessionParameters,
  type SessionVerdict,
  recordRound,
  verifySession,
} from "./protocol";
import {
  type HonestProverModel,
  type MafiaPosition,
  type NoiseModel,
  type ProverOracle,
  type RelayPath,
  DishonestProver,
  MafiaPreAskAttacker,
  applyNoise,
  mafiaRoundTrip,
  ordinaryAuthenticatedRelay,
  proverOracle,
  relayOverrun,
  relayPathLength,
  relayRoundTrip,
} from "./attacks";
import {
  type TimingProfile,
  DEFAULT_PROFILE,
  distanceFraudGain,
  symmetricRoundTrip,
  threshold,
} from "./timing";
import {
  blindSuccess,
  distanceFraudEnsemble,
  distanceFraudSuccess,
  falseRejection,
  honestAcceptance,
  mafiaSuccess,
  partialPreAskSuccess,
  repeatedAttempts,
} from "./probability";
import { concatBytes, fromHex, hmacSha256, utf8 } from "./sha256";

export type ScenarioName =
  | "honest"
  | "honest-noisy"
  | "authenticated-relay"
  | "online-relay"
  | "mafia-preask"
  | "distance-fraud";

export interface ScenarioConfig {
  readonly scenario: ScenarioName;
  readonly rounds: number;
  readonly toleratedErrors: number;
  readonly profile: TimingProfile;
  /** Seeds the deterministic challenge and nonce source. */
  readonly seed: string;
  /** Shared key, hex. Held by the verifier and the key holder only. */
  readonly keyHex: string;
  readonly honest: HonestProverModel;
  readonly relay: RelayPath;
  readonly mafia: MafiaPosition;
  readonly fraudDistance: Exact;
  readonly fraudDelay: Exact;
  readonly noise: NoiseModel;
  /** g, the rounds a mafia attacker manages to pre-ask. */
  readonly preAskRounds: number;
  /** Broken control: the verifier ignores timing. */
  readonly timingEnforced: boolean;
  /** Broken control: challenges are a fixed pattern the attacker knows. */
  readonly predictableChallenges: boolean;
  /** Broken control: the verifier reuses the previous nonce. */
  readonly reuseNonce: boolean;
}

export interface ScenarioAnalysis {
  /** The realized Hamming distance between R0 and R1 for this session. */
  readonly registerDistance: number;
  /** Exact per-session success probability for the acting adversary, or null. */
  readonly adversarySuccess: Exact | null;
  readonly adversarySuccessLabel: string;
  /** For distance fraud: the ideal ensemble average, shown beside the realized value. */
  readonly ensembleAverage: Exact | null;
  readonly honestAcceptance: Exact | null;
  readonly falseRejection: Exact | null;
  /** Non-empty when a broken control makes the exact formulas inapplicable. */
  readonly formulaCaveats: readonly string[];
}

export interface ScenarioResult {
  readonly config: ScenarioConfig;
  readonly nonceHex: string;
  readonly challenges: readonly Bit[];
  readonly records: readonly RoundRecord[];
  /** Null for the ordinary untimed authentication comparison. */
  readonly verdict: SessionVerdict | null;
  readonly threshold: Exact;
  readonly analysis: ScenarioAnalysis;
  /** Present only for the authenticated-relay contrast. */
  readonly authenticatedRelay: ReturnType<
    typeof ordinaryAuthenticatedRelay
  > | null;
  /** Present only for authentication: true when one changed tag is refused. */
  readonly authenticationTamperRejected: boolean | null;
  readonly notes: readonly string[];
}

/** The nonce the verifier would reuse under the broken-control scenario. */
export const REUSED_NONCE_HEX = "a1a1a1a1a1a1a1a1";

export const DEFAULT_CONFIG: ScenarioConfig = {
  scenario: "honest",
  rounds: 8,
  toleratedErrors: 1,
  profile: DEFAULT_PROFILE,
  seed: "s06-default",
  keyHex: "4b65792d666f722d7468652d6c6573736f6e2d6f6e6c79",
  honest: { distance: exact(4n), processingDelay: exact(3n) },
  relay: {
    verifierToProxyToken: exact(1n),
    relayLink: exact(30n),
    proxyReaderToProver: exact(1n),
    proverDelay: exact(3n),
    relayDelay: exact(1n),
  },
  mafia: { distance: exact(2n), processingDelay: exact(3n) },
  fraudDistance: exact(14n),
  fraudDelay: exact(0n),
  noise: { epsilon: exact(1n, 8n) },
  preAskRounds: 8,
  timingEnforced: true,
  predictableChallenges: false,
  reuseNonce: false,
};

function challengeBits(
  source: BitSource,
  rounds: number,
  predictable: boolean,
): Bit[] {
  if (!predictable) return source.nextBits(rounds);
  // A broken control: the verifier emits a fixed alternating pattern, which an
  // attacker can simply read off and pre-ask with perfectly.
  return Array.from({ length: rounds }, (_, i) => (i % 2) as Bit);
}

const AUTH_DOMAIN = utf8("crypto-lab-distance-bounding/auth-v1\0");

function authenticationTag(key: Uint8Array, challenge: Uint8Array): Uint8Array {
  return hmacSha256(key, concatBytes(AUTH_DOMAIN, challenge));
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

/**
 * Run one scenario end to end.
 *
 * The key never leaves this function's own derivation of the registers and the
 * oracle built from them. The relay and mafia actors receive only the oracle.
 */
export function runScenario(config: ScenarioConfig): ScenarioResult {
  assertRounds(config.rounds);
  const key = fromHex(config.keyHex);
  const source = new BitSource(utf8(`${config.seed}/${config.scenario}`));
  const nonce = config.reuseNonce
    ? fromHex(REUSED_NONCE_HEX)
    : source.nextBytes(16);
  const registers: Registers = deriveRegisters(key, nonce, config.rounds);
  const oracle: ProverOracle = proverOracle(registers);
  const challenges =
    config.scenario === "authenticated-relay"
      ? []
      : challengeBits(source, config.rounds, config.predictableChallenges);
  const limit = threshold(config.profile);
  const v = config.profile.v;
  const parameters: SessionParameters = {
    rounds: config.rounds,
    toleratedErrors: config.toleratedErrors,
    profile: config.profile,
    timingEnforced: config.timingEnforced,
  };

  const records: RoundRecord[] = [];
  const notes: string[] = [];
  let authenticatedRelay: ScenarioResult["authenticatedRelay"] = null;
  let authenticationTamperRejected: boolean | null = null;
  let analysisSuccess: Exact | null = null;
  let analysisLabel = "not applicable to this actor";
  let ensemble: Exact | null = null;
  const caveats: string[] = [];

  if (config.predictableChallenges && config.scenario === "mafia-preask") {
    const blindRounds = config.rounds - config.preAskRounds;
    caveats.push(
      "Challenges follow a fixed pattern, so the 3/4 figure does not apply. " +
        `The ${config.preAskRounds} pre-asked round(s) are certain; the remaining ` +
        `${blindRounds} round(s) are still blind guesses.`,
    );
  }
  if (config.predictableChallenges && config.scenario === "distance-fraud") {
    caveats.push(
      "The challenge pattern is known before the rapid phase, so this key " +
        "holder can preselect every correct response. The unknown-challenge " +
        "distance-fraud formula does not apply.",
    );
  }
  if (config.reuseNonce) {
    caveats.push(
      "The verifier reused its nonce, so sessions are not independent and " +
        "1-(1-p)^q must not be applied across attempts. Two complementary " +
        "pre-asks under one nonce recover both registers outright.",
    );
  }
  if (!config.timingEnforced) {
    caveats.push(
      "Timing is disabled, so this is no longer distance bounding: the verdict " +
        "reflects content only and a relay passes at any distance.",
    );
  }

  switch (config.scenario) {
    case "honest": {
      for (let round = 1; round <= config.rounds; round += 1) {
        const c = challenges[round - 1];
        const trip = symmetricRoundTrip(
          config.honest.distance,
          v,
          config.honest.processingDelay,
        );
        records.push(
          recordRound(round, c, response(registers, round, c), {
            bit: response(registers, round, c),
            trip,
          }),
        );
      }
      notes.push(
        "The genuine prover answers from the registers it derived from the same " +
          "nonce and key, at its real distance.",
      );
      break;
    }

    case "honest-noisy": {
      for (let round = 1; round <= config.rounds; round += 1) {
        const c = challenges[round - 1];
        const correct = response(registers, round, c);
        const trip = symmetricRoundTrip(
          config.honest.distance,
          v,
          config.honest.processingDelay,
        );
        records.push(
          recordRound(round, c, correct, {
            bit: applyNoise(correct, source, config.noise.epsilon),
            trip,
          }),
        );
      }
      notes.push(
        "Each returned bit flips independently with probability " +
          `${toFraction(config.noise.epsilon)}. Real radio errors are correlated and bursty; this model is not.`,
      );
      break;
    }

    case "authenticated-relay": {
      const authChallenge = source.nextBytes(16);
      const verifyTag = (challenge: Uint8Array, tag: Uint8Array) =>
        equalBytes(authenticationTag(key, challenge), tag);
      authenticatedRelay = ordinaryAuthenticatedRelay(
        (challenge) => authenticationTag(key, challenge),
        authChallenge,
        verifyTag,
      );
      const altered = ordinaryAuthenticatedRelay(
        (challenge) => {
          const tag = authenticationTag(key, challenge);
          tag[0] ^= 1;
          return tag;
        },
        authChallenge,
        verifyTag,
      );
      authenticationTamperRejected = !altered.authenticated;
      notes.push(
        "The relay forwards a 128-bit challenge and a genuine HMAC-SHA-256 " +
          "response without learning the shared key. The verifier accepts the " +
          "tag, but no rapid phase or timing measurement exists, so the exchange " +
          "establishes authentication and no proximity bound.",
      );
      break;
    }

    case "online-relay": {
      for (let round = 1; round <= config.rounds; round += 1) {
        const c = challenges[round - 1];
        const trip = relayRoundTrip(config.relay, v);
        records.push(
          recordRound(round, c, response(registers, round, c), {
            bit: oracle(round, c),
            trip,
          }),
        );
      }
      notes.push(
        "Every returned bit is correct. The complete relay path " +
          `(${toFraction(relayPathLength(config.relay))} one way) is charged to each round trip, ` +
          "which is the only thing that refuses it.",
      );
      break;
    }

    case "mafia-preask": {
      const guesses = config.predictableChallenges
        ? challenges.slice()
        : new BitSource(utf8(`${config.seed}/mafia-guess`)).nextBits(
            config.rounds,
          );
      const fallback = new BitSource(
        utf8(`${config.seed}/mafia-fallback`),
      ).nextBits(Math.max(1, config.rounds));
      const attacker = new MafiaPreAskAttacker(
        config.rounds,
        oracle,
        guesses,
        fallback,
        config.preAskRounds,
      );
      for (let round = 1; round <= config.rounds; round += 1) {
        const c = challenges[round - 1];
        const answer = attacker.answer(
          round,
          c,
          mafiaRoundTrip(config.mafia, v),
        );
        records.push(
          recordRound(round, c, response(registers, round, c), answer),
        );
      }
      analysisSuccess = config.predictableChallenges
        ? blindSuccess(
            config.rounds - config.preAskRounds,
            config.toleratedErrors,
          )
        : config.preAskRounds >= config.rounds
          ? mafiaSuccess(config.rounds, config.toleratedErrors)
          : partialPreAskSuccess(
              config.rounds,
              config.preAskRounds,
              config.toleratedErrors,
            );
      analysisLabel = config.predictableChallenges
        ? `${config.preAskRounds} predictable pre-asks; ${config.rounds - config.preAskRounds} blind round(s)`
        : config.preAskRounds >= config.rounds
          ? "mafia pre-ask over every round"
          : `partial pre-ask, g = ${config.preAskRounds} of ${config.rounds}`;
      notes.push(
        "The attacker stands near the verifier and answers from memory, so it " +
          "passes timing. It pre-asked the genuine prover with guessed " +
          "challenges and never saw the key or the registers.",
      );
      break;
    }

    case "distance-fraud": {
      const choices = config.predictableChallenges
        ? Array.from({ length: config.rounds }, (_, index) => index + 1)
            .filter(
              (round) => registers.r0[round - 1] !== registers.r1[round - 1],
            )
            .map((round) => response(registers, round, challenges[round - 1]))
        : new BitSource(utf8(`${config.seed}/fraud-choice`)).nextBits(
            Math.max(1, config.rounds),
          );
      // If h = 0, no early choice is consumed; keep the constructor's direct-
      // caller guard while allowing this degenerate response table.
      if (choices.length === 0) choices.push(0);
      const prover = new DishonestProver(registers, choices);
      for (let round = 1; round <= config.rounds; round += 1) {
        const c = challenges[round - 1];
        const answer = prover.answerEarly(
          round,
          config.fraudDistance,
          config.fraudDelay,
          v,
        );
        records.push(
          recordRound(round, c, response(registers, round, c), answer),
        );
      }
      const h = registerDistance(registers);
      analysisSuccess = config.predictableChallenges
        ? exact(1n)
        : distanceFraudSuccess(h, config.toleratedErrors);
      ensemble = config.predictableChallenges
        ? null
        : distanceFraudEnsemble(config.rounds, config.toleratedErrors);
      analysisLabel = config.predictableChallenges
        ? "certain under the known challenge pattern"
        : `realized register distance h = ${h}`;
      notes.push(
        "This is the legitimate key holder behaving dishonestly at a distance. " +
          "There is no relay and no third party, so it is NOT mafia fraud. It " +
          "commits to a response before seeing the challenge, then transmits " +
          "after challenge arrival; the model retains both propagation legs and " +
          "removes only the processing delay the verifier assumed.",
      );
      break;
    }
  }

  const verdict =
    config.scenario === "authenticated-relay"
      ? null
      : verifySession(records, parameters);

  const analysis: ScenarioAnalysis = {
    registerDistance: registerDistance(registers),
    adversarySuccess: analysisSuccess,
    adversarySuccessLabel: analysisLabel,
    ensembleAverage: ensemble,
    honestAcceptance:
      config.scenario === "honest-noisy"
        ? honestAcceptance(
            config.rounds,
            config.toleratedErrors,
            config.noise.epsilon,
          )
        : null,
    falseRejection:
      config.scenario === "honest-noisy"
        ? falseRejection(
            config.rounds,
            config.toleratedErrors,
            config.noise.epsilon,
          )
        : null,
    formulaCaveats: caveats,
  };

  return {
    config,
    nonceHex: Array.from(nonce, (b) => b.toString(16).padStart(2, "0")).join(
      "",
    ),
    challenges,
    records,
    verdict,
    threshold: limit,
    analysis,
    authenticatedRelay,
    authenticationTamperRejected,
    notes,
  };
}

/**
 * The chance an adversary succeeds in at least one of `q` attempts.
 *
 * Returns null when the verifier reused its nonce: the attempts are then NOT
 * independent -- the same response table answers all of them -- so 1-(1-p)^q
 * does not apply and no number is printed in its place. `repeatedAttempts`
 * refuses that case outright; this is where the lesson decides not to ask.
 */
export function attemptsSuccess(
  config: ScenarioConfig,
  perAttempt: Exact | null,
  attempts: number,
): Exact | null {
  if (perAttempt === null || config.reuseNonce) return null;
  return repeatedAttempts(perAttempt, attempts, true);
}

/** The blind-guess baseline for the current parameters, for comparison. */
export function blindBaseline(config: ScenarioConfig): Exact {
  return blindSuccess(config.rounds, config.toleratedErrors);
}

/** How much closer distance fraud makes the prover look. */
export function fraudGain(config: ScenarioConfig): Exact {
  return distanceFraudGain(config.profile, config.fraudDelay);
}

/** How far a relay's extra path overshoots the accepted threshold. */
export function relayExcess(config: ScenarioConfig): Exact {
  return relayOverrun(
    config.relay,
    config.profile.v,
    threshold(config.profile),
  );
}
