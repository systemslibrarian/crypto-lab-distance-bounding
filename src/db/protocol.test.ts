/// <reference types="node" />
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { exact, toFraction } from "./exact";
import {
  type Bit,
  BitSource,
  assertRounds,
  deriveRegisters,
  registerDistance,
  response,
} from "./prf";
import {
  type RoundRecord,
  type SessionParameters,
  recordRound,
  verifySession,
} from "./protocol";
import {
  DishonestProver,
  MafiaPreAskAttacker,
  applyNoise,
  corruptionThreshold,
  mafiaRoundTrip,
  ordinaryAuthenticatedRelay,
  proverOracle,
  relayAnswer,
  relayPathLength,
  relayRoundTrip,
} from "./attacks";
import { type TimingProfile, symmetricRoundTrip, threshold } from "./timing";
import { fromHex, utf8 } from "./sha256";

const profile: TimingProfile = {
  v: exact(1n),
  range: exact(10n),
  deltaLb: exact(2n),
};
const KEY = fromHex("00112233445566778899aabbccddeeff");
const NONCE_A = fromHex("a0a1a2a3a4a5a6a7");
const NONCE_B = fromHex("b0b1b2b3b4b5b6b7");

function parameters(
  rounds: number,
  toleratedErrors: number,
  timingEnforced = true,
): SessionParameters {
  return { rounds, toleratedErrors, profile, timingEnforced };
}

describe("verification separates timing from content", () => {
  it("accepts a session whose content errors are inside the allowance", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 4);
    const trip = symmetricRoundTrip(exact(4n), exact(2n), exact(3n));
    const records: RoundRecord[] = [];
    for (let round = 1; round <= 4; round += 1) {
      const c: Bit = 0;
      const expected = response(registers, round, c);
      // Round 2 carries the wrong bit but arrives in time.
      const bit = round === 2 ? ((1 - expected) as Bit) : expected;
      records.push(recordRound(round, c, expected, { bit, trip }));
    }
    const verdict = verifySession(records, parameters(4, 1));
    expect(verdict.contentErrors).toBe(1);
    expect(verdict.lateRounds).toBe(0);
    expect(verdict.accepted).toBe(true);
    expect(verdict.reason).toMatch(/within the tolerated 1/);
  });

  it("REJECTS any late round even when the error allowance is generous", () => {
    // The rule the lesson turns on. Round 3 is late by one unit. Every bit is
    // correct and x = 3 would absorb three content errors, but a late answer
    // is not a content error and cannot spend that allowance.
    const registers = deriveRegisters(KEY, NONCE_A, 4);
    const onTime = symmetricRoundTrip(exact(4n), exact(1n), exact(3n));
    const late = symmetricRoundTrip(exact(10n), exact(1n), exact(3n));
    expect(toFraction(onTime.total)).toBe("11");
    expect(toFraction(late.total)).toBe("23");
    expect(toFraction(threshold(profile))).toBe("22");

    const records: RoundRecord[] = [];
    for (let round = 1; round <= 4; round += 1) {
      const c: Bit = 1;
      const expected = response(registers, round, c);
      records.push(
        recordRound(round, c, expected, {
          bit: expected,
          trip: round === 3 ? late : onTime,
        }),
      );
    }
    for (const x of [0, 1, 2, 3, 4]) {
      const verdict = verifySession(records, parameters(4, x));
      expect(verdict.accepted, `x=${x}`).toBe(false);
      expect(verdict.lateRounds).toBe(1);
      // The late round is NOT counted as a content error.
      expect(verdict.contentErrors).toBe(0);
      expect(verdict.reason).toMatch(/cannot use the error allowance/);
      expect(verdict.rounds[2].outcome).toBe("late");
      expect(verdict.rounds[2].timingOk).toBe(false);
    }
  });

  it("treats a missing answer as a timing failure, never as a content error", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 3);
    const trip = symmetricRoundTrip(exact(4n), exact(1n), exact(3n));
    const records: RoundRecord[] = [];
    for (let round = 1; round <= 3; round += 1) {
      const c: Bit = 0;
      const expected = response(registers, round, c);
      records.push(
        recordRound(round, c, expected, {
          bit: round === 2 ? null : expected,
          trip,
        }),
      );
    }
    const verdict = verifySession(records, parameters(3, 3));
    expect(verdict.accepted).toBe(false);
    expect(verdict.missingRounds).toBe(1);
    expect(verdict.contentErrors).toBe(0);
    expect(verdict.rounds[1].outcome).toBe("missing");
    expect(verdict.rounds[1].distanceBound).toBeNull();
    expect(verdict.reason).toMatch(/returned nothing/);
  });

  it("refuses malformed session parameters by name", () => {
    const trip = symmetricRoundTrip(exact(1n), exact(1n), exact(1n));
    const records = [recordRound(1, 0, 0, { bit: 0, trip })];
    expect(() => verifySession(records, parameters(2, 0))).toThrow(
      /expected 2 round records/,
    );
    expect(() => verifySession(records, parameters(1, 2))).toThrow(/0\.\.n/);
    expect(() => assertRounds(0)).toThrow(/rounds n must be/);
    expect(() => assertRounds(65)).toThrow(/rounds n must be/);
  });
});

describe("the online relay", () => {
  it("returns every correct bit and still fails on timing alone", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 8);
    const oracle = proverOracle(registers);
    const path = {
      verifierToProxyToken: exact(1n),
      relayLink: exact(30n),
      proxyReaderToProver: exact(1n),
      proverDelay: exact(3n),
      relayDelay: exact(1n),
    };
    expect(toFraction(relayPathLength(path))).toBe("32");
    expect(toFraction(relayRoundTrip(path, profile.v).total)).toBe("68");

    const challenges = new BitSource(utf8("relay")).nextBits(8);
    const records: RoundRecord[] = [];
    for (let round = 1; round <= 8; round += 1) {
      const c = challenges[round - 1];
      const answer = relayAnswer(oracle, round, c, path, profile.v);
      records.push(
        recordRound(round, c, response(registers, round, c), answer),
      );
    }

    const verdict = verifySession(records, parameters(8, 3));
    // Every single content check passes.
    expect(verdict.contentErrors).toBe(0);
    expect(records.every((r) => r.received === r.expected)).toBe(true);
    // And the session is still refused, by timing, in every round.
    expect(verdict.accepted).toBe(false);
    expect(verdict.lateRounds).toBe(8);
    expect(verdict.rounds.every((r) => r.outcome === "late")).toBe(true);
  });

  it("BROKEN CONTROL: disabling the timing check lets the same relay pass", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 8);
    const oracle = proverOracle(registers);
    const path = {
      verifierToProxyToken: exact(1n),
      relayLink: exact(30n),
      proxyReaderToProver: exact(1n),
      proverDelay: exact(3n),
      relayDelay: exact(1n),
    };
    const challenges = new BitSource(utf8("relay")).nextBits(8);
    const records: RoundRecord[] = [];
    for (let round = 1; round <= 8; round += 1) {
      const c = challenges[round - 1];
      records.push(
        recordRound(
          round,
          c,
          response(registers, round, c),
          relayAnswer(oracle, round, c, path, profile.v),
        ),
      );
    }
    const enforced = verifySession(records, parameters(8, 0, true));
    const ignored = verifySession(records, parameters(8, 0, false));
    expect(enforced.accepted).toBe(false);
    expect(ignored.accepted).toBe(true);
    expect(ignored.lateRounds).toBe(0);
  });

  it("an ordinary authenticated exchange relays perfectly and proves no distance", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 8);
    const result = ordinaryAuthenticatedRelay(
      proverOracle(registers),
      8,
      new BitSource(utf8("auth")).nextBits(8),
    );
    expect(result.authenticated).toBe(true);
    expect(result.provedProximity).toBe(false);
    expect(result.provedDistance).toBeNull();
    expect(result.note).toMatch(/establishes no upper bound on distance/);
  });
});

describe("mafia fraud by pre-asking", () => {
  it("never receives the key or the registers, and still answers in time", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 8);
    const attacker = new MafiaPreAskAttacker(
      8,
      proverOracle(registers),
      new BitSource(utf8("guess")).nextBits(8),
      new BitSource(utf8("fallback")).nextBits(8),
    );
    expect(attacker.preAsked).toBe(8);
    const trip = mafiaRoundTrip(
      { distance: exact(2n), processingDelay: exact(3n) },
      profile.v,
    );
    expect(toFraction(trip.total)).toBe("7");
    const challenges = new BitSource(utf8("challenge")).nextBits(8);
    const records: RoundRecord[] = [];
    for (let round = 1; round <= 8; round += 1) {
      const c = challenges[round - 1];
      records.push(
        recordRound(
          round,
          c,
          response(registers, round, c),
          attacker.answer(round, c, trip),
        ),
      );
    }
    const verdict = verifySession(records, parameters(8, 8));
    // It passes timing in every round: it is standing next to the verifier.
    expect(verdict.lateRounds).toBe(0);
    // Its only difficulty is content, which is the point of the protocol.
    expect(verdict.contentErrors).toBeGreaterThan(0);
  });

  it("is right in every round where its guessed challenge happened to match", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 16);
    const guesses = new BitSource(utf8("g")).nextBits(16);
    const attacker = new MafiaPreAskAttacker(
      16,
      proverOracle(registers),
      guesses,
      new BitSource(utf8("f")).nextBits(16),
    );
    const trip = mafiaRoundTrip(
      { distance: exact(1n), processingDelay: exact(1n) },
      profile.v,
    );
    const challenges = new BitSource(utf8("c")).nextBits(16);
    let matched = 0;
    for (let round = 1; round <= 16; round += 1) {
      const c = challenges[round - 1];
      const answer = attacker.answer(round, c, trip);
      if (guesses[round - 1] === c) {
        matched += 1;
        expect(answer.bit).toBe(response(registers, round, c));
      }
    }
    expect(matched).toBeGreaterThan(0);
  });

  it("cannot answer a round whose challenge it guessed wrongly", () => {
    // The 3/4 bound exists because a wrong guess DESTROYS the needed value:
    // the prover discards the other register bit. An attacker that still
    // produced R^{C_i} after guessing C'_i != C_i would be holding both halves,
    // which is the same as reading the response registers outright.
    const rounds = 32;
    const registers = deriveRegisters(KEY, NONCE_A, rounds);
    const guesses = new BitSource(utf8("g")).nextBits(rounds);
    const fallback = new BitSource(utf8("f")).nextBits(rounds);
    const attacker = new MafiaPreAskAttacker(
      rounds,
      proverOracle(registers),
      guesses,
      fallback,
    );
    const trip = mafiaRoundTrip(
      { distance: exact(1n), processingDelay: exact(1n) },
      profile.v,
    );
    // Every round below is a MISS: the challenge is the complement of the
    // guess. The attacker must therefore answer with its own fallback bit, in
    // order. Asserting that it differs from the correct bit would be wrong --
    // a coin flip agrees with the truth half the time -- so the property
    // checked is the one that actually distinguishes the two behaviours:
    // WHERE the answer came from.
    let differing = 0;
    for (let round = 1; round <= rounds; round += 1) {
      const challenge = (1 - guesses[round - 1]) as Bit;
      const answer = attacker.answer(round, challenge, trip);
      expect(answer.bit, `round ${round}`).toBe(
        fallback[(round - 1) % fallback.length],
      );
      if (registers.r0[round - 1] !== registers.r1[round - 1]) {
        differing += 1;
        // In these rounds the stored value is a DIFFERENT bit from the correct
        // one, so an attacker returning the stored value would be visible.
        expect(response(registers, round, guesses[round - 1])).not.toBe(
          response(registers, round, challenge),
        );
      }
    }
    expect(differing).toBeGreaterThan(0);
  });

  it("BROKEN CONTROL: predictable challenges make the pre-ask certain", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 12);
    // The verifier emits a fixed alternating pattern, so the attacker simply
    // pre-asks with exactly the challenges it will later be sent.
    const predictable: Bit[] = Array.from(
      { length: 12 },
      (_, i) => (i % 2) as Bit,
    );
    const attacker = new MafiaPreAskAttacker(
      12,
      proverOracle(registers),
      predictable,
      new BitSource(utf8("f")).nextBits(12),
    );
    const trip = mafiaRoundTrip(
      { distance: exact(1n), processingDelay: exact(1n) },
      profile.v,
    );
    const records: RoundRecord[] = [];
    for (let round = 1; round <= 12; round += 1) {
      const c = predictable[round - 1];
      records.push(
        recordRound(
          round,
          c,
          response(registers, round, c),
          attacker.answer(round, c, trip),
        ),
      );
    }
    const verdict = verifySession(records, parameters(12, 0));
    // Every bit correct, zero errors, accepted with no tolerance at all.
    expect(verdict.contentErrors).toBe(0);
    expect(verdict.accepted).toBe(true);
  });

  it("gets nothing from a transcript once the nonce changes", () => {
    // Pre-ask under nonce A, then face a session under nonce B. The stored
    // answers now describe a different response table, so they carry no
    // information: the attacker is reduced to blind guessing.
    const rounds = 24;
    const oldRegisters = deriveRegisters(KEY, NONCE_A, rounds);
    const freshRegisters = deriveRegisters(KEY, NONCE_B, rounds);
    const guesses = new BitSource(utf8("g")).nextBits(rounds);
    const stale = new MafiaPreAskAttacker(
      rounds,
      proverOracle(oldRegisters),
      guesses,
      new BitSource(utf8("f")).nextBits(rounds),
    );
    const trip = mafiaRoundTrip(
      { distance: exact(1n), processingDelay: exact(1n) },
      profile.v,
    );
    let correctWhereGuessMatched = 0;
    let matched = 0;
    for (let round = 1; round <= rounds; round += 1) {
      const c = guesses[round - 1];
      matched += 1;
      const answer = stale.answer(round, c, trip);
      if (answer.bit === response(freshRegisters, round, c)) {
        correctWhereGuessMatched += 1;
      }
    }
    expect(matched).toBe(rounds);
    // Stale answers are right only by chance against the fresh table, so they
    // cannot be right everywhere the way they were under their own nonce.
    expect(correctWhereGuessMatched).toBeLessThan(rounds);
    // Against its OWN nonce the same stored data is right in every matched round.
    const sameNonce = new MafiaPreAskAttacker(
      rounds,
      proverOracle(oldRegisters),
      guesses,
      new BitSource(utf8("f")).nextBits(rounds),
    );
    for (let round = 1; round <= rounds; round += 1) {
      const c = guesses[round - 1];
      expect(sameNonce.answer(round, c, trip).bit).toBe(
        response(oldRegisters, round, c),
      );
    }
  });

  it("BROKEN CONTROL: complementary pre-asks under one reused nonce reveal both registers", () => {
    // Hancke & Kuhn §3.1 names this: running the protocol twice under the same
    // N_V with complementary guesses hands the attacker R0 and R1 outright.
    const rounds = 16;
    const registers = deriveRegisters(KEY, NONCE_A, rounds);
    const oracle = proverOracle(registers);
    const allZero: Bit[] = Array.from({ length: rounds }, () => 0);
    const allOne: Bit[] = Array.from({ length: rounds }, () => 1);
    const first = new MafiaPreAskAttacker(rounds, oracle, allZero, allZero);
    const second = new MafiaPreAskAttacker(rounds, oracle, allOne, allOne);
    const trip = mafiaRoundTrip(
      { distance: exact(1n), processingDelay: exact(1n) },
      profile.v,
    );

    const recoveredR0: Bit[] = [];
    const recoveredR1: Bit[] = [];
    for (let round = 1; round <= rounds; round += 1) {
      recoveredR0.push(first.answer(round, 0, trip).bit as Bit);
      recoveredR1.push(second.answer(round, 1, trip).bit as Bit);
    }
    expect(recoveredR0).toEqual([...registers.r0]);
    expect(recoveredR1).toEqual([...registers.r1]);

    // With the full table, the attacker now answers every challenge correctly.
    const challenges = new BitSource(utf8("c")).nextBits(rounds);
    const records: RoundRecord[] = [];
    for (let round = 1; round <= rounds; round += 1) {
      const c = challenges[round - 1];
      const bit = c === 0 ? recoveredR0[round - 1] : recoveredR1[round - 1];
      records.push(
        recordRound(round, c, response(registers, round, c), { bit, trip }),
      );
    }
    const verdict = verifySession(records, parameters(rounds, 0));
    expect(verdict.accepted).toBe(true);
    expect(verdict.contentErrors).toBe(0);
  });
});

describe("distance fraud", () => {
  it("is certain in every round where R0 and R1 agree", () => {
    const rounds = 32;
    const registers = deriveRegisters(KEY, NONCE_A, rounds);
    const prover = new DishonestProver(registers, [0]);
    let agreeing = 0;
    for (let round = 1; round <= rounds; round += 1) {
      const same = registers.r0[round - 1] === registers.r1[round - 1];
      if (!same) continue;
      agreeing += 1;
      // Whatever challenge arrives, the early answer is already correct.
      const answer = prover.answerEarly(round, exact(1n), exact(0n), profile.v);
      expect(answer.bit).toBe(response(registers, round, 0));
      expect(answer.bit).toBe(response(registers, round, 1));
    }
    expect(agreeing).toBeGreaterThan(0);
    expect(agreeing).toBe(rounds - registerDistance(registers));
  });

  it("is a coin flip exactly in the h rounds where the registers differ", () => {
    const rounds = 32;
    const registers = deriveRegisters(KEY, NONCE_A, rounds);
    const h = registerDistance(registers);
    expect(h).toBeGreaterThan(0);
    expect(h).toBeLessThan(rounds);
    // A prover that always commits to R0 is wrong precisely when the challenge
    // is 1 and the registers differ.
    const prover = new DishonestProver(registers, [0]);
    let differing = 0;
    for (let round = 1; round <= rounds; round += 1) {
      if (registers.r0[round - 1] !== registers.r1[round - 1]) differing += 1;
    }
    expect(differing).toBe(h);
    void prover;
  });

  it("answers early enough to be accepted from outside the honest range", () => {
    // Real distance 11 > R = 10, but answering with zero delay instead of the
    // trusted floor of 2 buys exactly one distance unit, so it is accepted.
    const registers = deriveRegisters(KEY, NONCE_A, 4);
    const prover = new DishonestProver(registers, [0, 1, 0, 1]);
    const records: RoundRecord[] = [];
    for (let round = 1; round <= 4; round += 1) {
      const c: Bit =
        registers.r0[round - 1] === registers.r1[round - 1] ? 0 : 0;
      const answer = prover.answerEarly(
        round,
        exact(11n),
        exact(0n),
        profile.v,
      );
      expect(toFraction(answer.trip.total)).toBe("22");
      records.push(
        recordRound(round, c, response(registers, round, c), answer),
      );
    }
    const verdict = verifySession(records, parameters(4, 4));
    expect(verdict.lateRounds).toBe(0);
    expect(verdict.accepted).toBe(true);
  });
});

describe("noise", () => {
  it("corrupts a bit exactly when the drawn value falls below the threshold", () => {
    const model = { epsilon: exact(1n, 4n), precision: 8 };
    const limit = corruptionThreshold(model);
    expect(limit).toBe(64n);
    expect(applyNoise(0, 63n, limit)).toBe(1);
    expect(applyNoise(0, 64n, limit)).toBe(0);
    expect(applyNoise(1, 0n, limit)).toBe(0);
    expect(applyNoise(1, 255n, limit)).toBe(1);
  });

  it("is a declared independent model, with its bounds enforced", () => {
    expect(corruptionThreshold({ epsilon: exact(0n), precision: 8 })).toBe(0n);
    expect(corruptionThreshold({ epsilon: exact(1n), precision: 8 })).toBe(
      256n,
    );
    expect(() =>
      corruptionThreshold({ epsilon: exact(3n, 2n), precision: 8 }),
    ).toThrow(/\[0, 1\]/);
    expect(() =>
      corruptionThreshold({ epsilon: exact(1n, 2n), precision: 0 }),
    ).toThrow(/1\.\.32/);
  });
});

describe("the attacker knowledge boundary is structural", () => {
  it("never lets attack code import a key, a register derivation or the expected bits", () => {
    const source = readFileSync("src/db/attacks.ts", "utf8");
    // The relay and mafia actors reach the prover only through ProverOracle.
    expect(source).toMatch(/export type ProverOracle/);
    // It must not derive registers itself: that would be reading the key.
    expect(source).not.toMatch(/deriveRegisters/);
    expect(source).not.toMatch(/hmacSha256|sha256/);
    // No module-level mutable state could smuggle a secret across the boundary.
    expect(source).not.toMatch(/^let |^var /m);
  });

  it("recovers nothing from an oracle built on a key the attack never sees", () => {
    // The key is created here and handed only to the oracle. The attacker
    // object is constructed with the oracle alone.
    const secret = new BitSource(utf8("unseen-key")).nextBytes(32);
    const registers = deriveRegisters(secret, NONCE_A, 8);
    const attacker = new MafiaPreAskAttacker(
      8,
      proverOracle(registers),
      new BitSource(utf8("g")).nextBits(8),
      new BitSource(utf8("f")).nextBits(8),
    );
    // It can answer, which is the attack; it holds no derivation of its own.
    const trip = mafiaRoundTrip(
      { distance: exact(1n), processingDelay: exact(1n) },
      profile.v,
    );
    expect([0, 1]).toContain(attacker.answer(1, 0, trip).bit);
    expect(Object.keys(attacker)).toEqual([]);
  });

  it("refuses an out-of-range pre-ask budget or round", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 4);
    const oracle = proverOracle(registers);
    expect(
      () => new MafiaPreAskAttacker(4, oracle, [0, 1, 0, 1], [0], 5),
    ).toThrow(/0\.\.n/);
    expect(() => new MafiaPreAskAttacker(4, oracle, [0, 1], [0], 4)).toThrow(
      /not enough guessed challenges/,
    );
    const attacker = new MafiaPreAskAttacker(4, oracle, [0, 1, 0, 1], [0]);
    const trip = mafiaRoundTrip(
      { distance: exact(1n), processingDelay: exact(1n) },
      profile.v,
    );
    expect(() => attacker.answer(9, 0, trip)).toThrow(/outside the session/);
  });
});

describe("the declared PRF instantiation", () => {
  it("splits h(K, N_V) into two n-bit registers", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 8);
    expect(registers.r0).toHaveLength(8);
    expect(registers.r1).toHaveLength(8);
    expect(registers.r0.every((b) => b === 0 || b === 1)).toBe(true);
  });

  it("changes completely with the nonce and with the key", () => {
    const a = deriveRegisters(KEY, NONCE_A, 32);
    const b = deriveRegisters(KEY, NONCE_B, 32);
    const c = deriveRegisters(fromHex("ff".repeat(16)), NONCE_A, 32);
    expect(a.r0).not.toEqual(b.r0);
    expect(a.r0).not.toEqual(c.r0);
    expect(a.r1).not.toEqual(b.r1);
  });

  it("is deterministic for the same key, nonce and round count", () => {
    expect(deriveRegisters(KEY, NONCE_A, 16)).toEqual(
      deriveRegisters(KEY, NONCE_A, 16),
    );
  });

  it("binds the nonce length so two nonces cannot collide by concatenation", () => {
    const short = deriveRegisters(KEY, fromHex("0102"), 8);
    const long = deriveRegisters(KEY, fromHex("010203"), 8);
    expect(short.r0).not.toEqual(long.r0);
  });

  it("returns the selected register bit for each challenge", () => {
    const registers = deriveRegisters(KEY, NONCE_A, 8);
    for (let round = 1; round <= 8; round += 1) {
      expect(response(registers, round, 0)).toBe(registers.r0[round - 1]);
      expect(response(registers, round, 1)).toBe(registers.r1[round - 1]);
    }
    expect(() => response(registers, 0, 0)).toThrow(/outside the register/);
    expect(() => response(registers, 9, 0)).toThrow(/outside the register/);
  });

  it("replays exactly from a seed and refuses malformed requests", () => {
    expect(new BitSource("x").nextBits(64)).toEqual(
      new BitSource("x").nextBits(64),
    );
    expect(new BitSource("x").nextBits(8)).not.toEqual(
      new BitSource("y").nextBits(8),
    );
    // Crossing the internal block boundary must keep producing bits.
    expect(new BitSource("x").nextBits(600)).toHaveLength(600);
    expect(new BitSource("x").nextBytes(4)).toHaveLength(4);
    expect(() => new BitSource("x").nextBits(-1)).toThrow(/non-negative/);
    expect(() => new BitSource("x").nextBytes(-1)).toThrow(/non-negative/);
  });
});
