import { describe, expect, it } from "vitest";
import { cmp, eq, exact, toFraction } from "./exact";
import {
  DEFAULT_CONFIG,
  REUSED_NONCE_HEX,
  type ScenarioConfig,
  type ScenarioName,
  blindBaseline,
  fraudGain,
  relayExcess,
  runScenario,
} from "./scenario";
import {
  blindSuccess,
  distanceFraudSuccess,
  mafiaSuccess,
} from "./probability";

const run = (overrides: Partial<ScenarioConfig> = {}) =>
  runScenario({ ...DEFAULT_CONFIG, ...overrides });

const ALL: ScenarioName[] = [
  "honest",
  "honest-noisy",
  "authenticated-relay",
  "online-relay",
  "mafia-preask",
  "distance-fraud",
];

describe("every scenario is complete and replayable", () => {
  it("produces a full transcript for each actor", () => {
    for (const scenario of ALL) {
      const result = run({ scenario });
      expect(result.records, scenario).toHaveLength(DEFAULT_CONFIG.rounds);
      expect(result.verdict.rounds, scenario).toHaveLength(
        DEFAULT_CONFIG.rounds,
      );
      expect(result.challenges, scenario).toHaveLength(DEFAULT_CONFIG.rounds);
      expect(result.notes.length, scenario).toBeGreaterThan(0);
      expect(toFraction(result.threshold), scenario).toBe("22");
      expect(result.analysis.registerDistance).toBeGreaterThanOrEqual(0);
      expect(result.analysis.registerDistance).toBeLessThanOrEqual(
        DEFAULT_CONFIG.rounds,
      );
    }
  });

  it("replays byte for byte from the same seed, and differs from another", () => {
    for (const scenario of ALL) {
      const a = run({ scenario });
      const b = run({ scenario });
      expect(a.nonceHex).toBe(b.nonceHex);
      expect(a.challenges).toEqual(b.challenges);
      expect(a.records.map((r) => r.received)).toEqual(
        b.records.map((r) => r.received),
      );
      expect(a.verdict.accepted).toBe(b.verdict.accepted);

      const other = run({ scenario, seed: "a-different-seed" });
      expect(other.nonceHex).not.toBe(a.nonceHex);
    }
  });
});

describe("the six required actor views", () => {
  it("accepts the honest prover inside the range", () => {
    const result = run({ scenario: "honest" });
    expect(result.verdict.accepted).toBe(true);
    expect(result.verdict.contentErrors).toBe(0);
    expect(result.verdict.lateRounds).toBe(0);
    // Distance 4, delay 3, so T = 11, comfortably inside Theta = 22.
    expect(toFraction(result.records[0].trip.total)).toBe("11");
  });

  it("shows an ordinary authenticated exchange relaying with no proximity proof", () => {
    const result = run({ scenario: "authenticated-relay" });
    expect(result.authenticatedRelay).not.toBeNull();
    expect(result.authenticatedRelay?.authenticated).toBe(true);
    expect(result.authenticatedRelay?.provedProximity).toBe(false);
    expect(result.records.every((r) => r.received === r.expected)).toBe(true);
  });

  it("charges the whole relay path to the online relay and refuses it", () => {
    const result = run({ scenario: "online-relay" });
    expect(result.records.every((r) => r.received === r.expected)).toBe(true);
    expect(result.verdict.contentErrors).toBe(0);
    expect(result.verdict.accepted).toBe(false);
    expect(result.verdict.lateRounds).toBe(DEFAULT_CONFIG.rounds);
    // 2*(1+30+1)/1 + 3 + 1 = 68, which overshoots Theta = 22 by 46.
    expect(toFraction(relayExcess(DEFAULT_CONFIG))).toBe("46");
  });

  it("lets the mafia attacker pass timing and quotes its exact chance", () => {
    const result = run({ scenario: "mafia-preask" });
    expect(result.verdict.lateRounds).toBe(0);
    expect(result.analysis.adversarySuccess).not.toBeNull();
    expect(eq(result.analysis.adversarySuccess!, mafiaSuccess(8, 1))).toBe(
      true,
    );
    expect(toFraction(result.analysis.adversarySuccess!)).toBe("24057/65536");
    // Strictly better than guessing, strictly worse than certainty.
    expect(cmp(result.analysis.adversarySuccess!, blindSuccess(8, 1))).toBe(1);
    expect(cmp(result.analysis.adversarySuccess!, exact(1n))).toBe(-1);
  });

  it("never hands the mafia attacker the verifier's real challenges", () => {
    // Its guessed challenges must be its OWN. If the scenario passed it the
    // real ones it would answer every round correctly while the page still
    // quoted a 3/4-per-round figure, which would be a false claim about an
    // attacker that had in effect read the response registers.
    const result = run({
      scenario: "mafia-preask",
      rounds: 16,
      toleratedErrors: 16,
    });
    expect(result.verdict.lateRounds).toBe(0);
    expect(result.verdict.contentErrors).toBeGreaterThan(0);
    expect(result.config.predictableChallenges).toBe(false);
  });

  it("quotes a partial pre-ask against the convolution, not the pure case", () => {
    const result = run({ scenario: "mafia-preask", preAskRounds: 4 });
    expect(result.analysis.adversarySuccessLabel).toMatch(/g = 4 of 8/);
    expect(cmp(result.analysis.adversarySuccess!, mafiaSuccess(8, 1))).toBe(-1);
    expect(cmp(result.analysis.adversarySuccess!, blindSuccess(8, 1))).toBe(1);
  });

  it("conditions distance fraud on the realized table and shows the average beside it", () => {
    const result = run({ scenario: "distance-fraud" });
    const h = result.analysis.registerDistance;
    expect(
      eq(result.analysis.adversarySuccess!, distanceFraudSuccess(h, 1)),
    ).toBe(true);
    expect(result.analysis.ensembleAverage).not.toBeNull();
    expect(result.analysis.adversarySuccessLabel).toMatch(
      new RegExp(`realized register distance h = ${h}`),
    );
    // The fraud buys exactly v(delta_lb - delta_actual)/2 = 1 distance unit.
    expect(toFraction(fraudGain(DEFAULT_CONFIG))).toBe("1");
  });

  it("describes distance fraud as the key holder, never as a relay", () => {
    const result = run({ scenario: "distance-fraud" });
    const text = result.notes.join(" ");
    expect(text).toMatch(/legitimate key holder/);
    expect(text).toMatch(/NOT mafia fraud/);
    expect(text).toMatch(/no relay and no third party/);
  });

  it("reports exact honest acceptance and false rejection under noise", () => {
    const result = run({ scenario: "honest-noisy" });
    expect(toFraction(result.analysis.honestAcceptance!)).toBe(
      "12353145/16777216",
    );
    expect(toFraction(result.analysis.falseRejection!)).toBe(
      "4424071/16777216",
    );
    expect(result.notes.join(" ")).toMatch(/correlated and bursty/);
  });
});

describe("the broken controls", () => {
  it("names the reused nonce and withdraws the independence formula", () => {
    const result = run({ reuseNonce: true });
    expect(result.nonceHex).toBe(REUSED_NONCE_HEX);
    expect(result.analysis.formulaCaveats.join(" ")).toMatch(
      /not independent|must not be applied/,
    );
  });

  it("makes a predictable-challenge pre-ask certain and says the 3/4 no longer applies", () => {
    const result = run({
      scenario: "mafia-preask",
      predictableChallenges: true,
    });
    expect(result.verdict.contentErrors).toBe(0);
    expect(result.verdict.accepted).toBe(true);
    expect(eq(result.analysis.adversarySuccess!, exact(1n))).toBe(true);
    expect(result.analysis.formulaCaveats.join(" ")).toMatch(
      /does not apply|succeeds with certainty/,
    );
  });

  it("says plainly that disabling timing stops it being distance bounding", () => {
    const result = run({ scenario: "online-relay", timingEnforced: false });
    expect(result.verdict.accepted).toBe(true);
    expect(result.analysis.formulaCaveats.join(" ")).toMatch(
      /no longer distance bounding/,
    );
  });

  it("accepts an out-of-range prover when delta_lb is set above its real floor", () => {
    // The invalid processing-delay lower bound. The prover really takes 0, the
    // verifier trusts 2, and an 11-unit prover is accepted inside R = 10.
    const result = run({
      scenario: "distance-fraud",
      fraudDistance: exact(11n),
      fraudDelay: exact(0n),
      toleratedErrors: 8,
    });
    expect(result.verdict.lateRounds).toBe(0);
    expect(result.verdict.accepted).toBe(true);
    expect(toFraction(result.records[0].trip.total)).toBe("22");
    expect(toFraction(result.verdict.rounds[0].distanceBound!)).toBe("10");
  });
});

describe("baselines and helpers", () => {
  it("reports the blind baseline for the current parameters", () => {
    expect(toFraction(blindBaseline(DEFAULT_CONFIG))).toBe("9/256");
  });

  it("rejects an invalid round count before running anything", () => {
    expect(() => run({ rounds: 0 })).toThrow(/rounds n must be/);
    expect(() => run({ rounds: 65 })).toThrow(/rounds n must be/);
  });

  it("refuses a tolerated-error count larger than the round count", () => {
    expect(() => run({ rounds: 4, toleratedErrors: 5 })).toThrow(/0\.\.n/);
  });
});
