/// <reference types="node" />
import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  type Exact,
  eq,
  exact,
  parseExact,
  toDecimal,
  toFraction,
} from "./exact";
import {
  DEFAULT_PROFILE,
  type TimingProfile,
  assertProfile,
  distanceFraudGain,
  distanceUpperBound,
  roundTrip,
  symmetricRoundTrip,
  threshold,
  trueDistance,
  withinThreshold,
} from "./timing";

const profile: TimingProfile = {
  v: exact(1n),
  range: exact(10n),
  deltaLb: exact(2n),
};

describe("the pinned acceptance boundary", () => {
  it("places Theta at exactly 22 for v = 1, R = 10, delta_lb = 2", () => {
    expect(toFraction(threshold(profile))).toBe("22");
  });

  it("accepts T = 22 and rejects T = 23, with no tolerance either side", () => {
    expect(withinThreshold(exact(22n), profile)).toBe(true);
    expect(withinThreshold(exact(23n), profile)).toBe(false);
    // The boundary is inclusive and exact: one unit under passes, and a
    // rational a hair over fails rather than rounding into acceptance.
    expect(withinThreshold(exact(21n), profile)).toBe(true);
    expect(withinThreshold(parseExact("22.000000000000000001"), profile)).toBe(
      false,
    );
    expect(withinThreshold(exact(22000001n, 1000000n), profile)).toBe(false);
    expect(withinThreshold(exact(21999999n, 1000000n), profile)).toBe(true);
  });

  it("is computed from exact rationals that a float would have blurred", () => {
    // 0.1 + 0.2 !== 0.3 in binary floating point. Here it is exact, and a
    // threshold built from thirds lands on the boundary rather than beside it.
    const thirds: TimingProfile = {
      v: exact(3n),
      range: exact(1n),
      deltaLb: exact(1n, 3n),
    };
    expect(toFraction(threshold(thirds))).toBe("1");
    expect(withinThreshold(exact(1n), thirds)).toBe(true);
    expect(withinThreshold(exact(1000001n, 1000000n), thirds)).toBe(false);
  });
});

describe("the round-trip equations", () => {
  it("adds the three legs of T = tau_out + delta_P + tau_return", () => {
    const trip = roundTrip(exact(4n), exact(3n), exact(5n));
    expect(toFraction(trip.total)).toBe("12");
  });

  it("builds the symmetric direct path T = 2D/v + delta_P", () => {
    // Hancke & Kuhn equation (2): t_m = 2 t_p + t_d.
    const trip = symmetricRoundTrip(exact(10n), exact(1n), exact(2n));
    expect(toFraction(trip.tauOut)).toBe("10");
    expect(toFraction(trip.tauReturn)).toBe("10");
    expect(toFraction(trip.total)).toBe("22");
    // Exactly on the boundary for the pinned profile.
    expect(withinThreshold(trip.total, profile)).toBe(true);

    const faster = symmetricRoundTrip(exact(10n), exact(2n), exact(2n));
    expect(toFraction(faster.total)).toBe("12");
  });

  it("recovers the distance it was built from", () => {
    for (const d of [0n, 1n, 7n, 10n, 100n]) {
      const trip = symmetricRoundTrip(exact(d), exact(1n), exact(2n));
      expect(eq(trueDistance(trip.total, exact(1n), exact(2n)), exact(d))).toBe(
        true,
      );
    }
  });
});

describe("the displayed distance bound and when it stops being safe", () => {
  it("computes D_hat = v(T - delta_lb)/2", () => {
    // Hancke & Kuhn equation (1), with the trusted lower bound standing in
    // for the unknown processing delay.
    expect(toFraction(distanceUpperBound(exact(22n), profile))).toBe("10");
    expect(toFraction(distanceUpperBound(exact(12n), profile))).toBe("5");
    expect(toFraction(distanceUpperBound(exact(2n), profile))).toBe("0");
  });

  it("is a true upper bound exactly while the prover cannot beat delta_lb", () => {
    // Honest: the real delay is at or above the trusted floor, so the
    // displayed bound is at or above the real distance.
    for (const realDelay of [exact(2n), exact(3n), exact(10n)]) {
      const trip = symmetricRoundTrip(exact(7n), exact(1n), realDelay);
      const shown = distanceUpperBound(trip.total, profile);
      const actual = trueDistance(trip.total, exact(1n), realDelay);
      expect(shown.n * actual.d >= actual.n * shown.d).toBe(true);
    }
  });

  it("NEGATIVE CONTROL: a prover faster than delta_lb breaks the bound", () => {
    // The executable failure the brief asks for. The verifier credits the
    // prover with delta_lb = 2 time units of processing. The prover actually
    // takes 0, so the verifier subtracts two units that never happened and
    // the displayed bound understates the real distance by exactly v*2/2 = 1.
    const realDelay = exact(0n);
    const realDistance = exact(11n);
    const trip = symmetricRoundTrip(realDistance, exact(1n), realDelay);
    expect(toFraction(trip.total)).toBe("22");

    const shown = distanceUpperBound(trip.total, profile);
    expect(toFraction(shown)).toBe("10");
    expect(toFraction(trueDistance(trip.total, exact(1n), realDelay))).toBe(
      "11",
    );

    // The bound is now BELOW the truth: it is no longer an upper bound.
    expect(shown.n * exact(11n).d < exact(11n).n * shown.d).toBe(true);
    // And the session is accepted even though the prover is outside R = 10.
    expect(withinThreshold(trip.total, profile)).toBe(true);
    // The gain is exactly v(delta_lb - delta_actual)/2.
    expect(toFraction(distanceFraudGain(profile, realDelay))).toBe("1");
  });

  it("reports no gain when the prover takes exactly the trusted floor", () => {
    expect(toFraction(distanceFraudGain(profile, exact(2n)))).toBe("0");
    // A slower prover gives a negative gain: it looks further away, not nearer.
    expect(toFraction(distanceFraudGain(profile, exact(6n)))).toBe("-2");
  });
});

describe("profile validation", () => {
  it("refuses a non-positive speed and negative parameters by name", () => {
    expect(() => assertProfile({ ...profile, v: exact(0n) })).toThrow(
      /v must be > 0/,
    );
    expect(() => assertProfile({ ...profile, v: exact(-1n) })).toThrow(
      /v must be > 0/,
    );
    expect(() => assertProfile({ ...profile, range: exact(-1n) })).toThrow(
      /R must be >= 0/,
    );
    expect(() => assertProfile({ ...profile, deltaLb: exact(-1n) })).toThrow(
      /delta_lb must be >= 0/,
    );
    expect(() => assertProfile(DEFAULT_PROFILE)).not.toThrow();
  });

  it("ships the pinned profile as the lesson default", () => {
    expect(toFraction(DEFAULT_PROFILE.v)).toBe("1");
    expect(toFraction(DEFAULT_PROFILE.range)).toBe("10");
    expect(toFraction(DEFAULT_PROFILE.deltaLb)).toBe("2");
  });
});

describe("no clock reaches a verdict", () => {
  it("never reads a browser or machine clock anywhere in the model", () => {
    // The security claim of a distance-bounding lesson would be worthless if
    // its verdict depended on JavaScript wall-clock jitter. This reads the
    // model's own source rather than trusting the comment that says so.
    const forbidden =
      /\bDate\.now\b|\bperformance\.now\b|\bnew Date\b|\bDate\.parse\b|requestAnimationFrame|setTimeout|setInterval|process\.hrtime/;
    // Comments are stripped first: this file and timing.ts both NAME those
    // APIs in prose to say they are forbidden, and a check that read prose as
    // code would fail on its own documentation while proving nothing about
    // what executes.
    const stripComments = (source: string): string =>
      source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
    const files = readdirSync("src/db").filter(
      (name) => name.endsWith(".ts") && !name.endsWith(".test.ts"),
    );
    expect(files.length).toBeGreaterThan(5);
    let scanned = 0;
    for (const name of files) {
      const code = stripComments(readFileSync(`src/db/${name}`, "utf8"));
      expect(forbidden.test(code), `${name} reads a clock`).toBe(false);
      scanned += 1;
    }
    expect(scanned).toBe(files.length);
    // Positive control: the stripper must not simply blank everything, and the
    // pattern must really fire on code that reads a clock.
    expect(stripComments("const t = Date.now();").includes("Date.now")).toBe(
      true,
    );
    expect(forbidden.test(stripComments("const t = Date.now();"))).toBe(true);
    expect(forbidden.test(stripComments("// Date.now is forbidden"))).toBe(
      false,
    );
  });
});

describe("exact rendering", () => {
  it("shows the exact fraction and a truncated decimal beside it", () => {
    const value: Exact = exact(6561n, 65536n);
    expect(toFraction(value)).toBe("6561/65536");
    expect(toDecimal(value, 6)).toBe("0.100112");
    expect(toDecimal(exact(1n), 0)).toBe("1");
    expect(toDecimal(exact(-3n, 2n), 2)).toBe("-1.50");
    expect(() => toDecimal(value, -1)).toThrow(/non-negative/);
  });

  it("parses both decimal and fractional input exactly", () => {
    expect(toFraction(parseExact("0.25"))).toBe("1/4");
    expect(toFraction(parseExact("3/12"))).toBe("1/4");
    expect(toFraction(parseExact("-2.5"))).toBe("-5/2");
    expect(toFraction(parseExact(" 7 "))).toBe("7");
    expect(() => parseExact("two")).toThrow(/not an exact value/);
    expect(() => parseExact("1/0")).toThrow(/zero denominator/);
  });
});
