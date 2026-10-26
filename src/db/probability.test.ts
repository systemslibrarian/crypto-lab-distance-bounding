import { describe, expect, it } from "vitest";
import {
  type Exact,
  add,
  cmp,
  eq,
  exact,
  ipow,
  mul,
  ONE,
  pow,
  sub,
  toFraction,
  ZERO,
} from "./exact";
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

/**
 * Exhaustive enumeration, written here and sharing no code with the closed
 * forms it checks. Each round of a pre-ask contributes four equally likely
 * elementary outcomes, three of which answer correctly; each blind round
 * contributes two, one of which does.
 */
type Outcome = readonly [weight: bigint, errored: boolean];
function enumerateWeighted(
  perRoundOutcomes: readonly (readonly Outcome[])[],
  tolerated: number,
): Exact {
  let accepted = 0n;
  let total = 0n;
  const walk = (index: number, weight: bigint, errors: number): void => {
    if (index === perRoundOutcomes.length) {
      total += weight;
      if (errors <= tolerated) accepted += weight;
      return;
    }
    for (const [w, errored] of perRoundOutcomes[index]) {
      walk(index + 1, weight * w, errors + (errored ? 1 : 0));
    }
  };
  walk(0, 1n, 0);
  return exact(accepted, total);
}

const preAskRound: readonly Outcome[] = [
  [3n, false],
  [1n, true],
];
const blindRound: readonly Outcome[] = [
  [1n, false],
  [1n, true],
];

describe("required exact fixtures", () => {
  it("reproduces every pinned fixture exactly", () => {
    expect(toFraction(mafiaSuccess(8, 0))).toBe("6561/65536");
    expect(toFraction(mafiaSuccess(8, 1))).toBe("24057/65536");
    expect(toFraction(blindSuccess(8, 1))).toBe("9/256");
    expect(toFraction(partialPreAskSuccess(8, 4, 0))).toBe("81/4096");
    expect(toFraction(distanceFraudSuccess(5, 1))).toBe("3/16");
    expect(toFraction(honestAcceptance(8, 1, exact(1n, 8n)))).toBe(
      "12353145/16777216",
    );
    expect(toFraction(falseRejection(8, 1, exact(1n, 8n)))).toBe(
      "4424071/16777216",
    );
  });

  it("keeps acceptance and false rejection complementary", () => {
    for (const n of [1, 4, 8]) {
      for (let x = 0; x <= n; x += 1) {
        for (const epsilon of [exact(0n), exact(1n, 8n), exact(1n, 3n), ONE]) {
          expect(
            eq(
              add(
                honestAcceptance(n, x, epsilon),
                falseRejection(n, x, epsilon),
              ),
              ONE,
            ),
          ).toBe(true);
        }
      }
    }
  });
});

describe("closed forms against exhaustive enumeration", () => {
  it("matches enumeration for mafia pre-ask through n = 8", () => {
    for (let n = 1; n <= 8; n += 1) {
      for (let x = 0; x <= n; x += 1) {
        const enumerated = enumerateWeighted(
          Array.from({ length: n }, () => preAskRound),
          x,
        );
        expect(
          eq(mafiaSuccess(n, x), enumerated),
          `n=${n} x=${x}: ${toFraction(mafiaSuccess(n, x))} vs ${toFraction(enumerated)}`,
        ).toBe(true);
      }
    }
  });

  it("matches enumeration for a blind responder through n = 8", () => {
    for (let n = 1; n <= 8; n += 1) {
      for (let x = 0; x <= n; x += 1) {
        const enumerated = enumerateWeighted(
          Array.from({ length: n }, () => blindRound),
          x,
        );
        expect(eq(blindSuccess(n, x), enumerated), `n=${n} x=${x}`).toBe(true);
      }
    }
  });

  it("matches enumeration for every partial pre-ask split through n = 8", () => {
    for (let n = 1; n <= 8; n += 1) {
      for (let g = 0; g <= n; g += 1) {
        for (let x = 0; x <= n; x += 1) {
          const enumerated = enumerateWeighted(
            [
              ...Array.from({ length: g }, () => preAskRound),
              ...Array.from({ length: n - g }, () => blindRound),
            ],
            x,
          );
          expect(
            eq(partialPreAskSuccess(n, g, x), enumerated),
            `n=${n} g=${g} x=${x}`,
          ).toBe(true);
        }
      }
    }
  });

  it("recovers the pure cases at the ends of the pre-ask split", () => {
    for (let n = 1; n <= 8; n += 1) {
      for (let x = 0; x <= n; x += 1) {
        expect(eq(partialPreAskSuccess(n, n, x), mafiaSuccess(n, x))).toBe(
          true,
        );
        expect(eq(partialPreAskSuccess(n, 0, x), blindSuccess(n, x))).toBe(
          true,
        );
      }
    }
  });

  it("matches enumeration for realized distance fraud through h = 8", () => {
    for (let h = 0; h <= 8; h += 1) {
      for (let x = 0; x <= h; x += 1) {
        const enumerated = enumerateWeighted(
          Array.from({ length: h }, () => blindRound),
          x,
        );
        expect(
          eq(distanceFraudSuccess(h, x), enumerated),
          `h=${h} x=${x}`,
        ).toBe(true);
      }
    }
  });

  it("matches an independently summed honest-noise enumeration", () => {
    // Sum over every error subset rather than using the binomial closed form.
    for (const epsilon of [exact(1n, 8n), exact(1n, 3n), exact(3n, 7n)]) {
      for (let n = 1; n <= 8; n += 1) {
        const keep = sub(ONE, epsilon);
        for (let x = 0; x <= n; x += 1) {
          let accepted: Exact = ZERO;
          for (let mask = 0; mask < 1 << n; mask += 1) {
            let errors = 0;
            for (let b = 0; b < n; b += 1) if (mask & (1 << b)) errors += 1;
            if (errors > x) continue;
            accepted = add(
              accepted,
              mul(pow(epsilon, errors), pow(keep, n - errors)),
            );
          }
          expect(
            eq(honestAcceptance(n, x, epsilon), accepted),
            `n=${n} x=${x} eps=${toFraction(epsilon)}`,
          ).toBe(true);
        }
      }
    }
  });

  it("agrees with the paper's k-parameterised false-accept sum", () => {
    // Hancke & Kuhn §3.4: p_FA = sum_{i=k..n} C(n,i)(3/4)^i(1/4)^(n-i), k = n-x.
    const binom = (n: number, k: number): bigint => {
      if (k < 0 || k > n) return 0n;
      let r = 1n;
      for (let i = 0n; i < BigInt(Math.min(k, n - k)); i += 1n) {
        r = (r * (BigInt(n) - i)) / (i + 1n);
      }
      return r;
    };
    for (let n = 1; n <= 8; n += 1) {
      for (let x = 0; x <= n; x += 1) {
        const k = n - x;
        let numerator = 0n;
        for (let i = k; i <= n; i += 1) {
          numerator += binom(n, i) * ipow(3n, i);
        }
        expect(eq(mafiaSuccess(n, x), exact(numerator, ipow(4n, n)))).toBe(
          true,
        );
      }
    }
  });
});

describe("monotonicity and boundary behaviour", () => {
  it("makes tolerated errors monotonically increase every attacker's success", () => {
    for (let n = 1; n <= 8; n += 1) {
      for (let x = 0; x < n; x += 1) {
        expect(cmp(mafiaSuccess(n, x + 1), mafiaSuccess(n, x))).toBe(1);
        expect(cmp(blindSuccess(n, x + 1), blindSuccess(n, x))).toBe(1);
        expect(
          cmp(
            partialPreAskSuccess(n, Math.floor(n / 2), x + 1),
            partialPreAskSuccess(n, Math.floor(n / 2), x),
          ),
        ).toBe(1);
      }
      for (let x = 0; x < n; x += 1) {
        expect(
          cmp(distanceFraudSuccess(n, x + 1), distanceFraudSuccess(n, x)),
        ).toBe(1);
      }
    }
  });

  it("ranks a pre-asking attacker above a blind one at equal tolerance", () => {
    for (let n = 1; n <= 8; n += 1) {
      for (let x = 0; x < n; x += 1) {
        expect(cmp(mafiaSuccess(n, x), blindSuccess(n, x))).toBe(1);
      }
    }
  });

  it("is certain when every round may be wrong, and (3/4)^n when none may", () => {
    for (let n = 1; n <= 8; n += 1) {
      expect(eq(mafiaSuccess(n, n), ONE)).toBe(true);
      expect(eq(blindSuccess(n, n), ONE)).toBe(true);
      expect(eq(mafiaSuccess(n, 0), exact(ipow(3n, n), ipow(4n, n)))).toBe(
        true,
      );
      expect(eq(blindSuccess(n, 0), exact(1n, ipow(2n, n)))).toBe(true);
    }
  });

  it("makes a zero realized register distance a certain distance fraud", () => {
    // h = 0: R0 and R1 agree everywhere, so answering before the challenge is
    // always right and no tolerance is needed.
    expect(eq(distanceFraudSuccess(0, 0), ONE)).toBe(true);
    for (let x = 0; x <= 4; x += 1) {
      expect(eq(distanceFraudSuccess(0, x), ONE)).toBe(true);
    }
  });

  it("shows the realized table can be far weaker than the ensemble average", () => {
    const n = 8;
    const x = 1;
    const ensemble = distanceFraudEnsemble(n, x);
    const weak = distanceFraudSuccess(2, x);
    const typical = distanceFraudSuccess(4, x);
    expect(cmp(weak, ensemble)).toBe(1);
    expect(cmp(weak, typical)).toBe(1);
    // The average is a weighted mean of the realized values, so it must sit
    // between the extremes rather than above or below both.
    expect(cmp(ensemble, distanceFraudSuccess(n, x))).toBe(1);
    expect(cmp(distanceFraudSuccess(0, x), ensemble)).toBe(1);
  });

  it("computes the ensemble average as the binomial mixture it claims to be", () => {
    for (let n = 0; n <= 8; n += 1) {
      for (let x = 0; x <= n; x += 1) {
        let total: Exact = ZERO;
        for (let h = 0; h <= n; h += 1) {
          const binom = (() => {
            let r = 1n;
            for (let i = 0n; i < BigInt(Math.min(h, n - h)); i += 1n) {
              r = (r * (BigInt(n) - i)) / (i + 1n);
            }
            return r;
          })();
          total = add(
            total,
            mul(exact(binom, ipow(2n, n)), distanceFraudSuccess(h, x)),
          );
        }
        expect(eq(distanceFraudEnsemble(n, x), total), `n=${n} x=${x}`).toBe(
          true,
        );
      }
    }
  });
});

describe("repeated attempts", () => {
  it("compounds independent fresh-nonce attempts exactly", () => {
    const p = mafiaSuccess(4, 0);
    expect(eq(repeatedAttempts(p, 0, true), ZERO)).toBe(true);
    expect(eq(repeatedAttempts(p, 1, true), p)).toBe(true);
    expect(
      eq(repeatedAttempts(p, 3, true), sub(ONE, pow(sub(ONE, p), 3))),
    ).toBe(true);
  });

  it("refuses to treat reused-nonce attempts as independent", () => {
    expect(() => repeatedAttempts(mafiaSuccess(4, 0), 3, false)).toThrow(
      /not independent/,
    );
  });

  it("rejects out-of-range inputs rather than ranking them", () => {
    expect(() => repeatedAttempts(exact(3n, 2n), 2, true)).toThrow(/\[0, 1\]/);
    expect(() => repeatedAttempts(exact(-1n, 2n), 2, true)).toThrow(/\[0, 1\]/);
    expect(() => repeatedAttempts(mafiaSuccess(4, 0), -1, true)).toThrow(
      /non-negative/,
    );
    expect(() => mafiaSuccess(-1, 0)).toThrow(/non-negative/);
    expect(() => mafiaSuccess(4, -1)).toThrow(/non-negative/);
    expect(() => partialPreAskSuccess(4, 5, 0)).toThrow(/0\.\.n/);
    expect(() => distanceFraudSuccess(-1, 0)).toThrow(/non-negative/);
    expect(() => falseRejection(4, 0, exact(3n, 2n))).toThrow(/\[0, 1\]/);
  });
});
