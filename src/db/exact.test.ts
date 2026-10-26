import { describe, expect, it } from "vitest";
import {
  ONE,
  ZERO,
  add,
  binomial,
  cmp,
  div,
  eq,
  exact,
  fromInt,
  gt,
  gte,
  ipow,
  isNonNegative,
  isPositive,
  lt,
  lte,
  mul,
  pow,
  sub,
  toFraction,
} from "./exact";
import { deriveRegisters, registerDistance } from "./prf";
import { sessionRegisters } from "./protocol";
import { honestAnswer } from "./attacks";
import { fromHex } from "./sha256";
import { symmetricRoundTrip } from "./timing";

describe("exact rational arithmetic", () => {
  it("reduces, normalises sign and refuses a zero denominator", () => {
    expect(toFraction(exact(2n, 4n))).toBe("1/2");
    expect(toFraction(exact(-2n, 4n))).toBe("-1/2");
    // A negative denominator normalises onto the numerator.
    expect(toFraction(exact(1n, -2n))).toBe("-1/2");
    expect(toFraction(exact(0n, 5n))).toBe("0");
    expect(() => exact(1n, 0n)).toThrow(/zero denominator/);
  });

  it("adds, subtracts, multiplies and divides exactly", () => {
    const third = exact(1n, 3n);
    const sixth = exact(1n, 6n);
    expect(toFraction(add(third, sixth))).toBe("1/2");
    expect(toFraction(sub(third, sixth))).toBe("1/6");
    expect(toFraction(mul(third, sixth))).toBe("1/18");
    expect(toFraction(div(third, sixth))).toBe("2");
    expect(() => div(ONE, ZERO)).toThrow(/division by zero/);
    // A tenth plus two tenths is exactly three tenths, which a float denies.
    expect(eq(add(exact(1n, 10n), exact(2n, 10n)), exact(3n, 10n))).toBe(true);
  });

  it("orders values without widening to a float", () => {
    const a = exact(1n, 3n);
    const b = exact(1n, 2n);
    expect(cmp(a, b)).toBe(-1);
    expect(cmp(b, a)).toBe(1);
    expect(cmp(a, exact(2n, 6n))).toBe(0);
    expect(lt(a, b)).toBe(true);
    expect(lte(a, exact(2n, 6n))).toBe(true);
    expect(gt(b, a)).toBe(true);
    expect(gte(b, b)).toBe(true);
    expect(eq(a, b)).toBe(false);
    expect(isPositive(a)).toBe(true);
    expect(isPositive(ZERO)).toBe(false);
    expect(isNonNegative(ZERO)).toBe(true);
    expect(isNonNegative(exact(-1n))).toBe(false);
  });

  it("builds from integers and refuses non-integers", () => {
    expect(toFraction(fromInt(7))).toBe("7");
    expect(toFraction(fromInt(-7n))).toBe("-7");
    expect(toFraction(fromInt(0))).toBe("0");
    expect(() => fromInt(1.5)).toThrow(/not an integer/);
  });

  it("raises to non-negative integer powers only", () => {
    expect(toFraction(pow(exact(2n, 3n), 3))).toBe("8/27");
    expect(toFraction(pow(exact(5n), 0))).toBe("1");
    expect(ipow(3n, 4)).toBe(81n);
    expect(ipow(3n, 0)).toBe(1n);
    expect(() => pow(ONE, -1)).toThrow(/non-negative integer/);
    expect(() => pow(ONE, 1.5)).toThrow(/non-negative integer/);
    expect(() => ipow(2n, -1)).toThrow(/non-negative integer/);
  });

  it("computes exact binomial coefficients and refuses nonsense", () => {
    expect(binomial(8, 0)).toBe(1n);
    expect(binomial(8, 1)).toBe(8n);
    expect(binomial(8, 4)).toBe(70n);
    expect(binomial(8, 8)).toBe(1n);
    expect(binomial(8, 9)).toBe(0n);
    expect(binomial(8, -1)).toBe(0n);
    // Large enough that a float factorial would have lost precision.
    expect(binomial(60, 30)).toBe(118264581564861424n);
    expect(() => binomial(-1, 0)).toThrow(/non-negative integer/);
    expect(() => binomial(1.5, 0)).toThrow(/non-negative integer/);
  });
});

describe("remaining model entry points", () => {
  it("derives session registers through the protocol's own entry point", () => {
    const key = fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    const nonce = fromHex("0102030405060708");
    const viaProtocol = sessionRegisters(key, nonce, 8);
    expect(viaProtocol).toEqual(deriveRegisters(key, nonce, 8));
    expect(registerDistance(viaProtocol)).toBeGreaterThanOrEqual(0);
  });

  it("answers honestly at the modeled distance and delay", () => {
    const key = fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    const registers = deriveRegisters(key, fromHex("0102030405060708"), 4);
    const v = exact(1n);
    const model = { distance: exact(4n), processingDelay: exact(3n) };
    for (let round = 1; round <= 4; round += 1) {
      for (const c of [0, 1] as const) {
        const answer = honestAnswer(registers, round, c, model, v);
        expect(answer.bit).toBe(
          c === 0 ? registers.r0[round - 1] : registers.r1[round - 1],
        );
        expect(toFraction(answer.trip.total)).toBe(
          toFraction(
            symmetricRoundTrip(model.distance, v, model.processingDelay).total,
          ),
        );
      }
    }
  });
});
