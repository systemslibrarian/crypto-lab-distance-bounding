/**
 * The declared instantiation of the Hancke-Kuhn shared secret function h.
 *
 * Hancke & Kuhn 2005 §3.1, p. 69 writes only:
 *
 *     R⁰₁R⁰₂R⁰₃…R⁰ₙ ‖ R¹₁R¹₂R¹₃…R¹ₙ := h(K, N_V)
 *
 * and §3.2, p. 70 says h "may in a typical implementation be some form of
 * secure (i.e. one-way and collision-resistant) hash function", that the
 * lengths of K, N_V and n are security parameters, and that for larger n the
 * registers "can be generated using a secure pseudo random-bit generator
 * seeded from the output of h".
 *
 * THE PAPER MANDATES NEITHER SHA-256 NOR ANY WIRE FORMAT. What follows is one
 * declared instantiation chosen for this lesson, and the UI says so in those
 * words. It is:
 *
 *     seed      = HMAC-SHA-256(K, DOMAIN ‖ len(N_V) ‖ N_V ‖ len16(n))
 *     block_j   = HMAC-SHA-256(seed, DOMAIN_EXPAND ‖ be32(j))
 *     R0 ‖ R1   = first 2n bits of block_0 ‖ block_1 ‖ …
 *
 * Bit order is declared: bits are taken most significant first within each
 * byte, the first n bits are R0 and the next n are R1.
 *
 * The length prefixes exist so that two different (K, N_V) pairs cannot be
 * concatenated into the same input. Without them a nonce ending in a byte that
 * another nonce begins with could collide, which would hand an attacker a
 * second session with the same response table and is exactly the reuse the
 * lesson spends an experiment on.
 */
import { concatBytes, hmacSha256, utf8 } from "./sha256";

const DOMAIN = utf8("crypto-lab-distance-bounding/hancke-kuhn/registers/v1");
const DOMAIN_EXPAND = utf8(
  "crypto-lab-distance-bounding/hancke-kuhn/expand/v1",
);

/** The largest n this lesson will build registers for. */
export const MAX_ROUNDS = 64;

export type Bit = 0 | 1;

export interface Registers {
  /** R0, indexed from round 1 at position 0. */
  readonly r0: readonly Bit[];
  /** R1, indexed from round 1 at position 0. */
  readonly r1: readonly Bit[];
}

function be32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

function bitsFrom(bytes: Uint8Array, count: number): Bit[] {
  const out: Bit[] = [];
  for (let i = 0; i < count; i += 1) {
    const byte = bytes[i >> 3];
    out.push(((byte >> (7 - (i & 7))) & 1) as Bit satisfies Bit);
  }
  return out;
}

export function assertRounds(n: number): void {
  if (!Number.isInteger(n) || n < 1 || n > MAX_ROUNDS) {
    throw new RangeError(`rounds n must be an integer in 1..${MAX_ROUNDS}`);
  }
}

/**
 * R0 ‖ R1 := h(K, N_V), in the instantiation declared above.
 *
 * Both the verifier and the honest prover call this with the same arguments
 * and obtain the same registers; that is the whole of the shared secret in
 * this protocol. The attacker never calls it, which is enforced structurally
 * and checked by a source-reading test.
 */
export function deriveRegisters(
  key: Uint8Array,
  nonce: Uint8Array,
  n: number,
): Registers {
  assertRounds(n);
  const seed = hmacSha256(
    key,
    concatBytes(DOMAIN, be32(nonce.length), nonce, be32(n)),
  );
  const needed = 2 * n;
  const blocks: Uint8Array[] = [];
  for (let j = 0; blocks.length * 32 * 8 < needed; j += 1) {
    blocks.push(hmacSha256(seed, concatBytes(DOMAIN_EXPAND, be32(j))));
  }
  const stream = bitsFrom(concatBytes(...blocks), needed);
  return { r0: stream.slice(0, n), r1: stream.slice(n) };
}

/** The response an honest prover returns for challenge c in round i (1-based). */
export function response(registers: Registers, round: number, c: Bit): Bit {
  const index = round - 1;
  if (index < 0 || index >= registers.r0.length) {
    throw new RangeError(`round ${round} is outside the register length`);
  }
  return c === 0 ? registers.r0[index] : registers.r1[index];
}

/**
 * Hamming distance between R0 and R1.
 *
 * This is the realized quantity distance fraud actually depends on: in a round
 * where R0ᵢ = R1ᵢ, a dishonest prover that answers before seeing Cᵢ is right
 * whatever the challenge turns out to be. Only the h positions where the two
 * registers differ are a coin flip for it.
 */
export function registerDistance(registers: Registers): number {
  let distance = 0;
  for (let i = 0; i < registers.r0.length; i += 1) {
    if (registers.r0[i] !== registers.r1[i]) distance += 1;
  }
  return distance;
}

/**
 * A deterministic bit source, so every scenario replays exactly.
 *
 * This stands in for the verifier's unpredictable challenge generator and for
 * nonce generation. It is NOT a security claim: a real verifier needs a real
 * entropy source, and the lesson says so. What it buys here is that a learner
 * and a test see the same session from the same seed.
 */
export class BitSource {
  #block: Uint8Array;
  #offset = 0;
  #counter = 0;
  readonly #seed: Uint8Array;

  constructor(seed: string | Uint8Array) {
    this.#seed = typeof seed === "string" ? utf8(seed) : seed;
    this.#block = hmacSha256(this.#seed, be32(this.#counter));
  }

  nextBit(): Bit {
    if (this.#offset >= this.#block.length * 8) {
      this.#counter += 1;
      this.#block = hmacSha256(this.#seed, be32(this.#counter));
      this.#offset = 0;
    }
    const byte = this.#block[this.#offset >> 3];
    const bit = ((byte >> (7 - (this.#offset & 7))) & 1) as Bit;
    this.#offset += 1;
    return bit;
  }

  nextBits(count: number): Bit[] {
    if (!Number.isInteger(count) || count < 0) {
      throw new RangeError("nextBits: count must be a non-negative integer");
    }
    return Array.from({ length: count }, () => this.nextBit());
  }

  nextBytes(count: number): Uint8Array {
    if (!Number.isInteger(count) || count < 0) {
      throw new RangeError("nextBytes: count must be a non-negative integer");
    }
    const out = new Uint8Array(count);
    for (let i = 0; i < count; i += 1) {
      let byte = 0;
      for (let b = 0; b < 8; b += 1) byte = (byte << 1) | this.nextBit();
      out[i] = byte;
    }
    return out;
  }
}
