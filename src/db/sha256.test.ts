/// <reference types="node" />
import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  concatBytes,
  fromHex,
  hmacSha256,
  sha256,
  toHex,
  utf8,
} from "./sha256";

describe("SHA-256", () => {
  it("matches the published FIPS 180-4 one-block and two-block examples", () => {
    // FIPS 180-4, Appendix B.1 and B.2.
    expect(toHex(sha256(utf8("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(
      toHex(
        sha256(
          utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        ),
      ),
    ).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    // The empty string, the padding edge every hand-rolled SHA-256 gets wrong first.
    expect(toHex(sha256(new Uint8Array(0)))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("agrees with an independent implementation across every padding boundary", () => {
    // 0..200 bytes crosses the 55/56/64 and 119/120/128 padding boundaries,
    // where a length field that spills into the next block is mishandled.
    for (let length = 0; length <= 200; length += 1) {
      const message = new Uint8Array(length);
      for (let i = 0; i < length; i += 1) message[i] = (i * 31 + 7) & 0xff;
      const reference = createHash("sha256").update(message).digest("hex");
      expect(toHex(sha256(message)), `length ${length}`).toBe(reference);
    }
  });

  it("rejects malformed hex rather than decoding it loosely", () => {
    expect(() => fromHex("abc")).toThrow(/even-length/);
    expect(() => fromHex("zz")).toThrow(/even-length/);
    expect(toHex(fromHex("00ff10"))).toBe("00ff10");
  });

  it("concatenates byte strings in order", () => {
    expect(
      toHex(concatBytes(fromHex("0102"), fromHex("03"), fromHex(""))),
    ).toBe("010203");
    expect(concatBytes().length).toBe(0);
  });
});

describe("HMAC-SHA-256", () => {
  it("matches the published RFC 4231 test vectors", () => {
    // RFC 4231 §4.2 Test Case 1.
    expect(toHex(hmacSha256(fromHex("0b".repeat(20)), utf8("Hi There")))).toBe(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    );
    // §4.3 Test Case 2.
    expect(
      toHex(hmacSha256(utf8("Jefe"), utf8("what do ya want for nothing?"))),
    ).toBe("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    // §4.4 Test Case 3.
    expect(
      toHex(hmacSha256(fromHex("aa".repeat(20)), fromHex("dd".repeat(50)))),
    ).toBe("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    // §4.6 Test Case 5, a truncated-output case used here at full width.
    expect(
      toHex(
        hmacSha256(fromHex("0c".repeat(20)), utf8("Test With Truncation")),
      ).slice(0, 32),
    ).toBe("a3b6167473100ee06e0c796c2955552b");
    // §4.7 Test Case 6: a key longer than the 64-byte block, which must be hashed first.
    expect(
      toHex(
        hmacSha256(
          fromHex("aa".repeat(131)),
          utf8("Test Using Larger Than Block-Size Key - Hash Key First"),
        ),
      ),
    ).toBe("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
  });

  it("agrees with an independent implementation over key and message lengths", () => {
    for (const keyLength of [0, 1, 32, 63, 64, 65, 200]) {
      for (const messageLength of [0, 1, 55, 64, 119, 200]) {
        const key = new Uint8Array(keyLength).map(
          (_, i) => (i * 17 + 3) & 0xff,
        );
        const message = new Uint8Array(messageLength).map(
          (_, i) => (i * 29 + 11) & 0xff,
        );
        const reference = createHmac("sha256", key)
          .update(message)
          .digest("hex");
        expect(
          toHex(hmacSha256(key, message)),
          `key ${keyLength} message ${messageLength}`,
        ).toBe(reference);
      }
    }
  });
});
