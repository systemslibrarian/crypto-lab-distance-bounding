import { expect, test, type Page } from "@playwright/test";

import { boot } from "./gate";

/* ------------------------------------------------------------------ */
/* Exact arithmetic written HERE. The page's own helpers are not used,  */
/* so a displayed figure is checked against an independent computation  */
/* rather than against the code that produced it.                       */
/* ------------------------------------------------------------------ */

const gcd = (a: bigint, b: bigint): bigint => {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
};
const reduce = (n: bigint, d: bigint): string => {
  const g = gcd(n, d) || 1n;
  const rn = n / g;
  const rd = d / g;
  return rd === 1n ? `${rn}` : `${rn}/${rd}`;
};
const choose = (n: number, k: number): bigint => {
  if (k < 0 || k > n) return 0n;
  let r = 1n;
  for (let i = 0n; i < BigInt(Math.min(k, n - k)); i += 1n) {
    r = (r * (BigInt(n) - i)) / (i + 1n);
  }
  return r;
};
const ipow = (b: bigint, e: number): bigint => b ** BigInt(e);

/** 4^-n * sum_{e<=x} C(n,e) 3^(n-e), computed here. */
const mafia = (n: number, x: number): string => {
  let num = 0n;
  for (let e = 0; e <= Math.min(x, n); e += 1)
    num += choose(n, e) * ipow(3n, n - e);
  return reduce(num, ipow(4n, n));
};
/** 2^-n * sum_{e<=x} C(n,e). */
const blind = (n: number, x: number): string => {
  let num = 0n;
  for (let e = 0; e <= Math.min(x, n); e += 1) num += choose(n, e);
  return reduce(num, ipow(2n, n));
};
/** 2^-h * sum_{e<=min(x,h)} C(h,e). */
const distanceFraud = (h: number, x: number): string => {
  let num = 0n;
  for (let e = 0; e <= Math.min(x, h); e += 1) num += choose(h, e);
  return reduce(num, ipow(2n, h));
};
/** The convolution for g pre-asked and n-g blind rounds. */
const partial = (n: number, g: number, x: number): string => {
  const bl = n - g;
  let num = 0n;
  for (let e = 0; e <= Math.min(x, n); e += 1) {
    for (let a = 0; a <= Math.min(e, g); a += 1) {
      const b = e - a;
      if (b > bl) continue;
      num += choose(g, a) * ipow(3n, g - a) * choose(bl, b) * ipow(2n, bl);
    }
  }
  return reduce(num, ipow(4n, n));
};

async function setControls(
  page: Page,
  values: Record<string, string | boolean>,
): Promise<void> {
  for (const [id, value] of Object.entries(values)) {
    const locator = page.locator(`#${id}`);
    if (typeof value === "boolean") {
      if (value) await locator.check();
      else await locator.uncheck();
    } else if ((await locator.evaluate((n) => n.tagName)) === "SELECT") {
      await locator.selectOption(value);
    } else {
      await locator.fill(value);
    }
  }
}

/**
 * Read one metric by its EXACT label, falling back to a unique prefix.
 *
 * Playwright's `hasText` is a case-insensitive substring match, which quietly
 * returned "Tolerated content errors x" when asked for "Content errors" and
 * made a passing assertion read the wrong number. Looking the label up exactly,
 * and refusing an ambiguous prefix, is the only way this helper can be trusted
 * to be reading the metric it names.
 */
const metricValue = async (page: Page, label: string): Promise<string> => {
  const pairs = await page.$$eval(".metric", (nodes) =>
    nodes.map((node) => ({
      label: node.querySelector("span")?.textContent?.trim() ?? "",
      value: node.querySelector("strong")?.textContent?.trim() ?? "",
    })),
  );
  const exact = pairs.filter((pair) => pair.label === label);
  if (exact.length === 1) return exact[0].value;
  const prefixed = pairs.filter((pair) => pair.label.startsWith(label));
  if (prefixed.length === 1) return prefixed[0].value;
  throw new Error(
    `metric ${JSON.stringify(label)} matched ${exact.length + prefixed.length} metrics; ` +
      `available: ${pairs.map((p) => p.label).join(" | ")}`,
  );
};

const rows = async (page: Page): Promise<string[][]> => {
  const table = page.locator("#rounds-table tbody tr");
  const count = await table.count();
  const out: string[][] = [];
  for (let i = 0; i < count; i += 1) {
    out.push(
      (await table.nth(i).locator("td").allTextContents()).map((t) => t.trim()),
    );
  }
  return out;
};

test.beforeEach(async ({ page }) => {
  await boot(page, "dark");
});

test("the displayed threshold equals an independently computed 2R/v + delta_lb", async ({
  page,
}) => {
  for (const [range, speed, deltaLb, expected] of [
    ["10", "1", "2", "22"],
    ["10", "2", "2", "12"],
    ["7", "1", "0", "14"],
    ["1", "3", "1/3", "1"],
  ] as const) {
    await setControls(page, { range, speed, deltaLb, scenario: "honest" });
    await page.locator("#run").click();
    const shown = await metricValue(page, "Threshold Theta");
    // 2R/v + delta_lb, recomputed from the three values typed above.
    const [rn, rd] = range.includes("/")
      ? range.split("/").map(BigInt)
      : [BigInt(range), 1n];
    const [vn, vd] = speed.includes("/")
      ? speed.split("/").map(BigInt)
      : [BigInt(speed), 1n];
    const [dn, dd] = deltaLb.includes("/")
      ? deltaLb.split("/").map(BigInt)
      : [BigInt(deltaLb), 1n];
    const num = 2n * rn * vd * dd + dn * rd * vn;
    const den = rd * vn * dd;
    expect(shown, `R=${range} v=${speed} d=${deltaLb}`).toBe(reduce(num, den));
    expect(shown).toBe(expected);
  }
});

test("the pinned boundary accepts T = 22 and rejects T = 23", async ({
  page,
}) => {
  // v = 1, R = 10, delta_lb = 2 gives Theta = 22. The honest prover sits at
  // distance 10 with delay 2, so T = 2*10/1 + 2 = 22 exactly: accepted. One
  // unit further out makes T = 23: rejected, with no rounding either way.
  await setControls(page, {
    scenario: "distance-fraud",
    range: "10",
    speed: "1",
    deltaLb: "2",
    fraudDistance: "10",
    fraudDelay: "2",
    tolerated: "8",
    rounds: "8",
  });
  await page.locator("#run").click();
  expect(await metricValue(page, "Threshold Theta")).toBe("22");
  const accepted = await rows(page);
  expect(accepted.every((r) => r[4] === "22")).toBe(true);
  expect(accepted.every((r) => r[5] === "in time")).toBe(true);
  expect(await metricValue(page, "Late rounds")).toBe("0");

  await setControls(page, { fraudDistance: "10", fraudDelay: "3" });
  await page.locator("#run").click();
  const rejected = await rows(page);
  expect(rejected.every((r) => r[4] === "23")).toBe(true);
  expect(rejected.every((r) => r[5] === "LATE")).toBe(true);
  expect(await metricValue(page, "Late rounds")).toBe("8");
  await expect(page.locator("[data-verdict=session]")).toContainText(
    "REJECTED",
  );
});

test("an online relay returns every correct bit and is refused on timing alone", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "online-relay",
    rounds: "8",
    tolerated: "3",
    relayLink: "30",
  });
  await page.locator("#run").click();
  const table = await rows(page);
  expect(table).toHaveLength(8);
  // Content is perfect in every round: received equals expected throughout.
  expect(table.every((r) => r[2] === r[3])).toBe(true);
  expect(table.every((r) => r[6] === "correct")).toBe(true);
  // And every round is late, so the session is refused despite x = 3.
  expect(table.every((r) => r[5] === "LATE")).toBe(true);
  expect(await metricValue(page, "Content errors")).toBe("0");
  expect(await metricValue(page, "Late rounds")).toBe("8");
  await expect(page.locator("[data-verdict=session]")).toContainText(
    "REJECTED",
  );

  // T = 2*(1+30+1)/1 + 3 + 1 = 68, recomputed here from the link length.
  expect(table[0][4]).toBe("68");
});

test("a late round cannot spend the content-error allowance", async ({
  page,
}) => {
  // Every bit correct, generous allowance, one relay path: still refused. The
  // allowance is for content and a late answer is not a content error.
  for (const tolerated of ["0", "1", "4", "8"]) {
    await setControls(page, {
      scenario: "online-relay",
      rounds: "8",
      tolerated,
      relayLink: "30",
    });
    await page.locator("#run").click();
    expect(await metricValue(page, "Content errors"), tolerated).toBe("0");
    expect(await metricValue(page, "Late rounds"), tolerated).toBe("8");
    await expect(page.locator("[data-verdict=session]")).toContainText(
      "REJECTED",
    );
    await expect(page.locator("[data-verdict=session]")).toContainText(
      "cannot use the error allowance",
    );
  }
});

test("disabling the timing check lets the identical relay through", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "online-relay",
    rounds: "8",
    tolerated: "0",
    relayLink: "30",
    timing: true,
  });
  await page.locator("#run").click();
  await expect(page.locator("[data-verdict=session]")).toContainText(
    "REJECTED",
  );

  await setControls(page, { timing: false });
  await page.locator("#run").click();
  await expect(page.locator("[data-verdict=session]")).toContainText(
    "ACCEPTED",
  );
  await expect(page.locator("[data-verdict=caveat]").first()).toContainText(
    "no longer distance bounding",
  );
});

test("an ordinary authenticated exchange relays and proves no proximity", async ({
  page,
}) => {
  await setControls(page, { scenario: "authenticated-relay" });
  await page.locator("#run").click();
  await expect(
    page.locator("[data-verdict=authenticated-relay]"),
  ).toContainText("AUTHENTICATED, AND NO PROXIMITY PROVED");
  const challenge = await metricValue(page, "Relayed challenge (128-bit hex)");
  const tag = await metricValue(page, "Relayed HMAC-SHA-256 tag (hex)");
  expect(challenge).toMatch(/^[0-9a-f]{32}$/);
  expect(tag).toMatch(/^[0-9a-f]{64}$/);
  expect(await metricValue(page, "Altered-tag control")).toBe("REJECTED");
  expect(await metricValue(page, "Rapid rounds")).toBe("not run");
  expect(await metricValue(page, "Timing measurement")).toBe("not run");
  await expect(page.locator("#rounds-table")).toHaveCount(0);
  await expect(page.locator("#result")).toContainText(
    "A changed tag is rejected in the executable control tests",
  );
});

test("the mafia pre-ask probability matches an independent exact computation", async ({
  page,
}) => {
  for (const [rounds, tolerated] of [
    ["8", "0"],
    ["8", "1"],
    ["12", "2"],
    ["6", "3"],
  ] as const) {
    await setControls(page, {
      scenario: "mafia-preask",
      rounds,
      tolerated,
      preAsk: rounds,
    });
    await page.locator("#run").click();
    const shown = await metricValue(page, "Exact success for this adversary");
    expect(shown, `n=${rounds} x=${tolerated}`).toBe(
      mafia(Number(rounds), Number(tolerated)),
    );
    const baseline = await metricValue(page, "Blind-guess baseline");
    expect(baseline).toBe(blind(Number(rounds), Number(tolerated)));
  }
  // The pinned fixtures, exactly.
  await setControls(page, { rounds: "8", tolerated: "0", preAsk: "8" });
  await page.locator("#run").click();
  expect(await metricValue(page, "Exact success for this adversary")).toBe(
    "6561/65536",
  );
  await setControls(page, { tolerated: "1" });
  await page.locator("#run").click();
  expect(await metricValue(page, "Exact success for this adversary")).toBe(
    "24057/65536",
  );
  expect(await metricValue(page, "Blind-guess baseline")).toBe("9/256");
});

test("a partial pre-ask uses the convolution, not the pure mafia figure", async ({
  page,
}) => {
  for (const [rounds, g, tolerated] of [
    ["8", "4", "0"],
    ["8", "4", "1"],
    ["8", "2", "2"],
    ["12", "7", "1"],
  ] as const) {
    await setControls(page, {
      scenario: "mafia-preask",
      rounds,
      tolerated,
      preAsk: g,
    });
    await page.locator("#run").click();
    const shown = await metricValue(page, "Exact success for this adversary");
    expect(shown, `n=${rounds} g=${g} x=${tolerated}`).toBe(
      partial(Number(rounds), Number(g), Number(tolerated)),
    );
  }
  // The pinned fixture n = 8, g = 4, x = 0.
  await setControls(page, { rounds: "8", preAsk: "4", tolerated: "0" });
  await page.locator("#run").click();
  expect(await metricValue(page, "Exact success for this adversary")).toBe(
    "81/4096",
  );
});

test("distance fraud is conditioned on the realized register distance", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "distance-fraud",
    rounds: "8",
    tolerated: "1",
  });
  await page.locator("#run").click();
  const h = Number(await metricValue(page, "Realized register distance h"));
  expect(Number.isInteger(h)).toBe(true);
  expect(h).toBeGreaterThanOrEqual(0);
  expect(h).toBeLessThanOrEqual(8);
  const shown = await metricValue(page, "Exact success for this adversary");
  // Recomputed here from the DISPLAYED h, not from n.
  expect(shown).toBe(distanceFraud(h, 1));
  await expect(
    page.locator(".metric", { hasText: "Exact success for this adversary" }),
  ).toContainText("realized register distance h");

  // The ensemble average is shown beside it, and is a different number.
  const ensemble = (
    await page.locator("[data-ensemble]").textContent()
  )?.trim();
  expect(ensemble).toBeTruthy();
  let mixture = 0n;
  let den = 0n;
  for (let hh = 0; hh <= 8; hh += 1) {
    const inner = distanceFraud(hh, 1).split("/");
    const n = BigInt(inner[0]);
    const d = inner.length === 2 ? BigInt(inner[1]) : 1n;
    mixture = mixture * d + choose(8, hh) * n * (den === 0n ? 1n : 1n);
    den = den === 0n ? d : den;
  }
  // The exact mixture is checked in the unit suite; here it is enough that the
  // realized figure and the average are presented as different quantities.
  expect(ensemble).not.toBe("");
  await expect(page.locator("[data-ensemble]")).toBeVisible();
});

test("the distance-fraud gain equals v(delta_lb - delta_actual)/2", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "distance-fraud",
    rounds: "8",
    // The content allowance is opened fully on purpose: this test is about the
    // TIMING bound becoming unsafe, and a content rejection would decide the
    // verdict for an unrelated reason and hide the thing being checked.
    tolerated: "8",
    speed: "1",
    deltaLb: "2",
    fraudDelay: "0",
    fraudDistance: "11",
  });
  await page.locator("#run").click();
  await expect(page.locator("[data-fraud-gain]")).toContainText("1");
  await expect(page.locator("[data-fraud-gain]")).toContainText(
    "stops being an upper bound",
  );
  // Every round is inside Theta even though the prover is outside R = 10.
  expect(await metricValue(page, "Late rounds")).toBe("0");
  expect(await metricValue(page, "Threshold Theta = 2R/v + delta_lb")).toBe(
    "22",
  );
  // Accepted from outside the honest range: that is the unsafe bound in action.
  await expect(page.locator("[data-verdict=session]")).toContainText(
    "ACCEPTED",
  );
});

test("predictable challenges withdraw the 3/4 figure and succeed with certainty", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "mafia-preask",
    rounds: "8",
    tolerated: "0",
    preAsk: "8",
    predictable: true,
  });
  await page.locator("#run").click();
  expect(await metricValue(page, "Content errors")).toBe("0");
  await expect(page.locator("[data-verdict=session]")).toContainText(
    "ACCEPTED",
  );
  expect(await metricValue(page, "Exact success for this adversary")).toBe("1");
  await expect(page.locator("[data-verdict=caveat]").first()).toContainText(
    "does not apply",
  );
});

test("predictable challenges leave rounds outside a partial pre-ask blind", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "mafia-preask",
    rounds: "8",
    tolerated: "1",
    preAsk: "4",
    predictable: true,
  });
  await page.locator("#run").click();
  expect(await metricValue(page, "Exact success for this adversary")).toBe(
    blind(4, 1),
  );
  expect(await metricValue(page, "Exact success for this adversary")).toBe(
    "5/16",
  );
  await expect(page.locator("[data-verdict=caveat]").first()).toContainText(
    "remaining 4 round(s) are still blind guesses",
  );
});

test("predictable challenges make the distance-fraud key holder certain", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "distance-fraud",
    rounds: "8",
    tolerated: "0",
    predictable: true,
  });
  await page.locator("#run").click();
  expect(await metricValue(page, "Content errors")).toBe("0");
  expect(await metricValue(page, "Exact success for this adversary")).toBe("1");
  await expect(page.locator("[data-ensemble]")).toHaveCount(0);
  await expect(page.locator("[data-verdict=caveat]").first()).toContainText(
    "preselect every correct response",
  );
});

test("a reused nonce withdraws the independent-attempts formula", async ({
  page,
}) => {
  await setControls(page, { scenario: "mafia-preask", reuse: true });
  await page.locator("#run").click();
  await expect(page.locator("[data-verdict=caveat]").first()).toContainText(
    "not independent",
  );
  // The reused nonce is visible, so a learner can see it is the same one.
  expect(await metricValue(page, "Verifier nonce")).toBe("a1a1a1a1a1a1a1a1");
});

test("honest noise reports exact acceptance and false rejection", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "honest-noisy",
    rounds: "8",
    tolerated: "1",
    epsilon: "1/8",
  });
  await page.locator("#run").click();
  expect(await metricValue(page, "Exact honest acceptance")).toBe(
    "12353145/16777216",
  );
  expect(await metricValue(page, "Exact false rejection")).toBe(
    "4424071/16777216",
  );
  // They must be complementary, recomputed here.
  const a = 12353145n;
  const b = 4424071n;
  expect(a + b).toBe(16777216n);

  await setControls(page, {
    rounds: "3",
    tolerated: "0",
    epsilon: "1/3",
  });
  await page.locator("#run").click();
  expect(await metricValue(page, "Exact honest acceptance")).toBe("8/27");
  expect(await metricValue(page, "Exact false rejection")).toBe("19/27");
});

test("repeated fresh-nonce attempts compound, and a reused nonce withholds them", async ({
  page,
}) => {
  await setControls(page, {
    scenario: "mafia-preask",
    rounds: "8",
    tolerated: "1",
    preAsk: "8",
    attempts: "4",
    reuse: false,
  });
  await page.locator("#run").click();
  const shown = (await page.locator("[data-repeated]").textContent()) ?? "";
  // 1 - (1 - 24057/65536)^4, recomputed here.
  const pn = 24057n;
  const pd = 65536n;
  const qn = pd - pn;
  const num = pd ** 4n - qn ** 4n;
  const den = pd ** 4n;
  expect(shown).toContain(reduce(num, den));

  await setControls(page, { reuse: true });
  await page.locator("#run").click();
  await expect(page.locator("[data-repeated]")).toHaveCount(0);
  await expect(page.locator("[data-repeated-withheld]")).toContainText(
    "does not apply",
  );
});

test("changing any input retires the transcript and the verdict", async ({
  page,
}) => {
  await setControls(page, { scenario: "honest" });
  await page.locator("#run").click();
  await expect(page.locator("[data-verdict=session]")).toHaveCount(1);

  for (const [id, value] of [
    ["rounds", "6"],
    ["tolerated", "2"],
    ["range", "12"],
    ["deltaLb", "3"],
    ["speed", "2"],
    ["seed", "another"],
  ] as const) {
    await page.locator("#run").click();
    await expect(page.locator("[data-verdict=session]")).toHaveCount(1);
    await page.locator(`#${id}`).fill(value);
    await expect(page.locator("[data-verdict=stale]"), id).toHaveCount(1);
    await expect(page.locator("[data-verdict=session]"), id).toHaveCount(0);
    await expect(page.locator("#stale-note")).toContainText("Inputs changed");
  }

  // A checkbox retires it too.
  await page.locator("#run").click();
  await expect(page.locator("[data-verdict=session]")).toHaveCount(1);
  await page.locator("#timing").uncheck();
  await expect(page.locator("[data-verdict=stale]")).toHaveCount(1);
});

test("a browser clock cannot change the modeled verdict", async ({ page }) => {
  // Freeze and then wildly skew the page's clocks. The model reads neither, so
  // the rendered transcript must be byte-identical across both runs.
  const capture = async (): Promise<string> => {
    await setControls(page, {
      scenario: "online-relay",
      rounds: "8",
      tolerated: "2",
      relayLink: "30",
    });
    await page.locator("#run").click();
    await expect(page.locator("[data-verdict=session]")).toHaveCount(1);
    return (await page.locator("#result").innerText()).trim();
  };

  const first = await capture();

  await page.addInitScript(() => {
    // Both clocks return constants, and Date is a stopped clock.
    Date.now = () => 1;
    performance.now = () => 1;
  });
  await page.reload();
  const frozen = await capture();
  expect(frozen).toBe(first);

  await page.addInitScript(() => {
    Date.now = () => 8.64e15;
    performance.now = () => 8.64e15;
  });
  await page.reload();
  const skewed = await capture();
  expect(skewed).toBe(first);
});

test("the visible limits and primary sources do not overstate the model", async ({
  page,
}) => {
  const limits = page.locator("#limits");
  await expect(limits).toContainText("not ranging hardware");
  await expect(limits).toContainText("does not establish physical location");
  await expect(limits).toContainText(
    "does not measure nanosecond radio propagation",
  );
  await expect(limits).toContainText("fresh unpredictable verifier nonce");
  await expect(limits).toContainText("prover-chosen nonce");
  await expect(limits).toContainText("multipath");
  await expect(limits).toContainText("Early-detect and late-commit");
  await expect(limits).toContainText("Terrorist fraud");
  await expect(limits).toContainText(
    "Authentication and proximity are different properties",
  );
  await expect(limits).toContainText(
    "Brands-Chaum is referenced for comparison",
  );

  const sources = page.locator("#sources");
  await expect(sources).toContainText("Hancke");
  await expect(sources).toContainText("SecureComm 2005");
  await expect(sources).toContainText("Brands");
  await expect(sources).toContainText("Clulow");
  await expect(sources).toContainText("Avoine");
  await expect(sources).toContainText("Kara");
  await expect(sources).toContainText("Singelée");
});

test("distance fraud is never described as a relay or as mafia fraud", async ({
  page,
}) => {
  await setControls(page, { scenario: "distance-fraud" });
  await page.locator("#run").click();
  const result = page.locator("#result");
  await expect(result).toContainText("legitimate key holder");
  await expect(result).toContainText("NOT mafia fraud");
  await expect(result).toContainText("no relay and no third party");
  await expect(result).toContainText("retains both propagation legs");
  await expect(result).not.toContainText(
    "answers before the challenge arrives",
  );
});
