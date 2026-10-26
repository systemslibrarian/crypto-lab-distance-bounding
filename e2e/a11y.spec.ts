import { expect, test, type Page } from "@playwright/test";

import {
  assertHiddenElementsDoNotPaint,
  boot,
  driveAllStates,
  expectBaselineNotStale,
  expectNoHorizontalOverflow,
  NARROW,
  reportCollected,
  settle,
  watchPageErrors,
} from "./gate";

const pageErrors = new WeakMap<Page, string[]>();

test.beforeEach(async ({ page }) => {
  pageErrors.set(page, watchPageErrors(page));
});

test.afterEach(async ({ page }) => {
  const errors = pageErrors.get(page) ?? [];
  expect(errors, errors.join("\n")).toEqual([]);
});

/**
 * Both colour schemes are scanned, because both are real: this lesson pins no
 * theme and persists nothing, so the operating-system preference is the only
 * input and a palette that fails contrast in one scheme would ship unnoticed
 * if only the other were scanned.
 */
const comprehensiveCases = [
  { osScheme: "dark", viewport: undefined, label: "dark OS preference" },
  {
    osScheme: "light",
    viewport: NARROW,
    label: "light OS preference at 380px",
  },
  {
    osScheme: "dark",
    viewport: { width: 320, height: 900 },
    label: "dark OS preference at 320px",
  },
] as const;

for (const { osScheme, viewport, label } of comprehensiveCases) {
  test(`all distance-bounding states pass WCAG A/AA under ${label}`, async ({
    page,
  }) => {
    test.setTimeout(900_000);
    if (viewport) await page.setViewportSize(viewport);
    await boot(page, osScheme);
    await driveAllStates(page, label);
    expectBaselineNotStale();
    reportCollected();
  });
}

for (const width of [320, 360, 390, 768, 1440]) {
  test(`every scenario reflows without page-level clipping at ${width}px`, async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await page.setViewportSize({ width, height: 900 });
    await boot(page, "dark");

    for (const scenario of [
      "honest",
      "authenticated-relay",
      "online-relay",
      "mafia-preask",
      "distance-fraud",
      "honest-noisy",
    ]) {
      await page.locator("#scenario").selectOption(scenario);
      await page.locator("#run").click();
      await expect(page.locator("[data-verdict=session]")).toHaveCount(1);
      await settle(page);
      await expectNoHorizontalOverflow(page, `${scenario} at ${width}px`);
      await assertHiddenElementsDoNotPaint(page, `${scenario} at ${width}px`);
    }
  });
}

test("the round transcript scrolls inside its own region rather than the page", async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 900 });
  await boot(page, "dark");
  await page.locator("#run").click();
  await expect(page.locator("#rounds-table")).toHaveCount(1);
  // The wide table is an intentional inner scroller and is reachable by
  // keyboard, which is what keeps it from being a 1.4.10 reflow failure.
  await expect(page.locator("#rounds-table")).toHaveAttribute("tabindex", "0");
  await expect(page.locator("#rounds-table")).toHaveAttribute("role", "region");
  await expectNoHorizontalOverflow(page, "transcript at 320px");
});

test("the whole lesson is operable from the keyboard with a visible focus ring", async ({
  page,
}) => {
  await boot(page, "dark");
  const run = page.locator("#run");
  await run.focus();
  await expect(run).toBeFocused();
  const outline = await run.evaluate(
    (node) => getComputedStyle(node).outlineStyle,
  );
  expect(outline).not.toBe("none");
  await page.keyboard.press("Enter");
  await expect(page.locator("[data-verdict=session]")).toHaveCount(1);

  // The select is reachable and changes the scenario without a pointer.
  const scenario = page.locator("#scenario");
  await scenario.focus();
  await expect(scenario).toBeFocused();
  await scenario.selectOption("online-relay");
  await expect(page.locator("[data-verdict=stale]")).toHaveCount(1);
});
