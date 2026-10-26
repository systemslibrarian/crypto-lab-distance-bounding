/**
 * Known WCAG 1.4.11 or generated-content findings.
 *
 * Deliberately empty. A new finding fails the gate, and the gate also fails if
 * a baselined entry worsens or disappears, so this cannot quietly become a
 * permanent exemption.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {};
