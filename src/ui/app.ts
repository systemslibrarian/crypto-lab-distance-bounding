/**
 * The learner-facing lesson.
 *
 * All arithmetic comes from `src/db`. This file reads controls, calls the
 * model, and renders. It performs no protocol or probability computation of
 * its own, so a browser claim test can recompute any displayed figure from the
 * inputs shown beside it.
 */
import {
  type ScenarioConfig,
  type ScenarioName,
  DEFAULT_CONFIG,
  blindBaseline,
  attemptsSuccess,
  fraudGain,
  parseExact,
  relayExcess,
  runScenario,
  toDecimal,
  toFraction,
  toHex,
} from "../db";
import {
  checkbox,
  el,
  escape,
  field,
  metrics,
  select,
  table,
  verdict,
} from "./dom";

const SCENARIOS: readonly (readonly [ScenarioName, string])[] = [
  ["honest", "1 — Honest prover, inside range"],
  ["authenticated-relay", "2 — Ordinary authenticated exchange, relayed"],
  ["online-relay", "3 — Hancke-Kuhn online relay"],
  ["mafia-preask", "4 — Mafia fraud: pre-ask a remote prover"],
  ["distance-fraud", "5 — Distance fraud: dishonest distant key holder"],
  ["honest-noisy", "6 — Honest prover on a noisy channel"],
];

const LIMITS = [
  "This is an arithmetic and event simulator. It is not ranging hardware and contains no radio.",
  "It does not establish physical location, and it does not measure nanosecond radio propagation. Every time here is a declared model quantity in abstract units.",
  "No browser or machine clock reaches a verdict. Date.now, performance.now, animation duration and real network latency are not read by the model, and a unit test reads the model's source to prove it.",
  "The exact probabilities assume ideal independent PRF output bits, a fresh unpredictable verifier nonce, and challenge bits the attacker cannot predict. Where an experiment breaks one of those, the page withdraws the formula instead of printing a number that no longer applies.",
  "The paper's optional prover-nonce variant is not implemented. A prover-chosen nonce would let a prover grind for a favourable response table, which is a real risk and is named here rather than modelled.",
  "Real jitter, multipath, non-line-of-sight propagation, interference, correlated or bursty errors and radio capture effects are not modelled. The noise model flips each response bit independently, which real channels do not.",
  "The exact noise sampler accepts rational error rates whose reduced denominator is at most 2^32; it uses rejection sampling rather than silently rounding the requested probability.",
  "The distance-fraud actor chooses a response before seeing the challenge but begins its return transmission after challenge arrival. The model retains both propagation legs and omits only processing delay; scheduled pre-transmission and physical synchronization attacks are outside it.",
  "Early-detect and late-commit behaviour depends on physical-layer symbol timing and sits outside this executable core. It is named in the sources, after Clulow et al. 2006.",
  "Terrorist fraud, collusion between a prover and an accomplice, localisation and production parameter selection are all out of scope.",
  "Authentication and proximity are different properties. Experiment 2 exists to make that concrete: a valid HMAC-SHA-256 challenge-response relays without difficulty, but this teaching transcript is not a complete deployed authentication protocol.",
  "Brands-Chaum is referenced for comparison only. It is not implemented here.",
];

interface Controls {
  scenario: ScenarioName;
  rounds: number;
  toleratedErrors: number;
  range: string;
  deltaLb: string;
  speed: string;
  relayLink: string;
  fraudDelay: string;
  fraudDistance: string;
  preAskRounds: number;
  epsilon: string;
  attempts: number;
  seed: string;
  timingEnforced: boolean;
  predictableChallenges: boolean;
  reuseNonce: boolean;
}

const INITIAL: Controls = {
  scenario: "honest",
  rounds: 8,
  toleratedErrors: 1,
  range: "10",
  deltaLb: "2",
  speed: "1",
  relayLink: "30",
  fraudDelay: "0",
  fraudDistance: "11",
  preAskRounds: 8,
  epsilon: "1/8",
  attempts: 4,
  seed: "s06-default",
  timingEnforced: true,
  predictableChallenges: false,
  reuseNonce: false,
};

function shell(): string {
  return `
<h1>Distance bounding: why authentication is not proximity</h1>
<p class="lede">A verifier can confirm it is talking to the right key holder and still have no idea where that key holder is. Hancke and Kuhn's 2005 protocol adds a timed rapid-bit exchange so the round trip itself bounds the distance. This lesson runs that protocol on exact rational arithmetic and shows what each attacker can and cannot do to it.</p>

<section class="panel" aria-labelledby="setup-title">
  <div class="eyebrow">Set up a session</div>
  <h2 id="setup-title">Parameters</h2>
  <div class="controls">
    ${select("scenario", "Who is answering", SCENARIOS, INITIAL.scenario)}
    ${field("rounds", "Rapid rounds n", String(INITIAL.rounds), 'type="number" min="1" max="64" step="1"')}
    ${field("tolerated", "Tolerated content errors x", String(INITIAL.toleratedErrors), 'type="number" min="0" max="64" step="1"')}
    ${field("range", "Accepted range R (distance units)", INITIAL.range)}
    ${field("deltaLb", "Trusted delay floor delta_lb (time units)", INITIAL.deltaLb)}
    ${field("speed", "Propagation speed v (distance per time)", INITIAL.speed)}
    ${field("relayLink", "Relay link length (distance units)", INITIAL.relayLink)}
    ${field("fraudDistance", "Distance-fraud prover distance", INITIAL.fraudDistance)}
    ${field("fraudDelay", "Distance-fraud actual delay", INITIAL.fraudDelay)}
    ${field("preAsk", "Rounds pre-asked g", String(INITIAL.preAskRounds), 'type="number" min="0" max="64" step="1"')}
    ${field("epsilon", "Per-bit error rate epsilon", INITIAL.epsilon)}
    ${field("attempts", "Independent attempts q", String(INITIAL.attempts), 'type="number" min="0" max="1000" step="1"')}
    ${field("seed", "Replay seed", INITIAL.seed, 'type="text"')}
  </div>
  <div class="controls">
    ${checkbox("timing", "Verifier enforces timing", INITIAL.timingEnforced)}
    ${checkbox("predictable", "BROKEN: challenges are predictable", INITIAL.predictableChallenges)}
    ${checkbox("reuse", "BROKEN: verifier reuses its nonce", INITIAL.reuseNonce)}
  </div>
  <div class="row">
    <button id="run" class="primary" type="button">Run the session</button>
    <span class="note" id="stale-note" role="status" aria-live="polite"></span>
  </div>
</section>

<section class="panel" aria-labelledby="result-title">
  <div class="eyebrow">What the verifier concluded</div>
  <h2 id="result-title">Result</h2>
  <div id="result"><p class="note">Press <strong>Run the session</strong>.</p></div>
</section>

<section class="panel" aria-labelledby="limits-title">
  <div class="eyebrow">Scope</div>
  <h2 id="limits-title">What this lesson does not do</h2>
  <ul id="limits">${LIMITS.map((l) => `<li>${escape(l)}</li>`).join("")}</ul>
</section>

<section class="panel" aria-labelledby="sources-title">
  <div class="eyebrow">Primary sources</div>
  <h2 id="sources-title">Read, not summarised</h2>
  <ul id="sources">
    <li><a href="https://www.cl.cam.ac.uk/~mgk25/sc2005-distance.pdf">G. P. Hancke and M. G. Kuhn, "An RFID Distance Bounding Protocol", SecureComm 2005, Athens, 5-9 September 2005, pp. 67-73</a>. Section 2 p. 68 equations (1) and (2) for the timing model; section 3.1 p. 69 for the protocol and the 3/4 per-round bound; section 3.2 p. 70 for the function h and its parameters; section 3.4 p. 70 for the false-accept and false-reject sums.</li>
    <li><a href="https://link.springer.com/content/pdf/10.1007/3-540-48285-7_30.pdf">S. Brands and D. Chaum, "Distance-Bounding Protocols", EUROCRYPT '93, LNCS 765, pp. 344-359</a>. The first timed challenge-response distance bound, described in Hancke-Kuhn section 2. Referenced for comparison only and not implemented here.</li>
    <li><a href="https://www.cl.cam.ac.uk/~mgk25/esas2006-distance.pdf">J. Clulow, G. P. Hancke, M. G. Kuhn and T. Moore, "So Near and Yet So Far: Distance-Bounding Attacks in Wireless Networks", ESAS 2006</a>. The source for early-detect and late-commit physical-layer attacks, which are named here and deliberately left outside the executable core.</li>
    <li><a href="https://sites.uclouvain.be/security/download/papers/AvoineBKLM-2010-jcs.pdf">G. Avoine, M. A. Bingöl, S. Kardaş, C. Lauradoux and B. Martin, "A Framework for Analyzing RFID Distance Bounding Protocols", Journal of Computer Security, 2010</a>. The adversary classification this lesson borrows its vocabulary from, including the separation of mafia fraud from distance fraud.</li>
    <li><a href="https://research.sabanciuniv.edu/id/eprint/15328/1/optimal.pdf">O. Kara, S. Kardaş, M. A. Bingöl and G. Avoine, "Optimal Security Limits of RFID Distance Bounding Protocols"</a>. Security limits for bitwise fast-phase protocols with no final signature, which is the class the protocol here belongs to.</li>
    <li><a href="https://cosicdatabase.esat.kuleuven.be/backend/publications/files/conferencepaper/919">D. Singelée and B. Preneel, "Distance Bounding in Noisy Environments"</a>. On tolerating channel errors without handing the attacker the allowance, which is why timing failures here can never spend x.</li>
  </ul>
</section>

<footer>
  <p>Every number on this page is computed from exact BigInt rationals. Decimals appear only beside their exact fractions, never instead of them.</p>
</footer>`;
}

function readControls(): Controls {
  const value = (id: string): string =>
    el<HTMLInputElement>(`#${id}`).value.trim();
  const checked = (id: string): boolean =>
    el<HTMLInputElement>(`#${id}`).checked;
  return {
    scenario: el<HTMLSelectElement>("#scenario").value as ScenarioName,
    rounds: Number(value("rounds")),
    toleratedErrors: Number(value("tolerated")),
    range: value("range"),
    deltaLb: value("deltaLb"),
    speed: value("speed"),
    relayLink: value("relayLink"),
    fraudDistance: value("fraudDistance"),
    fraudDelay: value("fraudDelay"),
    preAskRounds: Number(value("preAsk")),
    epsilon: value("epsilon"),
    attempts: Number(value("attempts")),
    seed: value("seed"),
    timingEnforced: checked("timing"),
    predictableChallenges: checked("predictable"),
    reuseNonce: checked("reuse"),
  };
}

function toConfig(controls: Controls): ScenarioConfig {
  return {
    ...DEFAULT_CONFIG,
    scenario: controls.scenario,
    rounds: controls.rounds,
    toleratedErrors: controls.toleratedErrors,
    seed: controls.seed,
    profile: {
      v: parseExact(controls.speed),
      range: parseExact(controls.range),
      deltaLb: parseExact(controls.deltaLb),
    },
    relay: {
      ...DEFAULT_CONFIG.relay,
      relayLink: parseExact(controls.relayLink),
    },
    fraudDistance: parseExact(controls.fraudDistance),
    fraudDelay: parseExact(controls.fraudDelay),
    noise: { ...DEFAULT_CONFIG.noise, epsilon: parseExact(controls.epsilon) },
    preAskRounds: controls.preAskRounds,
    timingEnforced: controls.timingEnforced,
    predictableChallenges: controls.predictableChallenges,
    reuseNonce: controls.reuseNonce,
  };
}

function render(config: ScenarioConfig, attempts: number): string {
  const result = runScenario(config);
  const { analysis } = result;

  if (result.authenticatedRelay) {
    const authentication = result.authenticatedRelay;
    return `
${verdict(
  authentication.authenticated ? "bad" : "warn",
  authentication.authenticated ? "AUTHENTICATED" : "AUTHENTICATION FAILED",
  "The verifier checked a relayed HMAC response. This untimed exchange has no rapid-bit phase and makes no distance verdict.",
  "session",
)}
${verdict(
  "bad",
  "AUTHENTICATED, AND NO PROXIMITY PROVED",
  authentication.note,
  "authenticated-relay",
)}
${metrics([
  ["Relayed challenge (128-bit hex)", toHex(authentication.challenge)],
  ["Relayed HMAC-SHA-256 tag (hex)", toHex(authentication.relayedTag)],
  [
    "Altered-tag control",
    result.authenticationTamperRejected ? "REJECTED" : "FAILED OPEN",
  ],
  ["Rapid rounds", "not run"],
  ["Timing measurement", "not run"],
])}
<h3>Ordinary authentication transcript</h3>
<p class="note">The relay receives only a challenge oracle, not the shared key. It forwards the verifier's challenge to the genuine key holder and returns that holder's tag unchanged. A changed tag is rejected in the executable control tests.</p>
<h3>What happened</h3>
${result.notes.map((note) => `<p class="note">${escape(note)}</p>`).join("")}`;
  }

  if (!result.verdict) {
    throw new Error("rapid scenario produced no distance-bounding verdict");
  }
  const outcome = result.verdict;

  const headline = outcome.accepted
    ? verdict(
        config.scenario === "honest" || config.scenario === "honest-noisy"
          ? "ok"
          : "bad",
        outcome.accepted ? "ACCEPTED" : "REJECTED",
        outcome.reason,
        "session",
      )
    : verdict(
        config.scenario === "honest" || config.scenario === "honest-noisy"
          ? "warn"
          : "ok",
        "REJECTED",
        outcome.reason,
        "session",
      );

  const rows = result.verdict.rounds.map((round, index) => [
    round.round,
    result.records[index].challenge,
    result.records[index].received ?? "-",
    result.records[index].expected,
    toFraction(round.total),
    round.timingOk ? "in time" : "LATE",
    round.contentOk ? "correct" : "wrong",
    round.outcome,
  ]);

  const probability: string[] = [];
  if (analysis.adversarySuccess) {
    probability.push(
      metrics([
        [
          `Exact success for this adversary (${analysis.adversarySuccessLabel})`,
          toFraction(analysis.adversarySuccess),
        ],
        ["as a decimal", toDecimal(analysis.adversarySuccess, 10)],
        ["Blind-guess baseline", toFraction(blindBaseline(config))],
      ]),
    );
  }
  const repeated = attemptsSuccess(config, analysis.adversarySuccess, attempts);
  if (repeated) {
    probability.push(
      `<p class="note" data-repeated>Over <span class="mono">${escape(attempts)}</span> independent attempts, each with a FRESH verifier nonce, the same adversary succeeds at least once with exact probability <span class="mono">${escape(toFraction(repeated))}</span>.</p>`,
    );
  } else if (analysis.adversarySuccess && config.reuseNonce) {
    probability.push(
      `<p class="note" data-repeated-withheld>No figure is given for repeated attempts: the verifier reused its nonce, so the attempts are not independent and <span class="mono">1-(1-p)^q</span> does not apply.</p>`,
    );
  }
  if (analysis.ensembleAverage) {
    probability.push(
      `<p class="note">The figure above is conditioned on THIS session's realized response table. The ideal ensemble average over h ~ Binomial(n, 1/2) is <span class="mono" data-ensemble>${escape(toFraction(analysis.ensembleAverage))}</span>; it is shown beside the realized value, never instead of it, because an average cannot tell you whether the session in front of you is the weak one.</p>`,
    );
  }
  if (analysis.honestAcceptance && analysis.falseRejection) {
    probability.push(
      metrics([
        ["Exact honest acceptance", toFraction(analysis.honestAcceptance)],
        ["Exact false rejection", toFraction(analysis.falseRejection)],
      ]),
    );
  }

  const caveats = analysis.formulaCaveats.length
    ? analysis.formulaCaveats
        .map((c) => verdict("warn", "Formula withdrawn", c, "caveat"))
        .join("")
    : "";

  const extra: string[] = [];
  if (config.scenario === "online-relay") {
    extra.push(
      `<p class="note" data-relay-excess>The relay path overshoots the accepted threshold by <span class="mono">${escape(toFraction(relayExcess(config)))}</span> time units in every round.</p>`,
    );
  }
  if (config.scenario === "distance-fraud") {
    extra.push(
      `<p class="note" data-fraud-gain>Answering in <span class="mono">${escape(toFraction(config.fraudDelay))}</span> instead of the trusted floor <span class="mono">${escape(toFraction(config.profile.deltaLb))}</span> makes the prover look <span class="mono">${escape(toFraction(fraudGain(config)))}</span> distance units nearer than it is. The displayed bound stops being an upper bound exactly here.</p>`,
    );
  }

  return `
${headline}
${metrics([
  ["Threshold Theta = 2R/v + delta_lb", toFraction(result.threshold)],
  ["Rounds n", config.rounds],
  ["Tolerated content errors x", config.toleratedErrors],
  ["Content errors", outcome.contentErrors],
  ["Late rounds", outcome.lateRounds],
  ["Missing rounds", outcome.missingRounds],
  ["Realized register distance h", analysis.registerDistance],
  ["Verifier nonce N_V", result.nonceHex],
])}
${caveats}
${extra.join("")}
<h3>Rapid rounds</h3>
${table(
  ["i", "C_i", "received", "expected", "T_i", "timing", "content", "outcome"],
  rows,
  "Rapid round transcript",
  "rounds-table",
)}
<p class="note">A late round is counted as a timing failure and never as a content error, so it cannot spend the allowance x. That separation is the whole difference between a distance bound and an ordinary authentication exchange.</p>
<h3>Exact probabilities</h3>
${probability.join("") || '<p class="note">No adversary is acting in this experiment.</p>'}
<h3>What happened</h3>
${result.notes.map((n) => `<p class="note">${escape(n)}</p>`).join("")}`;
}

export function mount(root: HTMLElement): void {
  root.innerHTML = shell();
  const output = el("#result");
  const staleNote = el("#stale-note");
  let lastSignature = "";

  const signature = (): string => JSON.stringify(readControls());

  const retire = (): void => {
    if (!lastSignature || signature() === lastSignature) {
      staleNote.textContent = "";
      return;
    }
    output.innerHTML = verdict(
      "warn",
      "Retired: inputs changed",
      "The transcript and verdict below were computed from different inputs. Run the session again.",
      "stale",
    );
    staleNote.textContent = "Inputs changed since the last run.";
  };

  const run = (): void => {
    try {
      const controls = readControls();
      output.innerHTML = render(toConfig(controls), controls.attempts);
      lastSignature = JSON.stringify(controls);
      staleNote.textContent = "";
    } catch (error) {
      output.innerHTML = verdict(
        "warn",
        "Input refused",
        error instanceof Error ? error.message : String(error),
        "error",
      );
      lastSignature = "";
      staleNote.textContent = "";
    }
  };

  el<HTMLButtonElement>("#run").addEventListener("click", run);
  for (const control of root.querySelectorAll<HTMLElement>("input, select")) {
    control.addEventListener("input", retire);
    control.addEventListener("change", retire);
  }
}
