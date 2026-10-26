#!/usr/bin/env node
/**
 * Clean-baseline source-mutation gate for the distance-bounding lesson.
 *
 * Run only from a clean commit. The runner proves the unmodified unit and
 * browser baseline first, changes exactly one source file at a time, requires
 * the mutated bundle to differ, requires the NAMED owning assertion to fail as
 * an ordinary test failure rather than as a crash, restores the exact saved
 * bytes, rebuilds to the baseline digest, and re-proves that assertion.
 * Evidence is written below the ignored test-results/ directory.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RESULT_ROOT = path.join(ROOT, "test-results", "claim-mutations");
const HEAD = git(["rev-parse", "HEAD"]).trim();
const CHILD_ENV = { ...process.env, CI: "1", FORCE_COLOR: "0" };

/**
 * Both runners take their name filter as a REGULAR EXPRESSION, so an assertion
 * title containing `+`, `(`, `?` or `.` silently selects nothing. A filter that
 * matches no test exits zero, which the gate would read as "the mutant
 * survived" -- or worse, on the restored run, as "the assertion passed". The
 * first mutation in this file hit exactly that: its title ends "T = 2D/v +
 * delta_P", and the bare `+` turned the pattern into "one or more spaces".
 * Escaping makes the title a literal, and `ranTests` below refuses a run that
 * executed nothing.
 */
const literal = (id) => id.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);

const unit = (file, id) => ({
  program: "npx",
  args: [
    "--no-install",
    "vitest",
    "run",
    file,
    "-t",
    literal(id),
    "--reporter=verbose",
  ],
  assertion: id,
});
const browser = (id) => ({
  program: "npx",
  args: [
    "--no-install",
    "playwright",
    "test",
    "claims.spec.ts",
    "--grep",
    literal(id),
    "--workers=1",
    "--retries=0",
    "--reporter=line",
  ],
  assertion: id,
});

/** A run that executed no test proves nothing, whatever its exit status. */
function ranTests(result) {
  if (/No test files found|No tests found/i.test(result.output)) return false;
  const vitest = /Tests\s+(?:\d+\s+failed\s*\|\s*)?(\d+)\s+passed/.exec(
    result.output,
  );
  const vitestNone = /Tests\s+no tests/i.test(result.output);
  if (vitestNone) return false;
  const playwright = /(\d+)\s+(?:passed|failed)/.exec(result.output);
  return Boolean(vitest || playwright);
}

const MUTATIONS = [
  {
    id: "S06-M01",
    finding:
      "A round trip crosses the distance twice: T = 2D/v + delta_P, not D/v + delta_P.",
    file: "src/db/timing.ts",
    anchor: "  return roundTrip(leg, deltaP, leg);",
    replacement: "  return roundTrip(leg, deltaP, exact(0n));",
    target: unit(
      "src/db/timing.test.ts",
      "builds the symmetric direct path T = 2D/v + delta_P",
    ),
  },
  {
    id: "S06-M02",
    finding:
      "The acceptance boundary is exact and inclusive: T = Theta is inside the range.",
    file: "src/db/timing.ts",
    anchor: "  return lte(total, threshold(profile));",
    replacement: "  return lte(total, sub(threshold(profile), exact(1n)));",
    target: unit(
      "src/db/timing.test.ts",
      "accepts T = 22 and rejects T = 23, with no tolerance either side",
    ),
  },
  {
    id: "S06-M03",
    finding:
      "A late answer is a timing failure and must never consume the content-error allowance x.",
    file: "src/db/protocol.ts",
    anchor: '      outcome = "late";\n      lateRounds += 1;',
    replacement: '      outcome = "late";\n      contentErrors += 1;',
    target: unit(
      "src/db/protocol.test.ts",
      "REJECTS any late round even when the error allowance is generous",
    ),
  },
  {
    id: "S06-M04",
    finding:
      "A pre-asking attacker answers a round correctly with probability 3/4, not 1/2.",
    file: "src/db/probability.ts",
    anchor: "    numerator += binomial(n, e) * ipow(3n, n - e);",
    replacement: "    numerator += binomial(n, e) * ipow(1n, n - e);",
    target: unit(
      "src/db/probability.test.ts",
      "reproduces every pinned fixture exactly",
    ),
  },
  {
    id: "S06-M05",
    finding:
      "A partial pre-ask convolves the pre-asked and blind error counts; it is not a product of separate allowances.",
    file: "src/db/probability.ts",
    anchor: "      if (b > blind) continue;",
    replacement: "      if (b !== 0) continue;",
    target: unit(
      "src/db/probability.test.ts",
      "matches enumeration for every partial pre-ask split through n = 8",
    ),
  },
  {
    id: "S06-M06",
    finding:
      "Distance fraud is conditioned on the REALIZED Hamming distance between R0 and R1, not on n.",
    file: "src/db/scenario.ts",
    anchor:
      "      analysisSuccess = distanceFraudSuccess(h, config.toleratedErrors);",
    replacement:
      "      analysisSuccess = distanceFraudSuccess(config.rounds, config.toleratedErrors);",
    target: browser(
      "distance fraud is conditioned on the realized register distance",
    ),
  },
  {
    id: "S06-M07",
    finding:
      "Attempts under a reused nonce are not independent, so 1-(1-p)^q must be refused rather than applied.",
    file: "src/db/probability.ts",
    anchor: "  if (!freshNoncePerAttempt) {",
    replacement: "  if (false && !freshNoncePerAttempt) {",
    target: unit(
      "src/db/probability.test.ts",
      "refuses to treat reused-nonce attempts as independent",
    ),
  },
  {
    id: "S06-M08",
    finding:
      "Predictable challenges make a pre-ask certain; quoting the ideal 3/4-per-round bound there would understate the attacker.",
    file: "src/db/scenario.ts",
    anchor:
      "      analysisSuccess = config.predictableChallenges\n        ? exact(1n)",
    replacement:
      "      analysisSuccess = config.predictableChallenges\n        ? mafiaSuccess(config.rounds, config.toleratedErrors)",
    target: browser(
      "predictable challenges withdraw the 3/4 figure and succeed with certainty",
    ),
  },
  {
    id: "S06-M09",
    finding:
      "The mafia attacker guesses its own challenges. Handing it the verifier's real ones is the same as letting it read the response registers.",
    file: "src/db/scenario.ts",
    anchor:
      "      const guesses = config.predictableChallenges\n        ? challenges.slice()\n        : new BitSource(utf8(`${config.seed}/mafia-guess`)).nextBits(\n            config.rounds,\n          );",
    replacement: "      const guesses = challenges.slice();",
    target: unit(
      "src/db/scenario.test.ts",
      "never hands the mafia attacker the verifier's real challenges",
    ),
  },
  {
    id: "S06-M10",
    finding:
      "Changing an input must retire the displayed transcript and verdict rather than leaving stale evidence on screen.",
    file: "src/ui/app.ts",
    anchor:
      '    output.innerHTML = verdict(\n      "warn",\n      "Retired: inputs changed",',
    replacement:
      '    if (lastSignature === "") return;\n    output.innerHTML = verdict(\n      "warn",\n      "Retired: inputs changed",',
    target: browser(
      "changing any input retires the transcript and the verdict",
    ),
  },
  {
    id: "S06-M11",
    finding:
      "No browser clock may reach a displayed verdict. Every modeled time is an exact rational supplied by the scenario.",
    file: "src/ui/app.ts",
    anchor: '  ["Rounds n", config.rounds],',
    replacement:
      '  ["Rounds n", `${config.rounds}:${new Date().getMilliseconds()}`],',
    target: browser("a browser clock cannot change the modeled verdict"),
  },
];

function git(args) {
  const result = spawnSync("git", ["-C", ROOT, ...args], {
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  }
  return result.stdout;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function occurrences(text, anchor) {
  return text.split(anchor).length - 1;
}

function assertClean() {
  if (git(["rev-parse", "HEAD"]).trim() !== HEAD) {
    throw new Error("HEAD moved during the mutation run");
  }
  const status = git(["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status !== "")
    throw new Error(`working tree is not clean: ${status.trim()}`);
}

function run(label, program, args, timeout = 300_000) {
  const startedAt = new Date().toISOString();
  const result = spawnSync(program, args, {
    cwd: ROOT,
    env: CHILD_ENV,
    encoding: "utf8",
    maxBuffer: 40 * 1024 * 1024,
    timeout,
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  return {
    label,
    program,
    args,
    startedAt,
    finishedAt: new Date().toISOString(),
    status: result.status,
    signal: result.signal,
    error: result.error?.message,
    output,
  };
}

function mustPass(result) {
  if (result.status !== 0 || result.signal || result.error) {
    throw new Error(`${result.label} failed\n${result.output}`);
  }
}

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function bundleDigest() {
  const directory = path.join(ROOT, "dist", "assets");
  const files = fs
    .readdirSync(directory)
    .filter((name) => name.endsWith(".js"))
    .sort();
  if (files.length === 0)
    throw new Error("build produced no JavaScript bundle");
  return sha256(
    files
      .map((name) => fs.readFileSync(path.join(directory, name)))
      .reduce(
        (joined, bytes) => Buffer.concat([joined, bytes]),
        Buffer.alloc(0),
      ),
  );
}

function build(label) {
  const result = run(label, "npm", ["run", "build"]);
  mustPass(result);
  return { command: result, digest: bundleDigest() };
}

function targetFailureIsOwned(result, mutation) {
  const { id, target } = mutation;
  if (!ranTests(result)) {
    throw new Error(
      `${id}: the owning assertion selected no test, so neither outcome means anything\n${result.output.slice(0, 2000)}`,
    );
  }
  if (result.status === 0) return false;
  if (result.status !== 1 || result.signal || result.error) {
    throw new Error(
      `${id}: target did not end in an ordinary test failure\n${result.output}`,
    );
  }
  if (
    /browserType\.launch|Executable doesn't exist|ERR_CONNECTION|ECONNREFUSED|EADDRINUSE|Target page, context or browser has been closed|Test timeout|error TS\d+/i.test(
      result.output,
    )
  ) {
    throw new Error(
      `${id}: infrastructure failure is not a caught mutation\n${result.output}`,
    );
  }
  if (
    !result.output.includes(target.assertion) ||
    !/AssertionError|expect\(|Expected:|Received:|Assertion/i.test(
      result.output,
    )
  ) {
    throw new Error(
      `${id}: failure was not owned by the named assertion\n${result.output}`,
    );
  }
  return true;
}

function compact(result) {
  return {
    label: result.label,
    program: result.program,
    args: result.args,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    status: result.status,
    signal: result.signal,
    error: result.error,
    outputSha256: sha256(result.output),
    outputTail: result.output.slice(-4000),
  };
}

function main() {
  if (process.argv.length !== 2) {
    throw new Error(
      "Usage: node scripts/claim-mutations.mjs (commit real work first)",
    );
  }
  if (
    fs.realpathSync(git(["rev-parse", "--show-toplevel"]).trim()) !==
    fs.realpathSync(ROOT)
  ) {
    throw new Error("run this script from its own repository");
  }
  assertClean();
  fs.mkdirSync(RESULT_ROOT, { recursive: true });
  const runDirectory = path.join(
    RESULT_ROOT,
    `${new Date().toISOString().replaceAll(/[:.]/g, "-")}-${process.pid}`,
  );
  fs.mkdirSync(runDirectory);
  const report = {
    schemaVersion: 1,
    head: HEAD,
    startedAt: new Date().toISOString(),
    baseline: {},
    mutations: [],
    status: "RUNNING",
  };
  const save = () => {
    fs.mkdirSync(runDirectory, { recursive: true });
    fs.writeFileSync(
      path.join(runDirectory, "report.json"),
      `${JSON.stringify(report, null, 2)}\n`,
    );
  };

  for (const mutation of MUTATIONS) {
    const bytes = fs.readFileSync(path.join(ROOT, mutation.file));
    const text = bytes.toString("utf8");
    if (
      occurrences(text, mutation.anchor) !== 1 ||
      mutation.anchor === mutation.replacement
    ) {
      throw new Error(
        `${mutation.id}: anchor must occur exactly once in ${mutation.file}`,
      );
    }
    const committed = git(["show", `HEAD:${mutation.file}`]);
    if (!Buffer.from(committed).equals(bytes)) {
      throw new Error(`${mutation.file} differs from the committed baseline`);
    }
  }

  try {
    const baselineBuild = build("baseline build");
    const baselineUnit = run("baseline unit", "npm", ["test"]);
    mustPass(baselineUnit);
    const baselineBrowser = run(
      "baseline browser claims",
      "npm",
      ["run", "test:claims"],
      900_000,
    );
    mustPass(baselineBrowser);
    assertClean();
    report.baseline = {
      bundleSha256: baselineBuild.digest,
      build: compact(baselineBuild.command),
      unit: compact(baselineUnit),
      browser: compact(baselineBrowser),
      passed: true,
    };
    console.info("baseline: unmutated copy PASSES");
    save();

    for (const mutation of MUTATIONS) {
      const targetPath = path.join(ROOT, mutation.file);
      const original = fs.readFileSync(targetPath);
      const changed = Buffer.from(
        original
          .toString("utf8")
          .replace(mutation.anchor, mutation.replacement),
      );
      const evidence = {
        id: mutation.id,
        finding: mutation.finding,
        file: mutation.file,
        originalSha256: sha256(original),
        mutantSha256: sha256(changed),
        status: "RUNNING",
      };
      report.mutations.push(evidence);
      save();
      let mutationError;
      let restorationError;
      try {
        fs.writeFileSync(targetPath, changed);
        const dirty = git([
          "status",
          "--porcelain=v1",
          "--untracked-files=all",
        ]);
        if (dirty !== ` M ${mutation.file}\n`) {
          throw new Error(
            `${mutation.id}: mutation did not produce exactly one modified file: ${dirty}`,
          );
        }
        const mutantBuild = build(`${mutation.id} mutant build`);
        if (mutantBuild.digest === report.baseline.bundleSha256) {
          throw new Error(
            `${mutation.id}: source mutation did not change the browser bundle`,
          );
        }
        const result = run(
          `${mutation.id} owning test`,
          mutation.target.program,
          mutation.target.args,
          mutation.target.args.includes("playwright") ? 900_000 : 300_000,
        );
        requireCondition(
          targetFailureIsOwned(result, mutation),
          `${mutation.id}: mutant survived its owning assertion`,
        );
        evidence.mutantBundleSha256 = mutantBuild.digest;
        evidence.build = compact(mutantBuild.command);
        evidence.owningTest = compact(result);
      } catch (error) {
        mutationError = error;
        evidence.error = error.message;
      } finally {
        try {
          fs.writeFileSync(targetPath, original);
          requireCondition(
            fs.readFileSync(targetPath).equals(original),
            `${mutation.id}: exact source restoration failed`,
          );
          const restoredBuild = build(`${mutation.id} restored build`);
          requireCondition(
            restoredBuild.digest === report.baseline.bundleSha256,
            `${mutation.id}: restored bundle differs from baseline`,
          );
          const restoredTarget = run(
            `${mutation.id} restored owning test`,
            mutation.target.program,
            mutation.target.args,
            mutation.target.args.includes("playwright") ? 900_000 : 300_000,
          );
          mustPass(restoredTarget);
          requireCondition(
            ranTests(restoredTarget),
            `${mutation.id}: the restored owning assertion selected no test`,
          );
          assertClean();
          evidence.restoration = {
            sourceSha256: sha256(fs.readFileSync(targetPath)),
            bundleSha256: restoredBuild.digest,
            build: compact(restoredBuild.command),
            owningTest: compact(restoredTarget),
            passed: true,
          };
        } catch (error) {
          restorationError = error;
          evidence.restoration = { passed: false, error: error.message };
        }
      }
      if (restorationError) throw restorationError;
      if (mutationError) {
        evidence.status = "FAILED";
        save();
        throw mutationError;
      }
      evidence.status = "CAUGHT";
      console.info(`${mutation.id}: caught`);
      save();
    }

    report.status = "PASSED";
    report.finishedAt = new Date().toISOString();
    save();
    console.info(`all ${MUTATIONS.length} mutation(s) caught`);
    console.info(`evidence: ${path.join(runDirectory, "report.json")}`);
  } catch (error) {
    report.status = "FAILED";
    report.finishedAt = new Date().toISOString();
    report.error = error.message;
    save();
    console.error(`mutation gate FAILED: ${error.message}`);
    console.error(`evidence: ${path.join(runDirectory, "report.json")}`);
    process.exitCode = 1;
  }
}

main();
