#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const runtimeDependencies = Object.keys(packageJson.dependencies ?? {});
if (runtimeDependencies.length !== 0) {
  throw new Error(
    `unexpected runtime dependencies: ${runtimeDependencies.join(", ")}`,
  );
}

const htmlPath = path.join(dist, "index.html");
const html = fs.readFileSync(htmlPath, "utf8");
if (!html.includes("/crypto-lab-distance-bounding/assets/")) {
  throw new Error(
    "built HTML does not use the /crypto-lab-distance-bounding/ base path",
  );
}
const assets = fs.readdirSync(path.join(dist, "assets"));
if (!assets.some((name) => name.endsWith(".js"))) {
  throw new Error("production build contains no JavaScript asset");
}
if (!assets.some((name) => name.endsWith(".css"))) {
  throw new Error("production build contains no CSS asset");
}

const deployedText = [
  html,
  ...assets
    .filter((name) => name.endsWith(".js") || name.endsWith(".css"))
    .map((name) => fs.readFileSync(path.join(dist, "assets", name), "utf8")),
].join("\n");

// The shipped bundle must identify this lesson and must still carry the
// claims the page is only honest because it makes.
for (const required of [
  "Distance bounding",
  "Hancke",
  "not ranging hardware",
  "does not establish physical location",
  "Authentication and proximity are different properties",
]) {
  if (!deployedText.includes(required)) {
    throw new Error(`production build lost required text: ${required}`);
  }
}

// A clock reaching a verdict is the one defect this lesson cannot ship.
for (const forbidden of ["Date.now(", "performance.now("]) {
  if (deployedText.includes(forbidden)) {
    throw new Error(`production build reads a clock: ${forbidden}`);
  }
}

console.info(
  "build evidence: distance-bounding base path, production assets, retained scope claims, no clock, zero runtime dependencies",
);
