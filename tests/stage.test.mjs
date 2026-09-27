// DIVE-5087: a2a is labelled experimental, as data the dashboard reads (`fivedive.stage`), not a
// name the dashboard hard-codes. The marketplace listing says the same for readers outside it.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => JSON.parse(fs.readFileSync(path.join(ROOT, p), "utf8"));

test("the manifest declares the plugin experimental", () => {
  assert.equal(read("a2a/.claude-plugin/plugin.json").fivedive.stage, "experimental");
});

test("the marketplace listing leads with Experimental", () => {
  const row = read(".claude-plugin/marketplace.json").plugins.find((p) => p.name === "a2a");
  assert.match(row.description, /^Experimental\. /);
});
