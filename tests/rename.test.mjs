// DIVE-5070: the command is `5dive a2a`, and `5dive peer` keeps working. The manifest keeps
// `peer` as the verb's name (all a 5dive CLI older than verb aliases reads, and that CLI still
// owns `a2a` as a builtin) and adds `a2a` as an alias. Every hint names the verb the caller
// typed, so a hint always works on the box that printed it.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN = (v) => path.join(ROOT, "a2a", "bin", v);
const CLI = path.join(ROOT, "a2a", "lib", "cli.mjs");
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "a2a/.claude-plugin/plugin.json"), "utf8"));

// Run an entry point the way 5dive's dispatcher does: FIVEDIVE_VERB is the verb that was typed.
const runBin = (file, verb, args) => {
  const env = { PATH: process.env.PATH };
  if (verb) env.FIVEDIVE_VERB = verb;
  const r = spawnSync(BIN(file), args, { env, input: "" });
  return { rc: r.status, out: r.stdout.toString(), err: r.stderr.toString() };
};
// Evaluate an export of cli.mjs in a fresh process, since VERB is fixed at import.
const evalCli = (verb, expr) => {
  const env = { PATH: process.env.PATH };
  if (verb !== undefined) env.FIVEDIVE_VERB = verb;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e",
    `const m = await import(${JSON.stringify(CLI)}); process.stdout.write(String(${expr}));`], { env });
  assert.equal(r.status, 0, r.stderr.toString());
  return r.stdout.toString();
};

test("the manifest keeps `peer` as the name (old CLIs) and adds `a2a` as its alias", () => {
  const verbs = manifest.fivedive.verbs;
  assert.equal(verbs.length, 1);
  assert.equal(verbs[0].name, "peer", "a CLI that predates aliases reads only .name, and it still owns `a2a`");
  assert.deepEqual(verbs[0].aliases, ["a2a"]);
  // What an old CLI's install check reads (`map(.name)`): `a2a` must not be in it, or the
  // plugin is refused there as naming a builtin.
  assert.deepEqual(verbs.map((v) => v.name), ["peer"]);
  assert.match(manifest.fivedive.setup.command, /^sudo 5dive peer setup$/, "the setup string must work on every CLI");
});

test("both verbs ship an executable entry point (5dive runs bin/<verb>, alias included)", () => {
  for (const v of ["peer", "a2a"]) {
    const st = fs.statSync(BIN(v));
    assert.ok(st.isFile() && (st.mode & 0o111), `bin/${v} is an executable file`);
  }
});

test("typed as `a2a`, every hint says `5dive a2a`", () => {
  for (const file of ["a2a", "peer"]) {
    const r = runBin(file, "a2a", ["--help"]);
    assert.equal(r.rc, 0, r.err);
    assert.match(r.out, /sudo 5dive a2a send <contact>/);
    assert.doesNotMatch(r.out, /5dive peer/);
  }
});

test("typed as `peer`, or run with no verb at all, every hint says `5dive peer`", () => {
  for (const [file, verb] of [["peer", "peer"], ["a2a", "peer"], ["peer", null], ["a2a", null]]) {
    const r = runBin(file, verb, ["--help"]);
    assert.equal(r.rc, 0, r.err);
    assert.match(r.out, /sudo 5dive peer send <contact>/, `bin/${file} verb=${verb}`);
    assert.doesNotMatch(r.out, /5dive a2a send/);
  }
});

test("an unknown FIVEDIVE_VERB is never echoed into a command line", () => {
  assert.equal(evalCli("rm -rf /", "m.VERB"), "peer");
  assert.equal(evalCli("", "m.VERB"), "peer");
  assert.equal(evalCli(undefined, "m.VERB"), "peer");
  assert.equal(evalCli("a2a", "m.VERB"), "a2a");
});

test("the delivery timer carries the verb setup ran as, so delivered reply hints match the box", () => {
  const tick = (verb) => evalCli(verb, `m.unitText("/usr/bin/node")["5dive-a2a-deliver.service"]`);
  assert.match(tick("a2a"), /^Environment=FIVEDIVE_VERB=a2a$/m);
  assert.match(tick("peer"), /^Environment=FIVEDIVE_VERB=peer$/m);
  const rec = `{ from_did: "did:key:z6Mkfixture", from_nick: "bob", from_address: "bob@example.com", envelope: { id: "m1", at: "t", body: "hi" } }`;
  const batch = (verb) => evalCli(verb, `m.renderBatch([${rec}], "n")`);
  assert.match(batch("a2a"), /Reply: sudo 5dive a2a send/);
  assert.match(batch(undefined), /Reply: sudo 5dive peer send/, "an old unit with no verb gets the name that works everywhere");
});

test("the README says, at the top, that this is not Google's A2A protocol", () => {
  const head = fs.readFileSync(path.join(ROOT, "README.md"), "utf8").split("\n").slice(0, 6).join("\n");
  assert.match(head, /Not Google's A2A protocol/);
});
