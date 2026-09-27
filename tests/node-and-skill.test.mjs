// DIVE-5065: what a stranger's box needs before `5dive peer` works, and how its agents learn
// to use it. bin/peer on a box with no node (plain Ubuntu: `plugin add` succeeded, `peer
// setup` failed), and the skill + AGENTS.md section the plugin now ships.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PEER = path.join(ROOT, "a2a", "bin", "a2a");
const BASH = fs.existsSync("/bin/bash") ? "/bin/bash" : "/usr/bin/bash";
const which = (cmd) => spawnSync(BASH, ["-c", `command -v ${cmd}`]).stdout.toString().trim();
const CP = which("cp");

// A PATH holding only what bin/peer needs and the stubs a case asks for, so the host's own
// node (nvm, /usr/bin, the CI toolcache) is never found by accident.
function box({ node = null, pm = "apt-get", pmFails = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-node-"));
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin);
  fs.symlinkSync(which("dirname"), path.join(bin, "dirname"));
  const log = path.join(dir, "calls.log");
  // The stub node: answers the version probe, and records the exec it is handed.
  const nodeStub = (major) => `#!${BASH}\nif [[ "$1" == -p ]]; then echo ${major}; exit 0; fi\necho "node-ran $*" >> ${log}\necho "node-ran $*"\n`;
  const writeNode = (major) => fs.writeFileSync(path.join(bin, "node"), nodeStub(major), { mode: 0o755 });
  if (node !== null) writeNode(node);
  // What the package manager "installs": the stub is written now and copied into PATH by it.
  const pending = path.join(dir, "node.pending");
  fs.writeFileSync(pending, nodeStub(18), { mode: 0o755 });
  if (pm) {
    fs.writeFileSync(path.join(bin, pm), `#!${BASH}\necho "${pm} $*" >> ${log}\n` +
      (pmFails ? "exit 100\n" : `if [[ "$1" == install ]]; then ${CP} -p ${pending} ${bin}/node; fi\n`), { mode: 0o755 });
  }
  const run = (args, env = {}) => {
    const r = spawnSync(BASH, [PEER, ...args], { env: { PATH: bin, ...env }, input: "" });
    return { rc: r.status, out: r.stdout.toString(), err: r.stderr.toString(), calls: fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "" };
  };
  return { run, done: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test("no node, any command: exit 69 naming the exact install command, and nothing is installed", () => {
  const b = box();
  const r = b.run(["status"], { A2A_TEST_ROOT: "1" });
  assert.equal(r.rc, 69);
  assert.match(r.err, /node was not found/);
  assert.match(r.err, /sudo apt-get install -y nodejs/);
  assert.match(r.err, /sudo 5dive peer setup --yes/);
  assert.equal(r.calls, "", "a non-setup command never installs");
  b.done();
});

test("no node, typed as `5dive a2a` (DIVE-5070): the setup hint names the verb that was typed", () => {
  const b = box();
  const r = b.run(["status"], { A2A_TEST_ROOT: "1", FIVEDIVE_VERB: "a2a" });
  assert.equal(r.rc, 69);
  assert.match(r.err, /^5dive a2a: needs Node\.js/m);
  assert.match(r.err, /sudo 5dive a2a setup --yes/);
  b.done();
});

test("no node, setup without --yes and no terminal: refuses, installs nothing (the owner has not agreed)", () => {
  const b = box();
  const r = b.run(["setup", "--domain=x.example.com"], { A2A_TEST_ROOT: "1" });
  assert.equal(r.rc, 69);
  assert.equal(r.calls, "");
  b.done();
});

test("no node, setup --yes as root: installs nodejs from apt, then runs setup with the same arguments", () => {
  const b = box();
  const r = b.run(["setup", "--domain=x.example.com", "--yes"], { A2A_TEST_ROOT: "1" });
  assert.equal(r.rc, 0, r.err);
  assert.match(r.calls, /^apt-get update -qq$/m);
  assert.match(r.calls, /^apt-get install -y nodejs$/m);
  assert.match(r.out, /node-ran \S+\/a2a\/lib\/cli\.mjs setup --domain=x\.example\.com --yes/);
  b.done();
});

test("no node, setup --yes on dnf: installs with dnf", () => {
  const b = box({ pm: "dnf" });
  const r = b.run(["setup", "--yes"], { A2A_TEST_ROOT: "1" });
  assert.equal(r.rc, 0, r.err);
  assert.match(r.calls, /^dnf install -y nodejs$/m);
  b.done();
});

test("no node, setup --yes but not root: nothing is installed", () => {
  const b = box();
  const r = b.run(["setup", "--yes"]);
  assert.equal(r.rc, 69);
  assert.equal(r.calls, "");
  b.done();
});

test("the install fails: exit 69, says so, and never runs the CLI", () => {
  const b = box({ pmFails: true });
  const r = b.run(["setup", "--yes"], { A2A_TEST_ROOT: "1" });
  assert.equal(r.rc, 69);
  assert.match(r.err, /apt-get install -y nodejs failed/);
  assert.doesNotMatch(r.calls, /node-ran/);
  b.done();
});

test("node too old: exit 69 naming the version, and setup --yes does not try the distro package", () => {
  const b = box({ node: 12 });
  const r = b.run(["setup", "--yes"], { A2A_TEST_ROOT: "1" });
  assert.equal(r.rc, 69);
  assert.match(r.err, /found 12/);
  assert.match(r.err, /nodejs\.org/);
  assert.equal(r.calls, "");
  b.done();
});

test("no node and no known package manager: points at nodejs.org", () => {
  const b = box({ pm: null });
  const r = b.run(["setup", "--yes"], { A2A_TEST_ROOT: "1" });
  assert.equal(r.rc, 69);
  assert.match(r.err, /nodejs\.org/);
  b.done();
});

test("node 18+: straight through to the CLI, nothing installed", () => {
  const b = box({ node: 22 });
  const r = b.run(["status"]);
  assert.equal(r.rc, 0, r.err);
  assert.match(r.out, /node-ran \S+cli\.mjs status/);
  assert.doesNotMatch(r.calls, /apt-get/);
  b.done();
});

// ---- the skill -----------------------------------------------------------------------------

const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "a2a/.claude-plugin/plugin.json"), "utf8"));
const skillDir = path.join(ROOT, "a2a/skills");
const skill = fs.readFileSync(path.join(skillDir, "message-agents/SKILL.md"), "utf8");
const region = (text) => {
  const b = "<!-- 5dive:a2a:begin -->", e = "<!-- 5dive:a2a:end -->";
  const i = text.indexOf(b), j = text.indexOf(e);
  assert.ok(i >= 0 && j > i, "delimited by the 5dive:a2a markers the CLI installs by");
  return text.slice(i, j + e.length);
};

test("the skill is declared: an undeclared skills/ dir is inert (plugin contract §2)", () => {
  assert.ok(manifest.fivedive.capabilities.includes("skill"));
  assert.ok(manifest.fivedive.capabilities.includes("verb"));
  assert.deepEqual(fs.readdirSync(skillDir), ["message-agents"]);
});

test("the skill has a name matching its folder and a description that says when to use it", () => {
  const fm = /^---\n([\s\S]*?)\n---\n/.exec(skill);
  assert.ok(fm, "front matter");
  assert.match(fm[1], /^name: message-agents$/m);
  const desc = /^description: (.+)$/m.exec(fm[1]);
  assert.ok(desc && /another box/i.test(desc[1]) && /Use when/.test(desc[1]));
});

test("the skill teaches every agent-side command, the approval rule and the board", () => {
  for (const cmd of ["sudo 5dive a2a send <nick>", "--message-file=-", "--reply-to=", "sudo 5dive a2a inbox", "sudo 5dive a2a contacts ls", "sudo 5dive a2a card"]) {
    assert.ok(skill.includes(cmd), `names ${cmd}`);
  }
  assert.match(skill, /never approves/);
  assert.match(skill, /board as a task/);
  assert.match(skill, /from=a2a-<nick>/);
  assert.match(skill, /sudo 5dive a2a contacts add/, "a refusal names the owner's command");
});

test("every peer subcommand the skill names exists in the CLI", async () => {
  const cli = fs.readFileSync(path.join(ROOT, "a2a/lib/cli.mjs"), "utf8");
  const table = /const table = \{([\s\S]*?)\};/.exec(cli)[1];
  const known = new Set([...table.matchAll(/(\w+): cmd/g)].map((m) => m[1]));
  const named = new Set([...skill.matchAll(/5dive (?:a2a|peer) ([a-z]+)/g)].map((m) => m[1]));
  for (const n of named) assert.ok(known.has(n), `peer ${n} is a real subcommand`);
});

test("AGENTS.md carries the skill's workflow byte for byte (other harnesses read that file)", () => {
  const agents = fs.readFileSync(path.join(ROOT, "a2a/AGENTS.md"), "utf8");
  assert.equal(region(agents), region(skill));
});
