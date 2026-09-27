// DIVE-5078: the dashboard's a2a settings page reads and writes through these verbs, as the
// owner (shelld's cgroup). What it needs that the terminal did not: every seat with its inbox
// state, the allowlist and the last delivery in one `status --json`, and a contact add (and a
// repin) that shows the key BEFORE it is trusted: `--check` writes nothing, and the write passes
// `--expect-did=<the key the owner saw>` so a card that changed in between is refused.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { generateKey, makeCard } from "../a2a/lib/core.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, "..", "a2a", "bin", "peer");
const at = (a, b) => [a, b].join("@");
const SHELLD = "0::/system.slice/shelld.service\n";
const DEV_UNIT = "0::/system.slice/system-5dive\\x2dagent.slice/" + at("5dive-agent", "dev") + ".service\n";
const DOMAIN = "settings-box.example.com";
const LUCA = at("luca", "b.example.com");
const OWNER = { user: "claude", uid: 1000, cgroup: SHELLD };

function box() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-settings-"));
  const etc = path.join(dir, "etc"), v = path.join(dir, "var");
  fs.writeFileSync(path.join(dir, "agents.json"), JSON.stringify({ agents: { claude: {}, dev: {}, ops: {} } }));
  fs.writeFileSync(path.join(dir, "passwd"), "root:x:0:0::/root:/bin/bash\nclaude:x:1000:1000::/home/claude:/bin/bash\nagent-dev:x:1101:1101::/home/agent-dev:/bin/bash\n");
  fs.writeFileSync(path.join(dir, "provisioning.env"), `FIVE_DOMAIN=${DOMAIN}\n`);
  const card = (key) => {
    const f = path.join(dir, `card-${Math.random().toString(36).slice(2)}.json`);
    fs.writeFileSync(f, JSON.stringify(makeCard({ name: "luca", domain: "b.example.com", inbox: "https://b.example.com/openagent/inbox", privatePem: key.privatePem })));
    return f;
  };
  const run = (args, { user, uid, cgroup } = OWNER) => {
    fs.writeFileSync(path.join(dir, "cgroup"), cgroup);
    const env = {
      PATH: process.env.PATH, A2A_TEST_ROOT: "1", A2A_ETC: etc, A2A_VAR: v,
      A2A_AGENTS_JSON: path.join(dir, "agents.json"), A2A_PASSWD: path.join(dir, "passwd"),
      A2A_PROVISIONING_ENV: path.join(dir, "provisioning.env"), A2A_CGROUP: path.join(dir, "cgroup"),
      SUDO_USER: user, SUDO_UID: String(uid),
    };
    const r = spawnSync("bash", [BIN, ...args], { env, encoding: "utf8" });
    let json = null;
    try { json = JSON.parse(r.stdout); } catch { /* text mode */ }
    return { rc: r.status, out: r.stdout, err: r.stderr, json };
  };
  const contacts = () => { try { return JSON.parse(fs.readFileSync(path.join(etc, "contacts.json"), "utf8")).contacts; } catch { return []; } };
  const setUp = run(["setup", "--no-system"]);
  assert.equal(setUp.rc, 0, setUp.err);
  return { dir, v, run, card, contacts, done: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test("status --json lists every seat with its inbox state, the allowlist and the last delivery", () => {
  const b = box();
  try {
    assert.equal(b.run(["enable", "dev"]).rc, 0);
    let s = b.run(["status", "--json"]).json;
    assert.deepEqual(s.seats.map((x) => [x.agent, x.inbox, x.address]), [
      ["claude", false, at("claude", DOMAIN)], ["dev", true, at("dev", DOMAIN)], ["ops", false, at("ops", DOMAIN)],
    ], "every registered seat, on or off, from the config");
    assert.match(s.seats[1].did, /^did:key:z/);
    assert.equal(s.seats[0].did, null, "a seat never turned on has no key yet");
    assert.deepEqual(s.allowlist, { enabled: false, homes: [] });
    assert.equal(s.last_delivery, null);

    // Turned off: still listed, inbox false, key kept (enable brings the same address back).
    assert.equal(b.run(["disable", "dev"]).rc, 0);
    s = b.run(["status", "--json"]).json;
    assert.equal(s.seats.find((x) => x.agent === "dev").inbox, false);
    assert.match(s.seats.find((x) => x.agent === "dev").did, /^did:key:z/);

    fs.appendFileSync(path.join(b.v, "events.log"), [
      JSON.stringify({ at: 1000, event: "delivered", agent: "dev" }),
      JSON.stringify({ at: 2000, event: "delivered", agent: "claude" }),
      JSON.stringify({ at: 3000, event: "deliver-failed", agent: "ops" }),
      "{ torn",
    ].join("\n"));
    assert.deepEqual(b.run(["status", "--json"]).json.last_delivery, { at: 2000, agent: "claude" }, "the newest delivered line; a failure is not a delivery");
    assert.match(b.run(["status"]).out, /last delivery: 1970-01-01T00:00:02\.000Z to claude/);
  } finally { b.done(); }
});

test("a setup re-run lists the agents that already have an inbox (not 'No agent has an inbox yet')", () => {
  const b = box();
  try {
    assert.equal(b.run(["enable", "dev"]).rc, 0);
    const r = b.run(["setup", "--no-system"]);
    assert.equal(r.rc, 0, r.err);
    assert.doesNotMatch(r.out, /No agent has an inbox yet/);
    assert.match(r.out, new RegExp(`Agents with an inbox:\\n  ${at("dev", DOMAIN).replace(/\./g, "\\.")}  did:key:z`));
  } finally { b.done(); }
});

test("contacts add --check shows the key and writes nothing; --expect-did adds only that key", () => {
  const b = box();
  try {
    const luca = generateKey(), other = generateKey();
    const card = b.card(luca);
    const c = b.run(["contacts", "add", LUCA, `--card-file=${card}`, "--check", "--json"]);
    assert.equal(c.rc, 0, c.err);
    assert.equal(c.json.check, true);
    assert.equal(c.json.did, luca.did);
    assert.equal(c.json.address, LUCA);
    assert.equal(c.json.contact, null);
    assert.deepEqual(b.contacts(), [], "a check pins nothing");

    // The card changed between the check and the confirm: refused, nothing pinned.
    const swapped = b.run(["contacts", "add", LUCA, `--card-file=${b.card(other)}`, `--expect-did=${luca.did}`]);
    assert.equal(swapped.rc, 1, swapped.out);
    assert.match(swapped.err, /not the key you confirmed/);
    assert.deepEqual(b.contacts(), []);

    const ok = b.run(["contacts", "add", LUCA, `--card-file=${card}`, `--expect-did=${luca.did}`, "--json"]);
    assert.equal(ok.rc, 0, ok.err);
    assert.deepEqual(b.contacts().map((x) => [x.nick, x.address, x.did]), [["luca", LUCA, luca.did]]);

    // Checked again once added: the page shows it is already there.
    const again = b.run(["contacts", "add", LUCA, `--card-file=${card}`, "--check", "--json"]);
    assert.equal(again.json.contact.nick, "luca");
  } finally { b.done(); }
});

test("repin --check shows old and new keys and writes nothing; --yes --expect-did repins only that key", () => {
  const b = box();
  try {
    const luca = generateKey(), rebuilt = generateKey(), third = generateKey();
    assert.equal(b.run(["contacts", "add", LUCA, `--card-file=${b.card(luca)}`]).rc, 0);
    const card = b.card(rebuilt);
    const c = b.run(["contacts", "repin", "luca", `--card-file=${card}`, "--check", "--json"]);
    assert.equal(c.rc, 0, c.err);
    assert.deepEqual([c.json.contact.did, c.json.did, c.json.same], [luca.did, rebuilt.did, false]);
    assert.equal(b.contacts()[0].did, luca.did, "a check repins nothing");

    const swapped = b.run(["contacts", "repin", "luca", `--card-file=${b.card(third)}`, "--yes", `--expect-did=${rebuilt.did}`]);
    assert.equal(swapped.rc, 1);
    assert.match(swapped.err, /not the key you confirmed/);
    assert.equal(b.contacts()[0].did, luca.did);

    const ok = b.run(["contacts", "repin", "luca", `--card-file=${card}`, "--yes", `--expect-did=${rebuilt.did}`]);
    assert.equal(ok.rc, 0, ok.err);
    assert.equal(b.contacts()[0].did, rebuilt.did);
  } finally { b.done(); }
});

test("an agent seat still cannot check, add, repin or change the allowlist (rc 77)", () => {
  const b = box();
  try {
    const luca = generateKey();
    const seat = { user: "agent-dev", uid: 1101, cgroup: DEV_UNIT };
    for (const args of [
      ["contacts", "add", LUCA, `--card-file=${b.card(luca)}`, "--check"],
      ["contacts", "add", LUCA, `--card-file=${b.card(luca)}`, `--expect-did=${luca.did}`],
      ["enable", "dev"],
      ["allow", "on"],
    ]) {
      const r = b.run(args, seat);
      assert.equal(r.rc, 77, `${args.join(" ")}: ${r.out}${r.err}`);
      assert.match(r.err, /only the box owner can do this/);
    }
    assert.deepEqual(b.contacts(), []);
    // Reading is allowed: the seat sees the same status the page does.
    assert.equal(b.run(["status", "--json"], seat).rc, 0);
  } finally { b.done(); }
});
