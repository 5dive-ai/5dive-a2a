// DIVE-5073: the owner's dashboard runs as `claude` (shelld, a system service that calls
// `sudo 5dive …`), and `claude` is an agent seat on most boxes, so "Finish setup" was refused
// with rc 77 on every box. The owner is now told apart by the process's cgroup, and a
// first-time setup with no arguments finds the box's domain and turns on no agent.
//
// The dashboard arms run the PUBLISHED setup line (plugin.json fivedive.setup.command) the way
// `5dive plugin setup` runs it from the dashboard: as `claude`, through sudo (SUDO_USER=claude,
// SUDO_UID=claude's uid), inside shelld's cgroup, with no arguments of its own.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { cgroupPath, ownerSurface, provisionedDomain } from "../a2a/lib/cli.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, "..", "a2a", "bin", "peer");
const MANIFEST = JSON.parse(fs.readFileSync(path.join(HERE, "..", "a2a", ".claude-plugin", "plugin.json"), "utf8"));
const at = (a, b) => [a, b].join("@");
const SHELLD = "0::/system.slice/shelld.service\n";
const agentUnitPath = (a) => "/system.slice/system-5dive\\x2dagent.slice/" + at("5dive-agent", a) + ".service";
const AGENT_UNIT = (a) => `0::${agentUnitPath(a)}\n`;
const DOMAIN = "fresh-box.example.com";

test("cgroupPath reads the unified line, and prefers name=systemd on a v1/hybrid host", () => {
  assert.equal(cgroupPath("0::/system.slice/shelld.service\n"), "/system.slice/shelld.service");
  assert.equal(cgroupPath("12:cpu:/\n1:name=systemd:/system.slice/shelld.service\n0::/\n"), "/system.slice/shelld.service");
  assert.equal(cgroupPath("0::/system.slice/a:b.service\n"), "/system.slice/a:b.service", "a colon inside the path is kept");
  assert.equal(cgroupPath("12:cpu:/foo\n"), null, "no systemd or unified line: unresolved, not guessed");
  assert.equal(cgroupPath(""), null);
});

test("ownerSurface: the dashboard and a login session are the owner; every agent unit is not", () => {
  for (const cg of ["/system.slice/shelld.service", "/user.slice/user-1000.slice/session-4.scope", "/user.slice/user-0.slice/session-c12.scope"]) {
    assert.equal(ownerSurface(cg), true, cg);
  }
  for (const cg of [
    agentUnitPath("dev"),
    agentUnitPath("claude"),
    "/system.slice/claude.service",
    "/user.slice/user-1000.slice/" + at("user", "1000") + ".service/app.slice/x.service",
    // Any user can create this one with `systemd-run --user --scope --unit=session-x`: not a login.
    "/user.slice/user-1000.slice/" + at("user", "1000") + ".service/app.slice/session-x.scope",
    "/user.slice/user-1000.slice/" + at("user", "1000") + ".service/session-x.scope",
    "/system.slice/shelld.service/child",
    "/system.slice/notshelld.service",
    "/",
    null,
  ]) {
    assert.equal(ownerSurface(cg), false, String(cg));
  }
});

test("provisionedDomain reads FIVE_DOMAIN from provisioning.env", () => {
  assert.equal(provisionedDomain(`FIVE_DOMAIN=${DOMAIN}\nFIVE_SERVER_NAME=x\n`), DOMAIN);
  assert.equal(provisionedDomain('export FIVE_DOMAIN="Box.Example.com"\n'), "box.example.com");
  assert.equal(provisionedDomain("FIVE_DOMAIN=\n"), null, "an empty value is no domain");
  assert.equal(provisionedDomain("FIVE_SERVER_NAME=x\n"), null);
});

// A fresh box: no a2a config yet, `claude` registered as an agent (as on most boxes), and an
// agent `dev`. The caller's cgroup is the one thing each arm changes.
function freshBox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-owner-"));
  const etc = path.join(dir, "etc"), v = path.join(dir, "var");
  fs.writeFileSync(path.join(dir, "agents.json"), JSON.stringify({ agents: { claude: {}, dev: {} } }));
  fs.writeFileSync(path.join(dir, "passwd"), "root:x:0:0::/root:/bin/bash\nclaude:x:1000:1000::/home/claude:/bin/bash\nagent-dev:x:1101:1101::/home/agent-dev:/bin/bash\n");
  fs.writeFileSync(path.join(dir, "provisioning.env"), `FIVE_DOMAIN=${DOMAIN}\nFIVE_SERVER_NAME=fresh-box\nFIVE_CLI_CANARY=\n`);
  const run = (args, { user, uid, cgroup }) => {
    fs.writeFileSync(path.join(dir, "cgroup"), cgroup);
    const env = {
      PATH: process.env.PATH, A2A_TEST_ROOT: "1", A2A_ETC: etc, A2A_VAR: v,
      A2A_AGENTS_JSON: path.join(dir, "agents.json"), A2A_PASSWD: path.join(dir, "passwd"),
      A2A_PROVISIONING_ENV: path.join(dir, "provisioning.env"), A2A_CGROUP: path.join(dir, "cgroup"),
    };
    if (user) { env.SUDO_USER = user; env.SUDO_UID = String(uid); }
    const r = spawnSync("bash", [BIN, ...args], { env, encoding: "utf8" });
    return { rc: r.status, out: r.stdout, err: r.stderr };
  };
  const config = () => { try { return JSON.parse(fs.readFileSync(path.join(etc, "config.json"), "utf8")); } catch { return null; } };
  return { dir, run, config, done: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

// The published line, minus `sudo 5dive peer`: what the dashboard's setup runs is exactly these
// arguments. --no-system keeps the arm off systemd and the web server (not root here).
function publishedArgs() {
  const words = MANIFEST.fivedive.setup.command.trim().split(/\s+/);
  assert.deepEqual(words.slice(0, 3), ["sudo", "5dive", "peer"], "setup.command is still `sudo 5dive peer …` (the name every CLI has)");
  return words.slice(3);
}

test("the dashboard's Finish setup (claude via sudo, in shelld): ok on a fresh box, domain found, no agent turned on", () => {
  const b = freshBox();
  try {
    const args = publishedArgs();
    assert.deepEqual(args, ["setup"], "the published line passes no --domain or --agents: setup must not need them");
    const r = b.run([...args, "--no-system"], { user: "claude", uid: 1000, cgroup: SHELLD });
    assert.equal(r.rc, 0, r.err);
    const c = b.config();
    assert.equal(c.domain, DOMAIN, "the domain is the box's own, from provisioning.env");
    assert.equal(c.inbox_url, `https://${DOMAIN}/openagent/inbox`);
    assert.deepEqual(c.agents, {}, "no agent gets an inbox until the owner picks one");
    assert.match(r.out, /No agent has an inbox yet\. Turn one on: sudo 5dive peer enable <agent>/);
    // The owner then turns one on, from the same dashboard.
    const e = b.run(["enable", "dev"], { user: "claude", uid: 1000, cgroup: SHELLD });
    assert.equal(e.rc, 0, e.err);
    assert.equal(b.config().agents.dev.inbox, true);
  } finally { b.done(); }
});

test("the same line from an agent's unit is still refused (rc 77), and writes nothing", () => {
  const b = freshBox();
  try {
    for (const [user, uid, unit] of [["claude", 1000, AGENT_UNIT("claude")], ["agent-dev", 1101, AGENT_UNIT("dev")], ["claude", 1000, "0::/system.slice/claude.service\n"]]) {
      const r = b.run([...publishedArgs(), "--no-system"], { user, uid, cgroup: unit });
      assert.equal(r.rc, 77, `${user} in ${unit.trim()}: ${r.err}`);
      assert.match(r.err, new RegExp(`only the box owner can do this, not an agent \\(called from ${user}\\)`));
      assert.equal(b.config(), null, "nothing was set up");
    }
  } finally { b.done(); }
});

test("an unreadable cgroup is not the owner (fail closed)", () => {
  const b = freshBox();
  try {
    const r = b.run(["setup", "--no-system"], { user: "claude", uid: 1000, cgroup: "" });
    assert.equal(r.rc, 77, r.err);
    assert.equal(b.config(), null);
  } finally { b.done(); }
});

test("a person logged in over ssh as claude (a session scope) is the owner", () => {
  const b = freshBox();
  try {
    const r = b.run(["setup", "--no-system"], { user: "claude", uid: 1000, cgroup: "0::/user.slice/user-1000.slice/session-7.scope\n" });
    assert.equal(r.rc, 0, r.err);
    assert.equal(b.config().domain, DOMAIN);
  } finally { b.done(); }
});

test("the dashboard surface grants owner verbs only: an agent seat is still who it is", () => {
  const b = freshBox();
  try {
    assert.equal(b.run(["setup", "--no-system", "--agents=dev"], { cgroup: AGENT_UNIT("x") }).rc, 0, "root with no SUDO_USER is the owner, as before");
    // agent-dev, reached through the dashboard's cgroup, asks for its own card: still the seat dev.
    const r = b.run(["card"], { user: "agent-dev", uid: 1101, cgroup: SHELLD });
    assert.equal(r.rc, 0, r.err);
    assert.ok(r.out.startsWith(at("dev", DOMAIN)), r.out);
  } finally { b.done(); }
});

test("this process's real /proc/self/cgroup parses to a path (the file the arms stand in for)", { skip: !fs.existsSync("/proc/self/cgroup") && "no /proc" }, () => {
  const cg = cgroupPath(fs.readFileSync("/proc/self/cgroup", "utf8"));
  assert.ok(cg === null || cg.startsWith("/"), String(cg));
});
