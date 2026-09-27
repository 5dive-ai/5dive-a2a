// DIVE-5083: a standard seat's sudo lists exact 5dive commands and a2a was not among them, so the
// seat received messages but `sudo 5dive peer send` asked it for a password. Every agent with an
// inbox now gets the SEAT verbs in /etc/sudoers.d/5dive-a2a; the owner verbs are not in it.
// These arms run the CLI as a plain user through the seams (the file lands in a scratch dir).
// tests/grant.sh grades the same file against the real sudo, as root, in a private namespace.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { sudoersText, SEAT_COMMANDS, seatUser, SUDOERS_FILE } from "../a2a/lib/cli.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, "..", "a2a", "bin", "peer");
const DOMAIN = "grant-box.example.com";
const at = (a, b) => [a, b].join("@");
const AGENT_UNIT = `0::/system.slice/system-5dive\\x2dagent.slice/${at("5dive-agent", "head")}.service\n`;
const visudo = ["/usr/sbin/visudo", "/usr/bin/visudo"].find((f) => fs.existsSync(f));

// `head` and `ops` are agents with accounts, `ghost` is registered with no account yet.
function box() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-grant-"));
  const etc = path.join(dir, "etc"), v = path.join(dir, "var"), sud = path.join(dir, "sudoers.d");
  fs.mkdirSync(sud);
  fs.writeFileSync(path.join(dir, "agents.json"), JSON.stringify({ agents: { head: {}, ops: {}, ghost: {}, claude: {} } }));
  fs.writeFileSync(path.join(dir, "passwd"), "root:x:0:0::/root:/bin/bash\nclaude:x:1000:1000::/home/claude:/bin/bash\n" +
    "agent-head:x:1101:1101::/home/agent-head:/bin/bash\nagent-ops:x:1102:1102::/home/agent-ops:/bin/bash\n");
  fs.writeFileSync(path.join(dir, "cgroup"), AGENT_UNIT);
  const file = path.join(sud, "5dive-a2a");
  const run = (args, { user, uid, visudoBin } = {}) => {
    const env = {
      PATH: process.env.PATH, A2A_TEST_ROOT: "1", A2A_ETC: etc, A2A_VAR: v, A2A_SUDOERS: file,
      A2A_AGENTS_JSON: path.join(dir, "agents.json"), A2A_PASSWD: path.join(dir, "passwd"), A2A_CGROUP: path.join(dir, "cgroup"),
    };
    if (visudoBin) env.A2A_VISUDO = visudoBin;
    if (user) { env.SUDO_USER = user; env.SUDO_UID = String(uid); }
    const r = spawnSync("bash", [BIN, ...args], { env, encoding: "utf8" });
    return { rc: r.status, out: r.stdout, err: r.stderr };
  };
  const grant = () => { try { return fs.readFileSync(file, "utf8"); } catch { return null; } };
  const users = () => (grant() || "").split("\n").filter((l) => l && !l.startsWith("#")).map((l) => l.split(" ")[0]);
  return { dir, file, sud, run, grant, users, done: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test("the grant lists the seat verbs under both names, and no owner verb", () => {
  const text = sudoersText(["agent-head"]);
  const line = text.split("\n").find((l) => l.startsWith("agent-head "));
  assert.match(line, /^agent-head ALL=\(root\) NOPASSWD: /, "runas root only, never (ALL)");
  const cmds = line.replace(/^[^:]*: /, "").split(", ");
  assert.equal(cmds.length, SEAT_COMMANDS.length * 2);
  for (const verb of ["peer", "a2a"]) {
    for (const c of ["send *", "inbox", "files ls", "files rm *", "contacts ls", "card", "status"]) assert.ok(cmds.includes(`/usr/local/bin/5dive ${verb} ${c}`), `${verb} ${c}`);
  }
  for (const c of cmds) {
    assert.match(c, /^\/usr\/local\/bin\/5dive (peer|a2a) (send|inbox|files|contacts|card|status)( |$)/, c);
    assert.doesNotMatch(c, /setup|enable|disable|uninstall|allow|limits|_tick|add|repin|mute|contacts rm|rounds/, c);
    // sudo-rs accepts one wildcard shape: a bare trailing `*` (as the 5dive CLI's own grants).
    assert.ok(!c.slice(0, -1).includes("*"), `only a trailing wildcard: ${c}`);
  }
  // `files` alone is `files ls`; `files *` would take in `files limits --max-file=…`.
  assert.ok(!cmds.some((c) => /(files|contacts) \*$/.test(c)));
});

test("the generated file passes visudo", { skip: !visudo && "no visudo on this host" }, () => {
  const b = box();
  try {
    fs.writeFileSync(b.file, sudoersText(["agent-head", "agent-ops", "claude"]), { mode: 0o440 });
    const r = spawnSync(visudo, ["-cf", b.file], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
  } finally { b.done(); }
});

test("seatUser is the account agentForUser maps back from", () => {
  assert.equal(seatUser("head"), "agent-head");
  assert.equal(seatUser("claude"), "claude");
  assert.equal(SUDOERS_FILE, "/etc/sudoers.d/5dive-a2a", "no dot in the name: sudo skips files in sudoers.d that have one");
});

test("setup, enable and disable keep the grant equal to the agents with an inbox; uninstall removes it", { skip: !visudo && "no visudo on this host" }, () => {
  const b = box();
  try {
    let r = b.run(["setup", "--no-system", `--domain=${DOMAIN}`, "--agents=head"]);
    assert.equal(r.rc, 0, r.err);
    assert.match(r.out, /sudo grant: agent-head may run/);
    assert.deepEqual(b.users(), ["agent-head"]);
    assert.equal(fs.statSync(b.file).mode & 0o777, 0o440);

    r = b.run(["enable", "ops"]);
    assert.equal(r.rc, 0, r.err);
    assert.deepEqual(b.users(), ["agent-head", "agent-ops"]);

    // A registered agent with no unix account yet gets an inbox and no sudoers line naming nobody.
    r = b.run(["enable", "ghost"]);
    assert.equal(r.rc, 0, r.err);
    assert.deepEqual(b.users(), ["agent-head", "agent-ops"]);

    r = b.run(["disable", "head"]);
    assert.equal(r.rc, 0, r.err);
    assert.match(r.out, /can no longer run 5dive peer as root/);
    assert.deepEqual(b.users(), ["agent-ops"]);

    r = b.run(["disable", "ops"]);
    assert.equal(r.rc, 0, r.err);
    r = b.run(["disable", "ghost"]);
    assert.equal(r.rc, 0, r.err);
    assert.equal(b.grant(), null, "no agent with an inbox: no file at all");

    // A box set up before DIVE-5083 gets its grant from a re-run of setup, with no flags.
    b.run(["enable", "head"]);
    fs.rmSync(b.file);
    r = b.run(["setup", "--no-system"]);
    assert.equal(r.rc, 0, r.err);
    assert.deepEqual(b.users(), ["agent-head"]);

    // Uninstall revokes it first; the rest of uninstall needs real root (systemd), so its rc is not graded here.
    r = b.run(["uninstall", "--keep-plugin"]);
    assert.equal(b.grant(), null, r.out + r.err);
    assert.deepEqual(fs.readdirSync(b.sud), [], "and no temp file left behind");
  } finally { b.done(); }
});

test("a grant visudo refuses is never installed, and the old one stays", () => {
  const b = box();
  try {
    assert.equal(b.run(["setup", "--no-system", `--domain=${DOMAIN}`, "--agents=head"], { visudoBin: "true" }).rc, 0);
    const before = b.grant();
    const r = b.run(["enable", "ops"], { visudoBin: "false" });
    assert.notEqual(r.rc, 0);
    assert.match(r.err, /failed visudo, so it was not installed/);
    assert.equal(b.grant(), before);
    assert.deepEqual(fs.readdirSync(b.sud), ["5dive-a2a"], "the rejected temp file is removed");
  } finally { b.done(); }
});

test("a seat running the owner verbs as root is still refused (the grant is not the only wall)", () => {
  const b = box();
  try {
    assert.equal(b.run(["setup", "--no-system", `--domain=${DOMAIN}`, "--agents=head"], { visudoBin: "true" }).rc, 0);
    const seat = { user: "agent-head", uid: 1101 };
    for (const args of [["contacts", "add", at("x", "example.com")], ["files", "limits", "--max-file=1G"], ["enable", "ops"], ["disable", "head"], ["setup"], ["uninstall"], ["allow", "on"]]) {
      const r = b.run(args, seat);
      assert.equal(r.rc, 77, `${args.join(" ")}: ${r.err}`);
      assert.match(r.err, /only the box owner can do this, not an agent \(called from agent-head\)/);
    }
    assert.deepEqual(b.users(), ["agent-head"], "nothing the seat ran changed the grant");
    for (const args of [["status"], ["inbox"], ["files", "ls"], ["contacts", "ls"], ["card"]]) {
      const r = b.run(args, seat);
      assert.equal(r.rc, 0, `${args.join(" ")}: ${r.err}`);
    }
  } finally { b.done(); }
});

test("card takes an agent name, never a path (a seat runs it as root)", () => {
  const b = box();
  try {
    assert.equal(b.run(["setup", "--no-system", `--domain=${DOMAIN}`, "--agents=head"], { visudoBin: "true" }).rc, 0);
    fs.writeFileSync(path.join(b.dir, "secret.json"), JSON.stringify({ token: "hunter2" }));
    const seat = { user: "agent-head", uid: 1101 };
    for (const name of ["../../secret", "../secret", "/etc/passwd", "head/../../secret", ".hidden"]) {
      const r = b.run(["card", name, "--json"], seat);
      assert.equal(r.rc, 64, `${name}: ${r.out}${r.err}`);
      assert.doesNotMatch(r.out + r.err, /hunter2/);
    }
    assert.equal(b.run(["card", "head"], seat).rc, 0);
  } finally { b.done(); }
});
