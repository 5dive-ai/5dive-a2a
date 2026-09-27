// DIVE-5064, the root half (driven by tests/ownership.sh, as root, inside a private mount
// namespace where /etc/5dive-a2a and /var/lib/5dive-a2a are scratch binds). The real CLI
// runs as root and rewrites the trust root; the real inbox runs as the non-root service
// user and must still read it. The node suites run everything as one uid, so they cannot
// see an ownership bug: this is the arm that can.
//
// env: LIB (a copy of a2a/lib the service user can read), NODE (a node it can run),
//      SVC (the service user), SENTINEL (a file that exists only in the scratch etc).
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const { LIB, NODE, SVC, SENTINEL } = process.env;
const state = await import(path.join(LIB, "state.mjs"));
const core = await import(path.join(LIB, "core.mjs"));
const cli = await import(path.join(LIB, "cli.mjs"));

let failed = 0;
const arm = (ok, name, detail = "") => { console.log(`${ok ? "ok  " : "FAIL"}  ${name}${ok || !detail ? "" : "  -- " + detail}`); if (!ok) failed++; };

const p = state.paths();
// Never write a real box's trust root: the scratch bind must be what root sees here.
if (process.geteuid() !== 0 || !fs.existsSync(path.join(p.etc, path.basename(SENTINEL)))) {
  console.log("FAIL  not root, or /etc/5dive-a2a is not the scratch bind: refusing to write");
  process.exit(2);
}
const svcGid = Number(spawnSync("id", ["-g", SVC], { encoding: "utf8" }).stdout.trim());
const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("SUDO_") && !k.startsWith("A2A_")));
const peer = (...args) => spawnSync(NODE, [path.join(LIB, "cli.mjs"), ...args], { encoding: "utf8", env });

// A set-up box: agent main has an inbox, no contacts yet, and the service owns what it
// should (the same ownTree `peer setup` runs).
const main = core.generateKey(), luca = core.generateKey();
for (const d of [p.keys, p.cards, p.spool]) fs.mkdirSync(d, { recursive: true });
fs.writeFileSync(path.join(p.keys, "main.key"), main.privatePem, { mode: 0o600 });
state.saveConfig({ domain: "a.example.com", inbox_url: "https://a.example.com/openagent/inbox", allowlist: { enabled: false, homes: [] }, agents: { main: { inbox: true, did: main.did } } }, p);
state.saveContacts([], p);
cli.ownTree(p, SVC);
const card = path.join(path.dirname(SENTINEL), "luca-card.json");
fs.writeFileSync(card, JSON.stringify(core.makeCard({ name: "luca", domain: "b.example.com", inbox: "https://b.example.com/openagent/inbox", privatePem: luca.privatePem, signedAt: "2026-09-27T09:00:00Z" })));

const owned = (f) => { const st = fs.statSync(f); return st.uid === 0 && st.gid === svcGid && (st.mode & 0o777) === 0o640; };
const desc = (f) => { const st = fs.statSync(f); return `uid ${st.uid} gid ${st.gid} mode ${(st.mode & 0o777).toString(8)} (want 0:${svcGid} 640)`; };

// 1. root rewrites both files through the real verbs.
let r = peer("contacts", "add", ["luca", "b.example.com"].join("@"), `--card-file=${card}`);
arm(r.status === 0, "root: peer contacts add", r.stderr);
r = peer("allow", "off");
arm(r.status === 0, "root: peer allow off (a config rewrite)", r.stderr);
arm(owned(p.contacts), `contacts.json is still root:${SVC} 0640 after contacts add`, desc(p.contacts));
arm(owned(p.config), `config.json is still root:${SVC} 0640 after a config write`, desc(p.config));
r = peer("status");
arm(r.status === 0 && !/PROBLEM/.test(r.stdout), "peer status: no problem", r.stdout + r.stderr);

// 2. the real inbox, as the service user, stores the contact's message.
const inbox = spawn("setpriv", [`--reuid=${SVC}`, `--regid=${SVC}`, "--init-groups", NODE, "--input-type=module", "-e",
  `const { createInbox } = await import(${JSON.stringify(path.join(LIB, "server.mjs"))});
   createInbox().listen(0, "127.0.0.1", function () { console.log(this.address().port); });`], { env, stdio: ["ignore", "pipe", "inherit"] });
const port = await new Promise((resolve) => { inbox.stdout.once("data", (d) => resolve(Number(String(d).trim()))); inbox.once("exit", () => resolve(0)); });
const at = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
const post = () => fetch(`http://127.0.0.1:${port}/openagent/inbox`, {
  method: "POST", headers: { "content-type": core.CONTENT_TYPE },
  body: JSON.stringify(core.signEnvelope(core.makeEnvelope({ id: core.ulid(), from: luca.did, to: [main.did], body: "arm", at: at() }), luca.privatePem)),
}).then((x) => x.status, () => 0);
const spooled = () => fs.readdirSync(p.spool).filter((f) => f.endsWith(".json")).length;
try {
  arm(port > 0, `inbox runs as ${SVC}`);
  const s1 = await post();
  arm(s1 === 202 && spooled() === 1, "a contact's message is STORED by the non-root inbox (not dropped as a stranger)", `status ${s1}, spooled ${spooled()}`);

  // 3. an install an older version left broken (root:root): loud, closed, and healed by the next write.
  fs.chownSync(p.contacts, 0, 0);
  r = peer("status");
  arm(r.status === 1 && /inbox cannot read contacts\.json/.test(r.stdout), "peer status fails loudly on a root:root contacts.json", r.stdout + r.stderr);
  const s2 = await post();
  arm(s2 === 503 && spooled() === 1, "the inbox answers 503 (not a silent 202) while it cannot read contacts", `status ${s2}`);
  r = peer("contacts", "mute", "luca");
  r = peer("contacts", "unmute", "luca");
  arm(owned(p.contacts), "the next contacts write heals a root:root file", desc(p.contacts));
  const s3 = await post();
  arm(s3 === 202 && spooled() === 2, "stored again after the heal, with no inbox restart", `status ${s3}, spooled ${spooled()}`);
  const ev = fs.readFileSync(p.events, "utf8");
  arm(/"inbox-cannot-read"/.test(ev), "events.log carries inbox-cannot-read for the owner");

  // 4. DIVE-5071: a sent file is READ as the calling seat (here `nobody`), never as root, and the
  // copy is served by the non-root inbox. Root reading the path would let any seat mail out
  // /etc/shadow or this box's own signing key.
  const seat = { kind: "seat", agent: "main", user: "nobody" };
  const cfg = state.loadConfig(p);
  const opts = { now: Date.now(), ttl: 3600e3, id: core.ulid(), to: "luca@b.example.com" };
  const readable = path.join(path.dirname(LIB), "readable.bin");
  fs.writeFileSync(readable, "a file the seat can read\n", { mode: 0o644 });
  const secret = path.join(path.dirname(LIB), "root-only.bin");
  fs.writeFileSync(secret, "root only\n", { mode: 0o600 });
  const refused = async (src) => { try { await cli.stageFile(p, cfg, seat, src, opts); return ""; } catch (e) { return String(e.message); } };
  for (const src of ["/etc/shadow", path.join(p.keys, "main.key"), secret]) {
    const why = await refused(src);
    arm(/Permission denied/.test(why), `a seat cannot send ${src === secret ? "a root-only 0600 file" : src} (read as the seat, not root)`, why || "it was staged");
  }
  const staged = state.listFiles(p);
  arm(staged.length === 0, "a refused file leaves nothing behind", `${staged.length} staged`);
  let f = null;
  try { f = await cli.stageFile(p, cfg, seat, readable, opts); } catch (e) { arm(false, "a seat sends a file it can read", e.message); }
  if (f) {
    const disk = path.join(p.files, f.token, f.name);
    const st = fs.statSync(disk);
    arm(st.uid === Number(spawnSync("id", ["-u", SVC], { encoding: "utf8" }).stdout.trim()) && (st.mode & 0o777) === 0o640, `the copy is ${SVC}-owned 0640`, desc(disk));
    const res = await fetch(`http://127.0.0.1:${port}/openagent/files/${f.token}/${f.name}`).then(async (x) => ({ status: x.status, body: await x.text() }), () => ({ status: 0 }));
    arm(res.status === 200 && res.body === "a file the seat can read\n", `the non-root inbox serves it`, `status ${res.status}`);
  }
} finally { inbox.kill(); }

console.log(failed ? `${failed} arm(s) failed` : "all arms pass");
process.exit(failed ? 1 : 0);
