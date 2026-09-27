// DIVE-5071: files as expiring links served by the sender's own box. Two boxes in one process,
// as in e2e.test.mjs (real inbox servers on 127.0.0.1, the real CLI as sudo would call it,
// `5dive agent send` stubbed), plus the receiving agent's own download command, run as written.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createInbox } from "../a2a/lib/server.mjs";
import { fileStore, paths } from "../a2a/lib/state.mjs";
import { makeEnvelope, signEnvelope, fileShapeError, envelopeShapeError, safeFileName, parseDuration, parseSize } from "../a2a/lib/core.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, "..", "a2a", "lib", "cli.mjs");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-files-"));
const calls = path.join(root, "agent-send.log");
fs.writeFileSync(path.join(root, "5dive"), `#!/usr/bin/env bash
{ for a in "$@"; do case "$a" in --message-file=*) cat "\${a#--message-file=}"; printf '\\n';; esac; done; printf 'END\\n'; } >> ${JSON.stringify(calls)}
`, { mode: 0o755 });

function box(name, agent, domain, uid) {
  const dir = path.join(root, name);
  const etc = path.join(dir, "etc"), v = path.join(dir, "var");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "agents.json"), JSON.stringify({ agents: { [agent]: {} } }));
  fs.writeFileSync(path.join(dir, "passwd"), `root:x:0:0::/root:/bin/bash\nagent-${agent}:x:${uid}:${uid}::/home/agent-${agent}:/bin/bash\n`);
  fs.writeFileSync(path.join(dir, "cgroup"), "0::/system.slice/system-5dive\\x2dagent.slice/5dive-agent@" + agent + ".service\n");
  const env = { A2A_TEST_ROOT: "1", A2A_CGROUP: path.join(dir, "cgroup"), A2A_ETC: etc, A2A_VAR: v, A2A_AGENTS_JSON: path.join(dir, "agents.json"), A2A_PASSWD: path.join(dir, "passwd"), A2A_FIVEDIVE: path.join(root, "5dive"), A2A_TMP: root };
  const saved = { ...process.env };
  Object.assign(process.env, { A2A_ETC: etc, A2A_VAR: v });
  const p = paths();
  process.env.A2A_ETC = saved.A2A_ETC; process.env.A2A_VAR = saved.A2A_VAR;
  if (saved.A2A_ETC === undefined) delete process.env.A2A_ETC;
  if (saved.A2A_VAR === undefined) delete process.env.A2A_VAR;
  return { agent, domain, uid, dir, p, env };
}

const A = box("a", "main", "a.example.com", 1101);
const B = box("b", "luca", "b.example.com", 1201);

function run(b, args, { seat = false, env = {}, cwd } = {}) {
  const e = { PATH: process.env.PATH, ...b.env, ...env };
  if (seat) { e.SUDO_USER = `agent-${b.agent}`; e.SUDO_UID = String(b.uid); }
  return new Promise((resolve) => {
    const ch = spawn(process.execPath, [CLI, ...args], { env: e, cwd });
    let out = "", err = "";
    ch.stdout.on("data", (d) => (out += d));
    ch.stderr.on("data", (d) => (err += d));
    ch.stdin.end();
    ch.on("close", (rc) => resolve({ rc, out, err }));
  });
}

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const spool = (b) => { try { return fs.readdirSync(b.p.spool).filter((f) => f.endsWith(".json")); } catch { return []; } };
const tokens = (b) => { try { return fs.readdirSync(b.p.files).filter((f) => /^[0-9a-f]{32}$/.test(f)); } catch { return []; } };
const lastRec = (b) => spool(b).map((f) => JSON.parse(fs.readFileSync(path.join(b.p.spool, f), "utf8"))).sort((x, y) => x.received_at - y.received_at).pop();
const sha = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const at = (ms = Date.now()) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
// Async: the inboxes live in THIS process, so a spawnSync'd curl would wait on a server that can't answer.
const bash = (line, cwd) => new Promise((resolve) => {
  const ch = spawn("bash", ["-c", line], { cwd });
  let stdout = "", stderr = "";
  ch.stdout.on("data", (d) => (stdout += d));
  ch.stderr.on("data", (d) => (stderr += d));
  ch.on("close", (status) => resolve({ status, stdout, stderr }));
});
const blob = (name, bytes) => { const f = path.join(root, name); fs.writeFileSync(f, crypto.randomBytes(bytes)); return f; };

let srvA, srvB, portA, portB;
test.before(async () => {
  for (const b of [A, B]) fs.mkdirSync(b.p.spool, { recursive: true });
  srvA = createInbox({ p: A.p, store: fileStore(A.p) });
  srvB = createInbox({ p: B.p, store: fileStore(B.p) });
  portA = await listen(srvA);
  portB = await listen(srvB);
  const resolve = `${A.domain}=http://127.0.0.1:${portA},${B.domain}=http://127.0.0.1:${portB}`;
  A.env.A2A_RESOLVE = resolve;
  B.env.A2A_RESOLVE = resolve;
  for (const [b, port] of [[A, portA], [B, portB]]) {
    const r = await run(b, ["setup", `--domain=${b.domain}`, `--agents=${b.agent}`, `--inbox-url=http://127.0.0.1:${port}/openagent/inbox`, "--no-system"]);
    assert.equal(r.rc, 0, r.err);
  }
  assert.equal((await run(A, ["contacts", "add", `luca@${B.domain}`])).rc, 0);
  assert.equal((await run(B, ["contacts", "add", `main@${A.domain}`])).rc, 0);
});
test.after(() => { srvA.close(); srvB.close(); fs.rmSync(root, { recursive: true, force: true }); });

test("shape: a file entry's every rendered field is pinned (name, url, size, sha256, expiry)", () => {
  const ok = { url: `https://a.example.com/openagent/files/${"a".repeat(32)}/report.pdf`, name: "report.pdf", size: 10, sha256: "0".repeat(64), expires: "2026-09-28T00:00:00Z" };
  assert.equal(fileShapeError(ok), null);
  for (const [k, v] of [["name", "x';rm -rf ~'"], ["name", ".hidden"], ["url", ok.url.replace("report.pdf", "other.pdf")], ["url", ok.url.replace("https://", "file://")],
    ["url", ok.url + "?x=1"], ["url", `https://a.example.com/openagent/files/${"g".repeat(32)}/report.pdf`], ["size", -1], ["size", 1.5], ["sha256", "0".repeat(63)], ["expires", "tomorrow"]]) {
    assert.notEqual(fileShapeError({ ...ok, [k]: v }), null, `${k}=${v} must not pass`);
  }
  const env = { ...makeEnvelope({ from: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", to: ["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"], body: "", at: "2026-09-27T00:00:00Z", files: [ok] }), sig: "x" };
  assert.equal(envelopeShapeError(env), null);
  assert.equal(envelopeShapeError({ ...env, files: [] }), "files");
  assert.equal(envelopeShapeError({ ...env, files: Array(9).fill(ok) }), "files");
  assert.equal(safeFileName("/tmp/my report (v2).pdf"), "my_report_v2_.pdf");
  assert.equal(safeFileName("../.."), "file");
  assert.equal(parseDuration("24h"), 86400e3);
  assert.equal(parseSize("100M"), 100 * 1024 ** 2);
  assert.equal(parseSize("1GiB"), 1024 ** 3);
});

let big;
test("a 50 MiB file: main sends it, luca's delivery carries the link, and luca's own command checks its sha256", async () => {
  const src = blob("big.bin", 50 * 1024 * 1024);
  const want = sha(fs.readFileSync(src));
  const r = await run(A, ["send", "luca", "The dataset you asked for.", `--file=${src}`], { seat: true });
  assert.equal(r.rc, 0, r.err);
  assert.match(r.out, new RegExp(`file big\\.bin  52428800 bytes  sha256 ${want}`));
  const [token] = tokens(A);
  assert.ok(token, "the copy lives under files/<token>/");
  assert.equal(fs.statSync(path.join(A.p.files, token, "big.bin")).mode & 0o777, 0o640);
  const rec = lastRec(B);
  const f = rec.envelope.files[0];
  assert.deepEqual({ name: f.name, size: f.size, sha256: f.sha256 }, { name: "big.bin", size: 52428800, sha256: want }, "the SIGNED message carries size and sha256");
  assert.equal(f.url, `http://127.0.0.1:${portA}/openagent/files/${token}/big.bin`, "served by the sender's own box");
  assert.ok(Date.parse(f.expires) - Date.now() > 23.9 * 3600e3 && Date.parse(f.expires) - Date.now() <= 24 * 3600e3, "24h by default");
  big = { token, url: f.url, want };

  const t = await run(B, ["_tick"], { env: { A2A_NOW: String(Date.now() + 61_000) } });
  assert.equal(t.rc, 0, t.err);
  const text = fs.readFileSync(calls, "utf8");
  assert.match(text, /The dataset you asked for\./);
  assert.match(text, /check[s]? the sha256/);
  assert.match(text, /untrusted data/);
  const line = text.split("\n").find((l) => l.includes("sha256sum -c"));
  assert.ok(line, text);
  const agentDir = fs.mkdtempSync(path.join(root, "luca-cwd-"));
  const dl = await bash(line.trim(), agentDir);
  assert.equal(dl.status, 0, dl.stdout + dl.stderr);
  assert.match(dl.stdout, /: OK$/m);
  assert.equal(sha(fs.readFileSync(path.join(agentDir, "a2a-files", rec.id, "big.bin"))), want);

  // The same command against tampered bytes fails: the check is real, not a formality.
  fs.writeFileSync(path.join(A.p.files, token, "big.bin"), crypto.randomBytes(1024));
  const bad = await bash(line.trim().replace(/--max-filesize \d+/, ""), fs.mkdtempSync(path.join(root, "luca-cwd-")));
  assert.notEqual(bad.status, 0, "a changed file fails the signed sha256");
});

test("a guessed token, a wrong name and the bare directory all answer the same 404", async () => {
  const base = `http://127.0.0.1:${portA}/openagent/files`;
  for (const u of [`${base}/${crypto.randomBytes(16).toString("hex")}/big.bin`, `${base}/${big.token}/other.bin`, `${base}/`, `${base}/${big.token}/`, `${base}/${big.token}`, `${base}/${big.token}/..%2Fbig.bin`]) {
    const res = await fetch(u);
    assert.equal(res.status, 404, u);
    assert.equal((await res.text()).length, 0, "no listing, no hint");
  }
  const post = await fetch(big.url, { method: "POST", body: "x" });
  assert.equal(post.status, 404);
});

test("after expiry the link answers 404 at once, and the tick deletes the bytes", async () => {
  const later = createInbox({ p: A.p, store: fileStore(A.p), now: () => Date.now() + 24 * 3600e3 + 1000 });
  const port = await listen(later);
  try {
    assert.equal((await fetch(big.url, { method: "HEAD" })).status, 200, "still live now");
    assert.equal((await fetch(big.url.replace(`:${portA}/`, `:${port}/`))).status, 404, "expired: 404 before any sweep");
  } finally { later.close(); }
  assert.ok(tokens(A).includes(big.token));
  const t = await run(A, ["_tick"], { env: { A2A_NOW: String(Date.now() + 24 * 3600e3 + 1000) } });
  assert.equal(t.rc, 0, t.err);
  assert.ok(!tokens(A).includes(big.token), "the timer deleted it");
  assert.ok(!fs.existsSync(path.join(A.p.files, `${big.token}.json`)));
  assert.match(fs.readFileSync(A.p.events, "utf8"), /"files-expired"/);
  assert.equal((await fetch(big.url)).status, 404);
});

test("over the per-file cap and over the box total: refused, nothing left behind, nothing sent", async () => {
  assert.equal((await run(A, ["files", "limits", "--max-file=1M"], { seat: true })).rc, 77, "a seat cannot raise or lower the caps");
  assert.equal((await run(A, ["files", "limits", "--max-file=1M", "--max-total=3M"])).rc, 0);
  const before = spool(B).length;
  const r = await run(A, ["send", "luca", "too big", `--file=${blob("two.bin", 2 * 1024 * 1024)}`], { seat: true });
  assert.equal(r.rc, 64, r.out + r.err);
  assert.match(r.err, /over this box's limit of 1 MiB per file/);
  assert.equal(tokens(A).length, 0, "the partial copy is gone");
  assert.equal(spool(B).length, before, "and no message went");

  assert.equal((await run(A, ["files", "limits", "--max-file=2M"])).rc, 0);
  const ok = await run(A, ["send", "luca", "fits", `--file=${blob("a.bin", 1536 * 1024)}`], { seat: true });
  assert.equal(ok.rc, 0, ok.err);
  const full = await run(A, ["send", "luca", "no room", `--file=${blob("b.bin", 1843 * 1024)}`], { seat: true });
  assert.equal(full.rc, 75, full.out + full.err);
  assert.match(full.err, /does not fit in this box's space for sent files/);
  assert.equal(tokens(A).length, 1);
  // Two files, the second over: the first is taken back out too.
  const two = await run(A, ["send", "luca", "pair", `--file=${blob("c.bin", 1024)}`, `--file=${blob("d.bin", 3 * 1024 * 1024)}`], { seat: true });
  assert.notEqual(two.rc, 0);
  assert.equal(tokens(A).length, 1);
  assert.equal((await run(A, ["files", "limits", "--max-file=100M", "--max-total=1G"])).rc, 0);
});

test("the owner revokes a link early; an agent can list and revoke only its own", async () => {
  const ls = await run(A, ["files", "ls"], { seat: true });
  assert.equal(ls.rc, 0, ls.err);
  const token = /^([0-9a-f]{32})  a\.bin/m.exec(ls.out)[1];
  const url = lastRec(B).envelope.files[0].url;
  assert.equal((await fetch(url)).status, 200);
  const rm = await run(A, ["files", "rm", token]);
  assert.equal(rm.rc, 0, rm.err);
  assert.equal((await fetch(url)).status, 404);
  assert.equal(tokens(A).length, 0);
  assert.equal((await run(A, ["files", "rm", token])).rc, 64, "already gone");
});

test("--file-ttl is capped at 7 days, like the message", async () => {
  const r = await run(A, ["send", "luca", `--file=${blob("week.bin", 10)}`, "--file-ttl=30d"], { seat: true });
  assert.equal(r.rc, 0, r.err);
  const f = lastRec(B).envelope.files[0];
  const left = Date.parse(f.expires) - Date.now();
  assert.ok(left <= 7 * 86400e3 && left > 7 * 86400e3 - 60e3, `expires ${f.expires}`);
  assert.equal(lastRec(B).envelope.body, "", "a file alone is a message");
  assert.equal((await run(A, ["send", "luca", "x", "--file=/no/such/file"], { seat: true })).rc, 64);
  assert.equal((await run(A, ["send", "luca", "x", `--file=${root}`], { seat: true })).rc, 64, "a directory is not a file");
});

test("a failed send takes its file back out: a link nobody got is not left served", async () => {
  const doc = JSON.parse(fs.readFileSync(A.p.contacts, "utf8"));
  const keep = doc.contacts[0].inbox;
  doc.contacts[0].inbox = "http://127.0.0.1:1/openagent/inbox";
  fs.writeFileSync(A.p.contacts, JSON.stringify(doc));
  const n = tokens(A).length;
  try {
    const r = await run(A, ["send", "luca", "unreachable", `--file=${blob("lost.bin", 100)}`, "--no-refresh"], { seat: true });
    assert.equal(r.rc, 69, r.out + r.err);
    assert.equal(tokens(A).length, n);
  } finally { doc.contacts[0].inbox = keep; fs.writeFileSync(A.p.contacts, JSON.stringify(doc)); }
});

test("a signed message whose file link points anywhere but the sender's own box is dropped", async () => {
  const key = fs.readFileSync(path.join(A.p.keys, "main.key"), "utf8");
  const mainDid = JSON.parse(fs.readFileSync(B.p.contacts, "utf8")).contacts[0].did;
  const lucaDid = JSON.parse(fs.readFileSync(A.p.contacts, "utf8")).contacts[0].did;
  const file = (origin) => ({ url: `${origin}/openagent/files/${"b".repeat(32)}/x.bin`, name: "x.bin", size: 1, sha256: "0".repeat(64), expires: at(Date.now() + 3600e3) });
  const post = (env) => fetch(`http://127.0.0.1:${portB}/openagent/inbox`, { method: "POST", headers: { "content-type": "application/openagent-msg+json" }, body: JSON.stringify(env) }).then((r) => r.status);
  const before = spool(B).length;
  const elsewhere = signEnvelope(makeEnvelope({ from: mainDid, to: [lucaDid], body: "fetch this", at: at(), files: [file("https://evil.example.com")] }), key);
  assert.equal(await post(elsewhere), 202);
  assert.equal(spool(B).length, before, "dropped, with the same 202");
  const home = signEnvelope(makeEnvelope({ from: mainDid, to: [lucaDid], body: "fetch this", at: at(), files: [file(`http://127.0.0.1:${portA}`)] }), key);
  assert.equal(await post(home), 202);
  assert.equal(spool(B).length, before + 1, "the positive control: the sender's own origin is stored");
});
