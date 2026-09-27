// DIVE-5064: the inbox's trust root (config.json, contacts.json) was rewritten root:root
// by `contacts add`, the inbox user could no longer read it, and readJson turned that into
// an empty contact list: every contact a stranger, dropped with the usual 202, nothing
// logged. These arms hold the inbox to failing CLOSED and LOUD on an unreadable trust
// root, and to noticing a chgrp/chmod heal, which moves the ctime and not the mtime.
// The ownership itself (root writes, a non-root inbox reads) is tests/ownership.sh.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createInbox } from "../a2a/lib/server.mjs";
import { fileStore, writeJson, readJsonStrict } from "../a2a/lib/state.mjs";
import { generateKey, makeEnvelope, signEnvelope, ulid } from "../a2a/lib/core.mjs";

const root = process.getuid && process.getuid() === 0;
const luca = generateKey(), main = generateKey();
const LUCA = ["luca", "b.example.com"].join("@");

function tree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a2a-trust-"));
  const etc = path.join(dir, "etc"), v = path.join(dir, "var");
  const p = {
    etc, var: v, config: path.join(etc, "config.json"), contacts: path.join(etc, "contacts.json"),
    keys: path.join(etc, "keys"), cards: path.join(etc, "cards"), spool: path.join(v, "spool"),
    seen: path.join(v, "seen.json"), counts: path.join(v, "counts.json"), events: path.join(v, "events.log"),
    outbox: path.join(v, "outbox.log"), delivered: path.join(v, "delivered.json"), allowIps: path.join(v, "allow-ips.json"),
  };
  fs.mkdirSync(etc, { recursive: true });
  fs.mkdirSync(p.spool, { recursive: true });
  writeJson(p.config, { domain: "a.example.com", agents: { main: { inbox: true, did: main.did } } });
  writeJson(p.contacts, { contacts: [{ nick: "luca", address: LUCA, did: luca.did, status: "active", muted: false, interrupt: false }] });
  return { dir, p };
}

const listen = (srv) => new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv.address().port)));
const post = (port) => fetch(`http://127.0.0.1:${port}/openagent/inbox`, {
  method: "POST", headers: { "content-type": "application/openagent-msg+json" },
  body: JSON.stringify(signEnvelope(makeEnvelope({ id: ulid(), from: luca.did, to: [main.did], body: "hi", at: new Date().toISOString().replace(/\.\d+Z$/, "Z") }), luca.privatePem)),
}).then((r) => r.status);
const spooled = (p) => fs.readdirSync(p.spool).filter((f) => f.endsWith(".json")).length;
const events = (p) => { try { return fs.readFileSync(p.events, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; } };

test("readJsonStrict: a missing file is the fallback, an unreadable or torn one throws", { skip: root && "root reads a 000 file" }, () => {
  const { dir, p } = tree();
  assert.deepEqual(readJsonStrict(path.join(dir, "nope.json"), { contacts: [] }), { contacts: [] });
  fs.chmodSync(p.contacts, 0o000);
  assert.throws(() => readJsonStrict(p.contacts, {}), (e) => e.code === "EACCES" && e.file === p.contacts);
  fs.writeFileSync(p.config, "{ torn");
  assert.throws(() => readJsonStrict(p.config, {}), (e) => e.code === "EPARSE");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("an unreadable contacts.json: 503 to the sender, one event for the owner, and the chmod heal is seen with no restart", { skip: root && "root reads a 000 file" }, async () => {
  const { dir, p } = tree();
  // The incident's shape: the inbox STARTS with a trust root it cannot read.
  fs.chmodSync(p.contacts, 0o000);
  const srv = createInbox({ p, store: fileStore(p) });
  const port = await listen(srv);
  try {
    assert.equal(await post(port), 503, "not a 202: the sender must not believe it was taken");
    assert.equal(await post(port), 503);
    assert.equal(spooled(p), 0);
    const bad = events(p).filter((e) => e.event === "inbox-cannot-read");
    assert.equal(bad.length, 1, "logged once, not once per message");
    assert.equal(bad[0].file, p.contacts);
    assert.equal(bad[0].error, "EACCES");

    // The hand heal: a mode/group change moves the ctime only.
    const mtime = fs.statSync(p.contacts).mtimeMs;
    fs.chmodSync(p.contacts, 0o640);
    assert.equal(fs.statSync(p.contacts).mtimeMs, mtime, "the heal did not touch the mtime");
    assert.equal(await post(port), 202);
    assert.equal(spooled(p), 1, "the contact's message is stored after the heal, without a restart");
    assert.ok(events(p).some((e) => e.event === "inbox-can-read"));

    // Unreadable again while running: no stale list (a removed contact must not get back in).
    fs.chmodSync(p.contacts, 0o000);
    assert.equal(await post(port), 503);
    assert.equal(spooled(p), 1);
  } finally { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("an unreadable config.json fails closed the same way", { skip: root && "root reads a 000 file" }, async () => {
  const { dir, p } = tree();
  const srv = createInbox({ p, store: fileStore(p) });
  const port = await listen(srv);
  try {
    assert.equal(await post(port), 202);
    assert.equal(spooled(p), 1);
    fs.chmodSync(p.config, 0o000);
    assert.equal(await post(port), 503);
    assert.equal(events(p).filter((e) => e.event === "inbox-cannot-read" && e.file === p.config).length, 1);
  } finally { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("a box that is not set up (no config, no contacts) is not an error: strangers get the 202", async () => {
  const { dir, p } = tree();
  fs.rmSync(p.config); fs.rmSync(p.contacts);
  const srv = createInbox({ p, store: fileStore(p) });
  const port = await listen(srv);
  try {
    assert.equal(await post(port), 202);
    assert.equal(spooled(p), 0);
    assert.equal(events(p).filter((e) => e.event === "inbox-cannot-read").length, 0);
  } finally { srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
