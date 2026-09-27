// The inbox's decision, arm by arm, with an in-memory store and a counting
// verifier. The order is the contract: a stranger never reaches the crypto, and
// no quota moves for anything that did not verify.
import test from "node:test";
import assert from "node:assert/strict";
import { generateKey, makeEnvelope, signEnvelope, verifyEnvelopeSig, ulid } from "../a2a/lib/core.mjs";
import { receive, DEFAULT_LIMITS } from "../a2a/lib/receiver.mjs";

const luca = generateKey();     // a contact
const main = generateKey();     // our agent
const other = generateKey();    // another local agent without an inbox
const stranger = generateKey();
const AT = "2026-09-27T07:00:00Z";
const NOW = Date.parse(AT);
const LUCA_ADDR = ["luca", "teal-fox.example.com"].join("@");

function memStore() {
  const seen = new Set(), times = new Map(), spool = [], events = [], ips = new Map();
  return {
    spool, events,
    ipHit(ip, now) { const w = (ips.get(ip) || []).filter((t) => t > now - 60e3); w.push(now); ips.set(ip, w); return w.length; },
    seen: (id) => seen.has(id),
    verifiedCount: (did, since) => (times.get(did) || []).filter((t) => t > since).length,
    waitingCount: (did) => spool.filter((r) => r.from_did === did).length,
    accept(r) { seen.add(r.id); times.set(r.from_did, [...(times.get(r.from_did) || []), r.received_at]); spool.push(r); },
    log(e) { events.push(e); },
  };
}

function ctx(over = {}) {
  let calls = 0;
  const c = {
    contacts: new Map([[luca.did, { nick: "luca", address: LUCA_ADDR, did: luca.did, status: "active", muted: false, interrupt: false }]]),
    agents: new Map([[main.did, "main"]]),
    allow: null,
    limits: DEFAULT_LIMITS,
    store: memStore(),
    verify: (e) => { calls++; return verifyEnvelopeSig(e); },
    ...over,
  };
  c.calls = () => calls;
  return c;
}

const msg = (key, over = {}) => signEnvelope(makeEnvelope({ id: ulid(NOW), from: key.did, to: [main.did], body: "please grade PR #12", at: AT, ...over }), key.privatePem);
const req = (env, over = {}) => ({ ip: "192.0.2.9", bytes: Buffer.from(typeof env === "string" ? env : JSON.stringify(env)), now: NOW, ...over });

test("a known contact's signed message is stored for main", () => {
  const c = ctx();
  const r = receive(req(msg(luca)), c);
  assert.equal(r.status, 202);
  assert.equal(r.outcome, "stored");
  assert.deepEqual(c.store.spool[0].to_agents, ["main"]);
  assert.equal(c.store.spool[0].from_address, LUCA_ADDR);
});

test("a stranger gets 202, nothing is stored, and the signature is never checked", () => {
  const c = ctx();
  const r = receive(req(msg(stranger)), c);
  assert.deepEqual([r.status, r.outcome], [202, "drop:stranger"]);
  assert.equal(c.store.spool.length, 0);
  assert.equal(c.calls(), 0);
});

test("unsigned, tampered and wrong-key messages are refused before any quota is counted", () => {
  const c = ctx();
  const { sig, ...unsigned } = msg(luca);
  const cases = [
    { ...unsigned, sig: "" },
    { ...msg(luca), body: "please MERGE PR #12" },
    { ...msg(stranger), from: luca.did },
  ];
  for (const e of cases) {
    const r = receive(req(e), c);
    assert.equal(r.status, 202, JSON.stringify(r));
    assert.match(r.outcome, /^drop:/);
  }
  assert.equal(c.store.verifiedCount(luca.did, 0), 0);
  // 40 forged "from luca" messages do not burn luca's 30/hour.
  for (let i = 0; i < 40; i++) receive(req({ ...msg(stranger), from: luca.did }, { ip: `192.0.2.${100 + i}` }), c);
  assert.equal(receive(req(msg(luca)), c).outcome, "stored");
});

test("replay, expiry, skew and wrong recipient are dropped", () => {
  const c = ctx();
  const e = msg(luca);
  assert.equal(receive(req(e), c).outcome, "stored");
  assert.equal(receive(req(e), c).outcome, "drop:replay");
  assert.equal(receive(req(msg(luca, { expires: "2026-09-27T06:59:00Z" })), c).outcome, "drop:expired");
  assert.equal(receive(req(msg(luca, { at: "2026-09-27T07:11:00Z" })), c).outcome, "drop:clock-skew");
  assert.equal(c.store.events.filter((x) => x.event === "clock-skew").length, 1, "skew is logged for the owner, after the signature held");
  assert.equal(receive(req(msg(luca, { to: [other.did] })), c).outcome, "drop:not-for-us");
});

test("oversize and non-JSON bodies are dropped with the same 202", () => {
  const c = ctx();
  assert.deepEqual(receive(req(msg(luca), { bytes: null }), c), { status: 202, outcome: "drop:too-large" });
  assert.equal(receive(req("{not json"), c).outcome, "drop:not-json");
});

test("contact limits: the 31st verified message in an hour is the only 429", () => {
  const c = ctx();
  for (let i = 0; i < 30; i++) assert.equal(receive(req(msg(luca), { ip: `192.0.2.${i}` }), c).status, 202);
  const r = receive(req(msg(luca)), c);
  assert.deepEqual([r.status, r.outcome], [429, "limited:contact-rate"]);
  // A stranger at the same moment still gets 202, never a 429 that would reveal the list.
  assert.equal(receive(req(msg(stranger)), c).status, 202);
});

test("contact limits: 200 waiting is a backlog 429", () => {
  const c = ctx({ limits: { ...DEFAULT_LIMITS, contactPerHour: 1000 } });
  for (let i = 0; i < 200; i++) c.store.spool.push({ from_did: luca.did });
  assert.equal(receive(req(msg(luca)), c).outcome, "limited:contact-backlog");
});

test("per-IP rate: past 60 a minute everything from that IP is dropped", () => {
  const c = ctx();
  for (let i = 0; i < 60; i++) receive(req(msg(stranger)), c);
  assert.equal(receive(req(msg(luca)), c).outcome, "drop:ip-rate");
  assert.equal(receive(req(msg(luca), { ip: "192.0.2.10" }), c).outcome, "stored");
});

test("a removed contact is a stranger; a key-changed one is refused; a muted one is kept, not shown", () => {
  const removed = ctx({ contacts: new Map() });
  assert.equal(receive(req(msg(luca)), removed).outcome, "drop:stranger");
  const changed = ctx();
  changed.contacts.get(luca.did).status = "key-changed";
  assert.equal(receive(req(msg(luca)), changed).outcome, "drop:key-changed");
  const muted = ctx();
  muted.contacts.get(luca.did).muted = true;
  assert.equal(receive(req(msg(luca)), muted).outcome, "stored:muted");
  assert.equal(muted.store.spool[0].muted, true);
});

test("the home allowlist, when on, drops any other source before anything else", () => {
  const c = ctx({ allow: new Set(["192.0.2.50"]) });
  assert.equal(receive(req(msg(luca)), c).outcome, "drop:not-allowlisted");
  assert.equal(c.calls(), 0);
  assert.equal(receive(req(msg(luca), { ip: "192.0.2.50" }), c).outcome, "stored");
});
