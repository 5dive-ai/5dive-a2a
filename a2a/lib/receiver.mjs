// The inbox's decision, in the order RFC 0001 §3 and the plan fix: cheapest
// first, crypto only for a claimed contact, contact limits only on a VERIFIED
// message. Every refusal before the contact limits is the same 202, so a
// stranger learns nothing, not even whether an address exists.
//
// receive() is pure over its inputs: the state lives behind `store`, the clock
// is `now`, and the verifier can be swapped for a spy (the harness counts how
// often a stranger's message reaches the crypto: it must be never).
import {
  MAX_REQUEST_BYTES, envelopeShapeError, envelopeTimeError, effectiveExpiry, verifyEnvelopeSig,
} from "./core.mjs";

export const DEFAULT_LIMITS = Object.freeze({
  ipPerMinute: 60,
  contactPerHour: 30,
  contactWaiting: 200,
});

// ctx:
//   contacts:  Map<did, {nick, address, status: 'active'|'key-changed', muted, interrupt}>
//   agents:    Map<did, agentName> — the local agents whose inbox is ON
//   allow:     null (off) or Set<ip> — the optional home allowlist
//   limits:    DEFAULT_LIMITS
//   store:     { ipHit(ip, now) -> n in last 60s, seen(id) -> bool,
//                verifiedCount(did, sinceMs) -> n, waitingCount(did) -> n,
//                accept(record) — marks seen, counts, spools; log(event) }
//   verify:    verifyEnvelopeSig (overridable only by the harness)
// req: { ip, bytes: Buffer|null (null = over the size cap), now }
// -> { status, outcome, record? }
export function receive(req, ctx) {
  const drop = (outcome) => ({ status: 202, outcome });
  const limits = ctx.limits || DEFAULT_LIMITS;
  const verify = ctx.verify || verifyEnvelopeSig;
  const now = req.now;

  // 0. the home allowlist, when the owner turned it on: from where, before anything.
  if (ctx.allow && !ctx.allow.has(req.ip)) return drop("drop:not-allowlisted");
  // 1. size.
  if (!req.bytes || req.bytes.length > MAX_REQUEST_BYTES) return drop("drop:too-large");
  // 2. per-source rate.
  if (ctx.store.ipHit(req.ip, now) > limits.ipPerMinute) return drop("drop:ip-rate");
  // Parse and shape.
  let env;
  try { env = JSON.parse(req.bytes.toString("utf8")); } catch { return drop("drop:not-json"); }
  const shape = envelopeShapeError(env);
  if (shape) return drop(`drop:shape-${shape}`);
  // 3. is `from` a contact? A stranger costs no crypto.
  const contact = ctx.contacts.get(env.from);
  if (!contact) return drop("drop:stranger");
  if (contact.status !== "active") return drop("drop:key-changed");
  // 4. the signature, then everything that is only meaningful once it holds.
  if (!verify(env)) return drop("drop:bad-signature");
  const recipients = env.to.filter((d) => ctx.agents.has(d));
  if (recipients.length === 0) return drop("drop:not-for-us");
  const timeErr = envelopeTimeError(env, now);
  if (timeErr) {
    // Logged for the owner, and only now that the signature holds (luca's review).
    if (timeErr === "clock-skew") ctx.store.log({ at: now, event: "clock-skew", from: contact.address, id: env.id, sent_at: env.at });
    return drop(`drop:${timeErr}`);
  }
  if (ctx.store.seen(env.id)) return drop("drop:replay");
  // 5. only now, with the sender proven: the contact's own limits. The only 429.
  if (ctx.store.verifiedCount(env.from, now - 3600 * 1000) >= limits.contactPerHour) {
    ctx.store.log({ at: now, event: "contact-rate", from: contact.address, id: env.id });
    return { status: 429, outcome: "limited:contact-rate" };
  }
  if (ctx.store.waitingCount(env.from) >= limits.contactWaiting) {
    ctx.store.log({ at: now, event: "contact-backlog", from: contact.address, id: env.id });
    return { status: 429, outcome: "limited:contact-backlog" };
  }
  const record = {
    id: env.id,
    received_at: now,
    expires_at: effectiveExpiry(env),
    from_did: env.from,
    from_nick: contact.nick,
    from_address: contact.address,
    muted: !!contact.muted,
    interrupt: !!contact.interrupt,
    to_agents: recipients.map((d) => ctx.agents.get(d)),
    envelope: env,
  };
  ctx.store.accept(record);
  return { status: 202, outcome: contact.muted ? "stored:muted" : "stored", record };
}
