// 5dive-a2a core: keys, did:key, RFC 8785 canonical JSON, the signed message
// envelope (OpenAgent RFC 0001) and the signed agent card. Pure functions only:
// no filesystem, no network, no clock except where a caller passes `now`.
import crypto from "node:crypto";

export const MSG_VERSION = "0.1";
// Domain separator (RFC 0001 §1). A message signature can never be replayed as a
// persona `provenance` signature or a Buzz binding, and the reverse.
export const MSG_PREFIX = "openagent:msg:v0.1\n";
export const MAX_REQUEST_BYTES = 64 * 1024;
export const MAX_BODY_BYTES = 16 * 1024;
export const DEFAULT_TTL_MS = 24 * 3600 * 1000;
export const MAX_TTL_MS = 7 * 24 * 3600 * 1000;
export const MAX_SKEW_MS = 10 * 60 * 1000;
export const CONTENT_TYPE = "application/openagent-msg+json";

// ---- base58btc and did:key --------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58btcEncode(bytes) {
  const buf = Buffer.from(bytes);
  let zeros = 0;
  while (zeros < buf.length && buf[zeros] === 0) zeros++;
  const digits = [];
  for (let i = zeros; i < buf.length; i++) {
    let carry = buf[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

export function base58btcDecode(str) {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;
  const bytes = [0];
  for (let i = zeros; i < str.length; i++) {
    const v = B58.indexOf(str[i]);
    if (v < 0) throw new Error("not base58btc");
    let carry = v;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  const body = bytes.reverse();
  while (body.length > 1 && body[0] === 0) body.shift();
  const out = Buffer.concat([Buffer.alloc(zeros), Buffer.from(str.length === zeros ? [] : body)]);
  return out;
}

const DID_RE = /^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/;

export function didFromPublicKey(publicKey) {
  const key = publicKey instanceof crypto.KeyObject && publicKey.type === "public" ? publicKey : crypto.createPublicKey(publicKey);
  const jwk = key.export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") throw new Error("not an ed25519 key");
  const raw = Buffer.from(jwk.x, "base64url");
  return "did:key:z" + base58btcEncode(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));
}

// did:key -> KeyObject. Throws on anything that is not an ed25519 did:key.
export function publicKeyFromDid(did) {
  if (typeof did !== "string" || !DID_RE.test(did)) throw new Error("not a did:key");
  const bytes = base58btcDecode(did.slice("did:key:z".length));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) throw new Error("not an ed25519 did:key");
  return crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: bytes.subarray(2).toString("base64url") }, format: "jwk" });
}

export function isDid(s) {
  try { publicKeyFromDid(s); return true; } catch { return false; }
}

export function shortDid(did) {
  return typeof did === "string" && did.length > 20 ? `${did.slice(0, 14)}…${did.slice(-6)}` : String(did);
}

export function generateKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString().trim(),
    did: didFromPublicKey(publicKey),
  };
}

// ---- RFC 8785 (JCS) ---------------------------------------------------------
//
// For JSON values, ECMAScript's JSON.stringify of a string and of a finite number
// IS the JCS serialisation (RFC 8785 §3.2.2.2 and §3.2.2.3 are defined by
// reference to it), and the default sort of property names compares UTF-16 code
// units, which is §3.2.3. What JSON.stringify alone gets wrong is key order and
// non-finite numbers; both are handled here.
export function jcs(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("JCS: non-finite number");
    return JSON.stringify(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().filter((k) => v[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  throw new Error(`JCS: unsupported ${typeof v}`);
}

// ---- the envelope -----------------------------------------------------------

export function signedBytes(env) {
  const { sig, ...rest } = env;
  return Buffer.concat([Buffer.from(MSG_PREFIX, "utf8"), Buffer.from(jcs(rest), "utf8")]);
}

export function signEnvelope(env, privatePem) {
  const { sig, ...rest } = env;
  const out = { ...rest };
  out.sig = crypto.sign(null, signedBytes(out), crypto.createPrivateKey(privatePem)).toString("base64");
  return out;
}

// True only when `sig` is a valid ed25519 signature by `from` over the canonical
// envelope with the domain separator. Never throws.
export function verifyEnvelopeSig(env) {
  try {
    if (typeof env.sig !== "string") return false;
    const sig = Buffer.from(env.sig, "base64");
    if (sig.length !== 64) return false;
    return crypto.verify(null, signedBytes(env), publicKeyFromDid(env.from), sig);
  } catch {
    return false;
  }
}

const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

function isoMs(s) {
  if (typeof s !== "string" || !ISO_RE.test(s)) return NaN;
  return Date.parse(s);
}

// Shape only: types, sizes, required fields. Returns null when well-formed, or a
// short reason. Cheap and crypto-free, so it runs before the contact lookup.
export function envelopeShapeError(env) {
  if (!env || typeof env !== "object" || Array.isArray(env)) return "not-an-object";
  if (env.openagent_msg !== MSG_VERSION) return "version";
  if (typeof env.id !== "string" || !ID_RE.test(env.id)) return "id";
  if (typeof env.from !== "string" || !DID_RE.test(env.from)) return "from";
  if (!Array.isArray(env.to) || env.to.length < 1 || env.to.length > 16 || !env.to.every((d) => typeof d === "string" && DID_RE.test(d))) return "to";
  if (Number.isNaN(isoMs(env.at))) return "at";
  if (env.expires !== undefined && Number.isNaN(isoMs(env.expires))) return "expires";
  if (env.thread !== undefined && (typeof env.thread !== "string" || !ID_RE.test(env.thread))) return "thread";
  if (env.ref !== undefined && (typeof env.ref !== "string" || env.ref.length > 256)) return "ref";
  if (typeof env.body !== "string" || Buffer.byteLength(env.body, "utf8") > MAX_BODY_BYTES) return "body";
  if (typeof env.sig !== "string" || env.sig.length > 200) return "sig";
  return null;
}

// The effective expiry: `expires` if given, else at + 24h, and never more than
// at + 7d (RFC 0001 §1: a sender cannot make the seen-id cache grow unbounded).
export function effectiveExpiry(env) {
  const at = isoMs(env.at);
  const want = env.expires !== undefined ? isoMs(env.expires) : at + DEFAULT_TTL_MS;
  return Math.min(want, at + MAX_TTL_MS);
}

// Checks that need a verified signature first (RFC 0001 §3 step 2, minus the
// replay check, which needs state). Returns null or a reason.
export function envelopeTimeError(env, nowMs) {
  const at = isoMs(env.at);
  if (Math.abs(nowMs - at) > MAX_SKEW_MS) return "clock-skew";
  if (effectiveExpiry(env) <= nowMs) return "expired";
  return null;
}

// ULID (Crockford base32, 48-bit ms time + 80 random bits).
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export function ulid(nowMs = Date.now()) {
  let t = nowMs, time = "";
  for (let i = 0; i < 10; i++) { time = CROCKFORD[t % 32] + time; t = Math.floor(t / 32); }
  const rnd = crypto.randomBytes(16);
  let r = "";
  for (let i = 0; i < 16; i++) r += CROCKFORD[rnd[i] % 32];
  return time + r;
}

export function makeEnvelope({ from, to, body, at, expires, thread, ref, id }) {
  const env = { openagent_msg: MSG_VERSION, id: id || ulid(), from, to: Array.isArray(to) ? to : [to], at, body };
  if (expires) env.expires = expires;
  if (thread) env.thread = thread;
  if (ref) env.ref = ref;
  return env;
}

// ---- the agent card ---------------------------------------------------------
//
// A card is a small OpenAgent document signed exactly like a persona's
// `provenance` (openagent lib/provenance.js): keys sorted recursively, no
// whitespace, `provenance.signature` removed, ed25519 over those bytes, the key
// an SPKI PEM in `provenance.created_by.key`. So `openagent verify` reads it.
export function stableStringify(v) {
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + stableStringify(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

function cardBytes(doc) {
  const clone = JSON.parse(JSON.stringify(doc));
  if (clone.provenance && typeof clone.provenance === "object") delete clone.provenance.signature;
  return Buffer.from(stableStringify(clone), "utf8");
}

export function makeCard({ name, domain, inbox, privatePem, signedAt }) {
  const publicPem = crypto.createPublicKey(crypto.createPrivateKey(privatePem)).export({ type: "spki", format: "pem" }).toString().trim();
  const doc = {
    openagent: "0.3",
    kind: "agent-card",
    id: `${name}@${domain}`,
    name,
    links: { inbox },
    provenance: { created_by: { name: `${name}@${domain}`, key: publicPem }, signed_at: signedAt },
  };
  doc.provenance.signature = crypto.sign(null, cardBytes(doc), crypto.createPrivateKey(privatePem)).toString("base64");
  return doc;
}

// -> { ok, reason, did?, inbox?, id? }. Never throws.
export function verifyCard(doc) {
  try {
    const prov = doc && doc.provenance;
    if (!prov || !prov.signature || !prov.created_by || !prov.created_by.key) return { ok: false, reason: "unsigned card" };
    const pub = crypto.createPublicKey(prov.created_by.key);
    const ok = crypto.verify(null, cardBytes(doc), pub, Buffer.from(String(prov.signature), "base64"));
    if (!ok) return { ok: false, reason: "card signature does not match" };
    const inbox = doc.links && doc.links.inbox;
    if (typeof inbox !== "string" || !/^https?:\/\//.test(inbox)) return { ok: false, reason: "card has no links.inbox" };
    return { ok: true, reason: "valid", did: didFromPublicKey(pub), inbox, id: doc.id };
  } catch (e) {
    return { ok: false, reason: `card unreadable: ${e.message}` };
  }
}

// "name@domain" -> { name, domain } or null.
export function parseAddress(addr) {
  const m = /^([a-z][a-z0-9-]{0,31})@([a-z0-9.-]+\.[a-z]{2,}|[a-z0-9.-]+:\d+)$/.exec(String(addr || "").toLowerCase());
  return m ? { name: m[1], domain: m[2] } : null;
}

export function cardUrl({ name, domain }) {
  return `https://${domain}/openagent/agents/${name}.json`;
}
