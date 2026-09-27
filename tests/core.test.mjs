// Crypto and format arms: did:key, RFC 8785, the envelope and the card.
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  base58btcEncode, base58btcDecode, didFromPublicKey, publicKeyFromDid, jcs, generateKey,
  makeEnvelope, signEnvelope, verifyEnvelopeSig, signedBytes, envelopeShapeError, envelopeTimeError,
  effectiveExpiry, makeCard, verifyCard, parseAddress, MSG_PREFIX, stableStringify,
} from "../a2a/lib/core.mjs";

test("base58btc round-trips, leading zeros included", () => {
  for (const hex of ["", "00", "0000ff", "ed01" + "11".repeat(32), "ffffffff"]) {
    const b = Buffer.from(hex, "hex");
    assert.deepEqual(base58btcDecode(base58btcEncode(b)), b);
  }
});

test("did:key: the W3C ed25519 vector and a round-trip", () => {
  // did-method-key test vector: this raw key encodes to exactly this did.
  const raw = Buffer.from("2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6", "hex");
  const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") }, format: "jwk" });
  const did = didFromPublicKey(key);
  assert.equal(did, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
  assert.deepEqual(publicKeyFromDid(did).export({ format: "jwk" }).x, raw.toString("base64url"));
  assert.throws(() => publicKeyFromDid("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")); // secp256k1, not ed25519
});

test("JCS: RFC 8785 §3.2.2 examples", () => {
  assert.equal(jcs({ numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27] }), '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}');
  assert.equal(jcs({ string: "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/" }), '{"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
  assert.equal(jcs({ literals: [null, true, false] }), '{"literals":[null,true,false]}');
  // Sorted by UTF-16 code units (RFC 8785 §3.2.3 example).
  const sorted = jcs({ "\u20ac": 1, "\r": 2, "\ud83d\ude00": 3, "1": 4, "\u0080": 5, "\u00f6": 6, "\ufb33": 7 });
  assert.equal(sorted, '{"\\r":2,"1":4,"\u0080":5,"\u00f6":6,"\u20ac":1,"\ud83d\ude00":3,"\ufb33":7}');
  assert.throws(() => jcs({ x: NaN }));
});

const me = generateKey();
const them = generateKey();
const AT = "2026-09-27T07:00:00Z";
const NOW = Date.parse(AT);
const base = () => makeEnvelope({ id: "01J8ZK3V7Q9M2X4T6B8N0C1D2E", from: me.did, to: [them.did], body: "hello", at: AT });

test("envelope: signs and verifies; key order does not matter", () => {
  const env = signEnvelope(base(), me.privatePem);
  assert.equal(verifyEnvelopeSig(env), true);
  const reordered = Object.fromEntries(Object.entries(env).reverse());
  assert.equal(verifyEnvelopeSig(reordered), true);
  assert.equal(signedBytes(env).subarray(0, MSG_PREFIX.length).toString(), MSG_PREFIX);
});

test("envelope: every RFC 0001 conformance 'invalid' case fails", () => {
  const env = signEnvelope(base(), me.privatePem);
  assert.equal(verifyEnvelopeSig({ ...env, body: "hellp" }), false, "one body byte changed");
  assert.equal(verifyEnvelopeSig({ ...signEnvelope(base(), them.privatePem), from: me.did }), false, "sig from a different key");
  const { sig, ...rest } = base();
  const noSep = crypto.sign(null, Buffer.from(jcs(rest)), crypto.createPrivateKey(me.privatePem)).toString("base64");
  assert.equal(verifyEnvelopeSig({ ...rest, sig: noSep }), false, "signed without the domain separator");
  const persona = crypto.sign(null, Buffer.from(stableStringify(rest)), crypto.createPrivateKey(me.privatePem)).toString("base64");
  assert.equal(verifyEnvelopeSig({ ...rest, sig: persona }), false, "a provenance-style signature presented as a message signature");
  assert.equal(envelopeTimeError({ ...env, expires: "2026-09-27T06:59:00Z" }, NOW), "expired");
  assert.equal(envelopeTimeError({ ...env, at: "2026-09-27T07:11:00Z" }, NOW), "clock-skew", "at 11 minutes ahead");
  assert.equal(envelopeTimeError(env, NOW + 9 * 60 * 1000), null, "9 minutes of drift is fine");
});

test("envelope: expiry defaults to +24h and is clamped to +7d", () => {
  assert.equal(effectiveExpiry(base()), NOW + 24 * 3600e3);
  assert.equal(effectiveExpiry({ ...base(), expires: "2027-09-27T07:00:00Z" }), NOW + 7 * 24 * 3600e3);
});

test("envelope: shape checks refuse oversize bodies and bad fields", () => {
  assert.equal(envelopeShapeError(signEnvelope(base(), me.privatePem)), null);
  assert.equal(envelopeShapeError({ ...base(), body: "x".repeat(16 * 1024 + 1), sig: "a" }), "body");
  assert.equal(envelopeShapeError({ ...base(), openagent_msg: "0.2", sig: "a" }), "version");
  assert.equal(envelopeShapeError({ ...base(), to: [], sig: "a" }), "to");
  assert.equal(envelopeShapeError({ ...base(), from: "did:web:x", sig: "a" }), "from");
});

test("card: signs like an OpenAgent persona, and a tampered card fails", () => {
  const card = makeCard({ name: "main", domain: "api.example.com", inbox: "https://api.example.com/openagent/inbox", privatePem: me.privatePem, signedAt: AT });
  const v = verifyCard(card);
  assert.equal(v.ok, true);
  assert.equal(v.did, me.did);
  assert.equal(v.id, ["main", "api.example.com"].join("@"));
  assert.equal(verifyCard({ ...card, links: { inbox: "https://evil.example.com/openagent/inbox" } }).ok, false);
});

test("addresses parse like email", () => {
  assert.deepEqual(parseAddress(["luca", "teal-fox.example.com"].join("@")), { name: "luca", domain: "teal-fox.example.com" });
  assert.equal(parseAddress("luca"), null);
  assert.equal(parseAddress("Luca@x"), null);
});
